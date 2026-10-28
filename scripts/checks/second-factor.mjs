import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

/**
 * 第二因子防线的门禁。
 *
 * 密码登录一直有限流，三道 MFA 门户却一次都没有 —— 而第二因子的存在前提
 * 正是「密码已经泄露」。能无限次尝试的第二因子不构成防线。
 *
 * 这里检查三件事：
 *   1. 每个验证端点必须先查限流桶、失败必须计数
 *   2. rateLimit.ts 里定义的桶必须真的被用上（不能只定义不接线）
 *   3. 验证失败不得把 detail 回传浏览器
 */
export function checkSecondFactor({ check, ROOT }) {
  const read = (rel) => readFileSync(join(ROOT, rel), "utf8");

  check("第二因子：三道门户都有限流与会话绑定", () => {
    const mfa = read("packages/core/src/routes/mfa.ts");

    const endpoints = [
      { path: '"/mfa/verify-totp"', guard: "checkSecondFactorAllowed", record: "recordSecondFactorFailure" },
      { path: '"/mfa/verify-recovery"', guard: "checkSecondFactorAllowed", record: "recordSecondFactorFailure" },
      { path: '"/passkey/login-verify"', guard: "checkPasskeyIpAllowed", record: "recordPasskeyIpFailure" },
    ];

    for (const item of endpoints) {
      const start = mfa.indexOf(`mfaRoutes.post(${item.path}`);
      if (start < 0) throw new Error(`找不到端点 ${item.path}`);
      const next = mfa.indexOf("mfaRoutes.post(", start + 10);
      const body = mfa.slice(start, next > start ? next : start + 4000);

      if (!body.includes(item.guard)) {
        throw new Error(`${item.path} 没有调用 ${item.guard}，可无限尝试`);
      }
      if (!body.includes(item.record)) {
        throw new Error(`${item.path} 失败时不计数，限流形同虚设`);
      }
      // 通过后必须清零，否则正常用户会被历史失败拖黑
      if (!/clear(SecondFactor|PasskeyIp)Failures/.test(body)) {
        throw new Error(`${item.path} 成功后不清零计数，正常用户会被误锁`);
      }
    }

    // userId 与会话必须校验绑定关系
    for (const path of ['"/mfa/verify-totp"', '"/mfa/verify-recovery"']) {
      const start = mfa.indexOf(`mfaRoutes.post(${path}`);
      const next = mfa.indexOf("mfaRoutes.post(", start + 10);
      const body = mfa.slice(start, next > start ? next : start + 4000);
      if (!body.includes("isPendingSessionOfUser")) {
        throw new Error(`${path} 未校验 sessionId 与 userId 的绑定，可跨账号爆破验证码`);
      }
    }
  });

  check("第二因子：限流桶有定义就必须有调用", () => {
    const rateLimit = read("packages/core/src/services/rateLimit.ts");

    // 桶定义块里声明的每个键，都必须在全项目里被引用超过定义处
    const block = rateLimit.slice(
      rateLimit.indexOf("export const buckets"),
      rateLimit.indexOf("// ----", rateLimit.indexOf("export const buckets")),
    );
    const keys = [...block.matchAll(/^\s{2}(\w+):/gm)].map((m) => m[1]);
    if (keys.length === 0) throw new Error("未解析到任何限流桶");

    const sources = ["packages/core/src/routes", "packages/core/src/services"];

    for (const key of keys) {
      const callers = new Set();

      const walk = (dir) => {
        for (const rel of listFiles(ROOT, dir)) {
          const src = readFileSync(join(ROOT, rel), "utf8");
          if (rel.endsWith("rateLimit.ts")) {
            // 只看 buckets.<key> 在文件内的使用，跳过定义处
            const uses = (src.match(new RegExp(`buckets\\.${key}`, "g")) ?? []).length;
            if (uses > 0) callers.add(rel);
            continue;
          }
          if (src.includes(`buckets.${key}`)) callers.add(rel);
        }
      };

      for (const dir of sources) walk(dir);

      // 桶只要在自己的服务里被用到就算接线（接口函数会包装它）
      if (callers.size === 0) {
        throw new Error(`限流桶 ${key} 定义了但从未使用`);
      }
    }
  });

  check("第二因子：状态查询必须带 caller，不能只凭 userId", () => {
    // Core 侧自己会校验 caller 与 userId 的关系，但 Gateway 必须先把 caller 传过去。
    // 少传 caller 会让 Core 一律 403 —— 或者更糟，把校验放宽成"不传就放行"。
    const dir = "packages/gateway/src";
    const files = [];
    const walk = (rel) => {
      for (const entry of readdirSync(join(ROOT, rel), { withFileTypes: true })) {
        const path = `${rel}/${entry.name}`;
        if (entry.isDirectory()) walk(path);
        else if (/\.(ts|tsx)$/.test(entry.name)) files.push(path);
      }
    };
    walk(dir);

    for (const file of files) {
      const src = readFileSync(join(ROOT, file), "utf8");
      // 匹配 path: "/mfa/status" 或 "/mfa/factors" 所在的 callCore 对象
      for (const key of ['"/mfa/status"', '"/mfa/factors"']) {
        let idx = src.indexOf(key);
        while (idx >= 0) {
          const blockEnd = src.indexOf("});", idx);
          const block = src.slice(Math.max(0, idx - 400), blockEnd > idx ? blockEnd : idx + 400);
          // 必须是作为对象属性传的 caller（`caller,` 或 `caller:`），
          // 不能是 payload 里的 `caller.userId` —— 那玩意儿没有传到信封上。
          if (!/^\s*caller\s*[,:]?\s*$/m.test(block)) {
            throw new Error(file + " 调用 " + key + " 时没传 caller 字段，Core 会拒绝或放宽校验");
          }
          idx = src.indexOf(key, idx + key.length);
        }
      }
    }
  });

  check("第二因子：错误 detail 不回传浏览器", () => {
    const mfa = read("packages/core/src/routes/mfa.ts");

    // 服务层的 detail 只允许进 console.error
    if (/c\.json\(\{[^}]*detail\s*:/.test(mfa)) {
      throw new Error("响应体里带了 detail，可能把挑战值或凭据数据暴露给客户端");
    }

    const passkey = read("packages/core/src/services/passkey.ts");
    const logs = (passkey.match(/console\.error\("\[passkey\]/g) ?? []).length;
    if (logs < 2) throw new Error("passkey 失败未写入服务端日志，线上无法定位");
  });
}

function listFiles(ROOT, dir) {
  const out = [];
  const walk = (rel) => {
    for (const entry of readdirSync(join(ROOT, rel), { withFileTypes: true })) {
      const path = `${rel}/${entry.name}`;
      if (entry.isDirectory()) walk(path);
      else if (/\.(ts|tsx)$/.test(entry.name)) out.push(path);
    }
  };
  walk(dir);
  return out;
}
