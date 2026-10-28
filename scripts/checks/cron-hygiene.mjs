import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Cron 与签名密钥的门禁。
 *
 * 免费版 Cron 每次只有 10ms CPU，而它每 15 分钟跑一次、一天 96 次。
 * 任何"每轮都做一次多余的写"都会乘以 96，且和其它 Worker 共享 D1 写入配额。
 *
 * 三个真实问题：
 *   1. 稳态下仍然无条件 UPDATE 每把密钥（96 tick × 2 把 = 192 行/天，全是同一个值）
 *   2. 同步用 await 串行阻塞，挤占本该留给清理的预算
 *   3. retiredAt 在降级时从不写入，这个字段对降级的键永远为 NULL
 */
export function checkCronHygiene({ check, ROOT }) {
  const read = (rel) => readFileSync(join(ROOT, rel), "utf8");

  check("Cron：密钥同步稳态零写入", () => {
    const keys = read("packages/core/src/services/signingKeys.ts");

    // 必须有"先算差异、无差异就返回"的路径
    if (!/计划|planKeyChanges|changes\.length === 0/.test(keys)) {
      throw new Error("syncSigningKeys 没有跳过无变化写入的路径，每轮都会白写");
    }
    if (!/if \(changes\.length === 0\) return 0;/.test(keys)) {
      throw new Error("缺少数值相等时提前返回，稳态仍会产生写入");
    }

    // 循环里不得出现无条件 update
    const loop = keys.slice(keys.indexOf("for (const [index, key]"), keys.indexOf("export async function"));
    if (/else \{\s*await db\s*\.update/.test(loop)) {
      throw new Error("循环里仍然无条件 UPDATE；只有真的变了才该写");
    }

    // 写入必须合并成一次 batch
    if (!keys.includes("await db.batch(")) {
      throw new Error("多次写入应合并为一次 batch（D1 单事务单往返）");
    }
  });

  check("Cron：retiredAt 与 status 同步维护", () => {
    const keys = read("packages/core/src/services/signingKeys.ts");

    // 降级时必须写 retiredAt
    if (!/retiredAt: status === "active" \? null : now/.test(keys) && !/wantRetiredAt/.test(keys)) {
      throw new Error("降级为 retired 时没有写 retiredAt，字段永远是 NULL");
    }

    // active 的键必须清空 retiredAt
    if (!/retiredAt: null|\? current\.retiredAt \?\? now : null/.test(keys)) {
      throw new Error("active 的键没有清空 retiredAt，字段会残留旧值");
    }
  });

  check("Cron：所有任务放进 waitUntil，不串行阻塞", () => {
    const entry = read("packages/core/src/index.ts");
    const scheduled = entry.slice(entry.indexOf("async scheduled("));

    if (!/ctx\.waitUntil\([\s\S]*runCleanup/.test(scheduled)) {
      throw new Error("runCleanup 没有放进 waitUntil");
    }
    if (!/ctx\.waitUntil\([\s\S]*syncSigningKeys/.test(scheduled)) {
      throw new Error("syncSigningKeys 仍在 await 串行，会挤占清理的 CPU 预算");
    }
    // 不得在 scheduled 里直接 await 这两个慢任务
    if (/^\s*await syncSigningKeys/m.test(scheduled)) {
      throw new Error("scheduled 里仍然直接 await syncSigningKeys");
    }
  });

  check("Cron：signing_keys 超出保留窗口会被清理", () => {
    const keys = read("packages/core/src/services/signingKeys.ts");
    if (!/export async function pruneRetiredKeys/.test(keys)) {
      throw new Error("退役公钥没有清理路径，每次轮换净增一行");
    }

    // 清理必须挂在写路径（cron / 同步）上，不能挂在 JWKS 读路径上 ——
    // 读接口每次被下游轮询都顺手写一次库，是另一类污染。
    const jwks = keys.slice(keys.indexOf("export async function buildJwks"));
    if (/await pruneRetiredKeys\(db\)/.test(jwks)) {
      throw new Error("buildJwks 是只读路径，不得在其中写库");
    }

    const cron = read("packages/core/src/cron.ts");
    if (!/report\.signingKeys = await pruneRetiredKeys\(db\)/.test(cron)) {
      throw new Error("pruneRetiredKeys 没有挂到 cron 上");
    }

    // 保留数量与 JWKS 输出数量必须用同一个常量
    const retiredQuery = jwks.slice(jwks.indexOf('eq(signingKeys.status, "retired")'));
    if (!retiredQuery.includes("RETAINED_RETIRED_KEYS")) {
      throw new Error("JWKS 输出与清理用的保留常量不一致，会删掉仍在输出的键");
    }
  });

  check("OIDC：sid 必须来自发起授权的会话，不能反查", () => {
    const routes = read("packages/core/src/routes/oidc.ts");

    const exchange = routes.slice(routes.indexOf('"/token/exchange"'));

    // sid 必须直接取自授权码，不能来自任何查询结果
    if (!/const sessionId = codeRow\.sessionId;/.test(exchange)) {
      throw new Error("token/exchange 的 sessionId 不是从授权码取的");
    }
    // 不得再出现"取第一条查询结果当 sid"
    if (/sessionRows\[0\]\.id|sessionRows\[0\]\?\.id/.test(exchange)) {
      throw new Error("token/exchange 仍在用查询结果当 sid，多浏览器时会指错会话");
    }
    // 会话校验必须以 id 为主键，而不是以 user_id 为条件取任意一条
    if (!/eq\(sessions\.id,\s*sessionId\)/.test(exchange)) {
      throw new Error("token/exchange 没有按会话 id 校验有效性");
    }

    // 授权码必须存下 sessionId。schema 定义在 /authorize/prepare 之前，切片要往前多取一段。
    const authorize = routes.slice(
      routes.indexOf("const authorizeSchema"),
      routes.indexOf('"/token/exchange"'),
    );
    if (!/sessionId:\s*z\.string\(\)\.min\(1\)/.test(authorize)) {
      throw new Error("authorizeSchema 没有强制要求 sessionId");
    }
    if (!/sessionId:\s*parsed\.data\.sessionId/.test(authorize)) {
      throw new Error("/authorize/prepare 没有把 sessionId 存进授权码");
    }

    // 没有 sessionId 的在途码必须拒绝，不能签发 sid: ""
    if (/sid:\s*sessionId/.test(exchange) && !/if \(!sessionId\)/.test(exchange)) {
      throw new Error("授权码缺 sessionId 时仍在签发 ID Token，会产生 sid 为空的令牌");
    }

    // schema 必须真的加了这一列
    const schema = read("packages/core/src/db/schema.ts");
    const table = schema.slice(schema.indexOf("authorizationCodes"), schema.indexOf("oidcStates"));
    if (!/sessionId:\s*text\("session_id"\)/.test(table)) {
      throw new Error("authorization_codes 表没有 session_id 列");
    }
  });

  check("OIDC：密钥与 PKCE 比较必须恒定时间", () => {
    const svc = read("packages/core/src/services/oidc.ts");

    const client = svc.slice(svc.indexOf("export async function verifyClientSecret"), svc.indexOf("export function parseRedirectUris"));
    if (/hash\s*!==\s*app\.clientSecretHash/.test(client)) {
      throw new Error("verifyClientSecret 用了 !== 直接比较");
    }
    if (!client.includes("timingSafeEqual")) {
      throw new Error("verifyClientSecret 没有用 timingSafeEqual");
    }

    const pkce = svc.slice(svc.indexOf("export async function verifyPkce"));
    if (/computed\s*===\s*codeChallenge/.test(pkce)) {
      throw new Error("verifyPkce 用了 === 直接比较");
    }
    if (!pkce.slice(0, 600).includes("timingSafeEqual")) {
      throw new Error("verifyPkce 没有用 timingSafeEqual");
    }
  });

  check("OIDC：_headers 覆盖每个构建产物", () => {
    const pkg = JSON.parse(read("packages/gateway/package.json"));
    const scripts = pkg.scripts ?? {};
    const headers = read("packages/gateway/public/_headers");

    const assets = new Set();
    for (const key of ["build:js", "build:css"]) {
      for (const m of String(scripts[key] ?? "").matchAll(/--outfile=\S*?\/?assets\/([\w.-]+)/g)) {
        assets.add(m[1]);
      }
    }
    if (assets.size === 0) throw new Error("未能从构建脚本解析出任何产物");

    const missing = [...assets].filter((name) => !headers.includes("/assets/" + name));
    if (missing.length > 0) {
      throw new Error("_headers 漏了: " + missing.join(", "));
    }
  });
}
