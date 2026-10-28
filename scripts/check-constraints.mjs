#!/usr/bin/env node
/**
 * 硬约束门禁。
 *
 * 判定标准只有一条：**改了会导致数据泄露、认证绕过或部署失效，且测试覆盖不到。**
 * 改错后 typecheck 或测试会立刻红的，交回去，不在这里重复。
 *
 * 组织方式：**一个领域一条 check，条内断言多件事**。
 * 条数不是重点，能一眼看出「哪个领域的地基塌了」才是。
 */
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const checks = [];

function check(name, fn) {
  try {
    fn();
    checks.push({ name, ok: true });
  } catch (error) {
    checks.push({ name, ok: false, detail: error.message });
  }
}

// ------------------------------------------------------------------ 工具

const read = (rel) => readFileSync(join(ROOT, rel), "utf8");
const exists = (rel) => existsSync(join(ROOT, rel));

/**
 * 剥离注释后再匹配，避免说明文字里的词被判成违规。
 *
 * 注意块注释的匹配方式：**只剥行首（或 JSX 表达式的花括号）开头的块注释**。
 * 早先用「斜杠星号 + 任意内容 + 星号斜杠」无差别匹配，
 * 结果 app.tsx 里的字符串 "/assets/星号" 被当成注释起点，
 * 一路吃到下一个块注释结尾 —— 把后面所有 app.route(...) 全吞了，
 * 路由表解析出来是空的，前端路径检查因此漏报。
 */
function stripComments(content, kind) {
  if (kind === "toml") {
    return content.split("\n").map((l) => l.replace(/(^|\s)#.*$/, "$1")).join("\n");
  }
  if (kind === "sql") {
    return content.split("\n").map((l) => l.replace(/--.*$/, "")).join("\n");
  }
  return content
    .replace(/^[ \t]*\{[ \t]*\/\*[\s\S]*?\*\//gm, "")
    .replace(/^[ \t]*\/\*[\s\S]*?\*\//gm, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
}

const code = (rel) => {
  const raw = read(rel);
  if (rel.endsWith(".toml")) return stripComments(raw, "toml");
  if (rel.endsWith(".sql")) return stripComments(raw, "sql");
  return stripComments(raw, "ts");
};

/** 取某个函数/路由的代码块，截到下一个 marker 为止。 */
function block(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  if (start < 0) return "";
  const end = endMarker ? source.indexOf(endMarker, start + startMarker.length) : -1;
  return source.slice(start, end > start ? end : start + 3000);
}

/** 递归列出某个目录下指定扩展名的文件（相对 ROOT 的路径）。 */
function walk(dir, pattern) {
  const out = [];
  const visit = (rel) => {
    for (const entry of readdirSync(join(ROOT, rel), { withFileTypes: true })) {
      const path = `${rel}/${entry.name}`;
      if (entry.isDirectory()) visit(path);
      else if (pattern.test(entry.name)) out.push(path);
    }
  };
  visit(dir);
  return out;
}

function must(condition, message) {
  if (!condition) throw new Error(message);
}

function mustInclude(src, needle, message) {
  must(src.includes(needle), message);
}

function mustMatch(src, re, message) {
  must(toRegExp(re).test(src), message);
}

function mustNotMatch(src, re, message) {
  must(!toRegExp(re).test(src), message);
}

/** 允许直接传字符串：字符串按字面量匹配，正则按正则用。 */
function toRegExp(re) {
  return re instanceof RegExp ? re : new RegExp(re.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
}

// ============================================================ 1. 隔离边界
check("隔离边界：Core 不可达，身份不走头部", () => {
  const core = code("packages/core/wrangler.toml");
  mustInclude(core, "workers_dev = false", "Core 必须 workers_dev = false");
  mustNotMatch(core, /^routes\s*=/m, "Core 不得配置 routes");
  mustInclude(core, "[[d1_databases]]", "Core 应有 D1 binding");
  mustNotMatch(core, "kv_namespaces", "Core 不得有 KV");
  mustNotMatch(core, "r2_buckets", "Core 不得有 R2");

  const gateway = code("packages/gateway/wrangler.toml");
  mustInclude(gateway, "[[services]]", "Gateway 应有 Service Binding");
  mustInclude(gateway, "[assets]", "Gateway 应有 Assets");
  for (const forbidden of ["d1_databases", "kv_namespaces", "r2_buckets"]) {
    mustNotMatch(gateway, forbidden, `Gateway 不得有 ${forbidden}`);
  }
  // 免费版：配了 run_worker_first 会在超额时 429 且不回退静态资源
  mustNotMatch(gateway, "run_worker_first", "生产配置不得含 run_worker_first");

  // 身份只走 Service Binding 的 body：CORE.fetch 只允许出现在 callCore.ts
  const callers = walk("packages/gateway/src", /\.(ts|tsx)$/).filter(
    (f) => !f.endsWith("callCore.ts") && read(f).includes("CORE.fetch"),
  );
  must(callers.length === 0, `env.CORE.fetch 出现在 ${callers.join(", ")}`);

  const internal = code("packages/core/src/routes/internal.ts");
  mustNotMatch(internal, '"/query"', "Core 不得有 /query 透传端点");
  mustNotMatch(internal, "payload: z.object({ sql", "Core 不得接受裸 SQL");
});

// ============================================================ 2. 凭证与会话
check("凭证与会话：HMAC、__Host-、mfa_pending 不可鉴权", () => {
  const crypto = code("packages/core/src/lib/crypto.ts");
  mustNotMatch(crypto, /PBKDF2|deriveBits/, "不得使用 PBKDF2");
  mustInclude(crypto, "HMAC", "密码必须经 HMAC 处理");

  const schema = code("packages/core/src/db/schema.ts");
  mustInclude(schema, "password_hash", "密码字段必须叫 password_hash");
  mustNotMatch(schema, /\bpassword:\s*text\(/, "不得有裸 password 字段");

  mustInclude(code("packages/shared/src/index.ts"), '"__Host-sid"', "会话 Cookie 必须带 __Host- 前缀");

  const session = code("packages/gateway/src/middleware/session.ts");
  for (const attr of ["httpOnly: true", "secure: true", 'sameSite: "Lax"', 'path: "/"']) {
    mustInclude(session, attr, `Cookie 缺少 ${attr}`);
  }
  // lastUsedAt 不更新的话，活动会话页显示的"最后活动"永远等于创建时间
  mustInclude(session, "/session/touch", "requireAuth 未更新 lastUsedAt");

  // mfa_pending 必须在服务端被显式拒绝，不能靠调用方自觉
  mustInclude(
    code("packages/core/src/services/session.ts"),
    "SessionStatus.MfaPending",
    "lookupSession 必须显式拒绝 mfa_pending",
  );
  mustInclude(
    code("packages/core/src/routes/internal.ts"),
    '"/session/lookup-pending"',
    "需要 pending 专用查询，与鉴权查询分离",
  );

  const upgrade = block(
    code("packages/core/src/routes/mfa.ts"),
    '"/mfa/verify-totp"',
    "mfaRoutes.post(",
  );
  mustInclude(upgrade, "rotateSessionToken", "MFA 升级必须轮换 token");
  mustNotMatch(upgrade, "createSession\(", "MFA 升级不得新建会话（会撞主键）");
});

// ============================================================ 3. OIDC 协议
check("OIDC：令牌可吊销、协议参数强制、sid 有据可依", () => {
  const oidc = code("packages/core/src/services/oidc.ts");

  const issue = block(oidc, "export async function issueAccessToken", "export type IntrospectionResult");
  mustInclude(issue, "randomHex", "访问令牌必须是随机串");
  mustNotMatch(issue, "signJwt", "访问令牌不得是 JWT（否则无法即时吊销）");

  // 不存在 / 已吊销 / 已过期 必须给出完全相同的响应
  const introspect = block(oidc, "export async function introspect", "export async function revokeToken");
  const falses = (introspect.match(/\{ active: false \}/g) ?? []).length;
  must(falses >= 3, `introspect 无效分支只有 ${falses} 处，应覆盖不存在/已吊销/已过期`);

  mustMatch(oidc, /method === "S256"/, "PKCE 只接受 S256");
  mustInclude(oidc, "isNull(authorizationCodes.usedAt)", "授权码消费必须原子");
  mustInclude(oidc, "returning()", "授权码消费必须以受影响行数判定");

  // 比较必须恒定时间：同一个代码库里两套写法，后来的人只会抄容易的那个
  const client = block(oidc, "export async function verifyClientSecret", "export function parseRedirectUris");
  mustNotMatch(client, /hash\s*!==\s*app\.clientSecretHash/, "verifyClientSecret 不得用 !== 比较");
  mustInclude(client, "timingSafeEqual", "verifyClientSecret 必须用 timingSafeEqual");
  const pkce = oidc.slice(oidc.indexOf("export async function verifyPkce"));
  mustNotMatch(pkce, /computed\s*===\s*codeChallenge/, "verifyPkce 不得用 === 比较");
  mustInclude(pkce.slice(0, 600), "timingSafeEqual", "verifyPkce 必须用 timingSafeEqual");

  // 私钥不落 D1，JWKS 只读 public_jwk
  const keys = code("packages/core/src/services/signingKeys.ts");
  const jwks = block(keys, "export async function buildJwks", "export async function listSigningKeys");
  mustNotMatch(jwks, "private_jwk", "buildJwks 不得读取私钥");
  mustInclude(jwks, "row.publicJwk", "JWKS 必须从 publicJwk 生成");
  mustNotMatch(
    block(schemaOf(), "export const signingKeys", "export const passkeys"),
    /private/i,
    "signing_keys 表不得有私钥字段",
  );

  // sid 必须来自发起授权的会话，不能反查"该用户某个活跃会话"
  const routes = code("packages/core/src/routes/oidc.ts");
  mustInclude(routes, "sid: sessionId", "ID Token 必须含 sid");
  const exchange = routes.slice(routes.indexOf('"/token/exchange"'));
  mustInclude(exchange, "const sessionId = codeRow.sessionId;", "sid 不是从授权码取的");
  mustNotMatch(exchange, /sessionRows\[0\]\??\.id/, "仍在用查询结果当 sid，多浏览器会指错会话");
  mustMatch(exchange, /eq\(sessions\.id,\s*sessionId\)/, "没有按会话 id 校验有效性");
  mustMatch(exchange, /if \(!sessionId\)/, "缺 sessionId 时仍会签发 sid 为空的令牌");

  const authorize = routes.slice(routes.indexOf("const authorizeSchema"), routes.indexOf('"/token/exchange"'));
  mustMatch(authorize, /sessionId:\s*z\.string\(\)\.min\(1\)/, "authorizeSchema 没有强制要求 sessionId");
  mustMatch(authorize, /sessionId:\s*parsed\.data\.sessionId/, "authorize/prepare 没把 sessionId 存进授权码");
  mustMatch(
    block(schemaOf(), "export const authorizationCodes", "export const oidcStates"),
    /sessionId:\s*text\("session_id"\)/,
    "authorization_codes 表没有 session_id 列",
  );

  // CSRF 豁免范围必须精确
  const csrf = code("packages/gateway/src/middleware/csrf.ts");
  const exempt = csrf.match(/EXEMPT_PREFIXES = \[([^\]]*)\]/);
  must(exempt, "未声明 CSRF 豁免前缀");
  const entries = exempt[1].split(",").map((x) => x.trim()).filter(Boolean);
  must(
    entries.length === 1 && entries[0] === '"/oauth/"',
    `CSRF 豁免范围过大: ${entries.join(", ")}`,
  );

  // 每个构建产物都必须有明确的缓存策略：文件名不带 hash，漏掉就按默认走
  const pkg = JSON.parse(read("packages/gateway/package.json"));
  const headers = read("packages/gateway/public/_headers");
  const assets = new Set();
  for (const key of ["build:js", "build:css"]) {
    for (const m of String(pkg.scripts?.[key] ?? "").matchAll(/--outfile=\S*?\/?assets\/([\w.-]+)/g)) {
      assets.add(m[1]);
    }
  }
  must(assets.size > 0, "未能从构建脚本解析出任何产物");
  for (const name of assets) {
    mustInclude(headers, `/assets/${name}`, `_headers 漏了 ${name} 的缓存策略`);
  }
});

function schemaOf() {
  return code("packages/core/src/db/schema.ts");
}

// ============================================================ 4. MFA 数据
check("MFA：secret 加密、防重放、单次使用、challenge 有清理", () => {
  const aes = code("packages/core/src/lib/aes.ts");
  mustInclude(aes, '"AES-GCM"', "TOTP secret 必须 AES-GCM 加密");
  mustInclude(aes, "deriveKey", "必须从主密钥派生");

  const totp = code("packages/core/src/services/totp.ts");
  mustInclude(totp, "encryptSecret", "TOTP secret 未加密");
  mustInclude(totp, "lastUsedStep", "TOTP 未记录已用步长");
  mustInclude(totp, "lt(mfaFactors.lastUsedStep", "TOTP 缺少严格递增判定");

  const recovery = code("packages/core/src/services/recovery.ts");
  mustInclude(recovery, "sha256Hex", "恢复码必须哈希存储");
  mustInclude(recovery, "isNull(mfaRecoveryCodes.usedAt)", "恢复码必须单次使用");
  mustInclude(recovery, "returning(", "恢复码必须以受影响行数判定");

  const passkey = code("packages/core/src/services/passkey.ts");
  mustInclude(
    block(passkey, "export async function completeAuthentication", "// ---- 编解码"),
    "newCounter",
    "Passkey 认证后必须更新 counter",
  );
  const consume = block(passkey, "export async function consumeChallenge", "export async function lazyCleanupChallenges");
  mustInclude(consume, "isNull(passkeyChallenges.consumedAt)", "challenge 必须单次使用");
  mustInclude(consume, "gt(passkeyChallenges.expiresAt", "challenge 必须校验过期");

  // 免用户名登录时 user_id 为 NULL，按 user_id 过滤的清理永远碰不到那些行
  mustMatch(
    code("packages/core/src/cron.ts"),
    /report\.passkeyChallenges\s*=/,
    "cron 未清理 passkey_challenges，匿名登录产生的行会无限堆积",
  );
  mustMatch(passkey, /export async function lazyCleanupExpiredChallenges/, "缺少不按 user_id 过滤的过期清理");
  mustInclude(
    code("packages/core/src/services/passkeyAuth.ts"),
    "await lazyCleanupExpiredChallenges(db)",
    "生成认证选项时没有调用全局过期清理",
  );
});

// ============================================================ 5. 第二因子
check("第二因子：三道门户都有限流、会话绑定与失败计数", () => {
  const mfa = code("packages/core/src/routes/mfa.ts");

  // 密码已泄露时，第二因子是唯一防线；能无限次尝试的防线不构成防线
  const endpoints = [
    { path: '"/mfa/verify-totp"', guard: "checkSecondFactorAllowed", record: "recordSecondFactorFailure", clear: "clearSecondFactorFailures" },
    { path: '"/mfa/verify-recovery"', guard: "checkSecondFactorAllowed", record: "recordSecondFactorFailure", clear: "clearSecondFactorFailures" },
    { path: '"/passkey/login-verify"', guard: "checkPasskeyIpAllowed", record: "recordPasskeyIpFailure", clear: "clearPasskeyIpFailures" },
  ];
  for (const item of endpoints) {
    const start = mfa.indexOf(`mfaRoutes.post(${item.path}`);
    must(start >= 0, `找不到端点 ${item.path}`);
    const next = mfa.indexOf("mfaRoutes.post(", start + 10);
    const body = mfa.slice(start, next > start ? next : start + 4000);

    mustInclude(body, item.guard, `${item.path} 没有调用 ${item.guard}，可无限尝试`);
    mustInclude(body, item.record, `${item.path} 失败时不计数，限流形同虚设`);
    // 通过后必须清零，否则正常用户会被历史失败拖黑
    mustInclude(body, item.clear, `${item.path} 成功后不清零，正常用户会被误锁`);
  }

  // userId 与 sessionId 来自不同地方，不校验绑定就能拿别人的 userId 当预言机
  for (const path of ['"/mfa/verify-totp"', '"/mfa/verify-recovery"']) {
    const start = mfa.indexOf(`mfaRoutes.post(${path}`);
    const next = mfa.indexOf("mfaRoutes.post(", start + 10);
    mustInclude(
      mfa.slice(start, next > start ? next : start + 4000),
      "isPendingSessionOfUser",
      `${path} 未校验 sessionId 与 userId 的绑定，可跨账号爆破验证码`,
    );
  }

  // 桶定义了就必须接线：只定义不用的桶是空头支票
  const rateLimit = code("packages/core/src/services/rateLimit.ts");
  const bucketBlock = rateLimit.slice(
    rateLimit.indexOf("export const buckets"),
    rateLimit.indexOf("// ----", rateLimit.indexOf("export const buckets")),
  );
  const bucketKeys = [...bucketBlock.matchAll(/^\s{2}(\w+):/gm)].map((m) => m[1]);
  must(bucketKeys.length > 0, "未解析到任何限流桶");
  const sources = walk("packages/core/src", /\.ts$/);
  for (const key of bucketKeys) {
    const used = sources.some((f) => read(f).includes(`buckets.${key}`));
    must(used, `限流桶 ${key} 定义了但从未使用`);
  }

  // 状态查询必须带 caller：Core 会校验 caller 与 userId 的关系，
  // 少传就让 Core 一律 403，或者更糟 —— 把校验放宽成"不传就放行"
  for (const file of walk("packages/gateway/src", /\.(ts|tsx)$/)) {
    const src = read(file);
    for (const key of ['"/mfa/status"', '"/mfa/factors"']) {
      let idx = src.indexOf(key);
      while (idx >= 0) {
        const end = src.indexOf("});", idx);
        const frame = src.slice(Math.max(0, idx - 400), end > idx ? end : idx + 400);
        mustMatch(frame, /^\s*caller\s*[,:]?\s*$/m, `${file} 调用 ${key} 时没传 caller 字段`);
        idx = src.indexOf(key, idx + key.length);
      }
    }
  }

  // 服务层的 detail 只允许进 console.error，不能出现在响应里 —— 它可能含挑战值
  mustNotMatch(mfa, /c\.json\(\{[^}]*detail\s*:/, "响应体里带了 detail，会暴露挑战值或凭据数据");
  const passkeyLogs = (code("packages/core/src/services/passkey.ts").match(/console\.error\("\[passkey\]/g) ?? []).length;
  must(passkeyLogs >= 2, "passkey 失败未写入服务端日志，线上无法定位");
});

// ============================================================ 6. 前端脚本
check("前端脚本：路径存在、异常不吞、提示可见", () => {
  // ---- 路径必须对得上路由表 ----
  // 用原文而不是 code()：这里要的是真实的路由注册，不是去注释后的文本。
  const app = read("packages/gateway/src/app.tsx");
  const mounts = new Map();
  for (const m of app.matchAll(/app\.route\("([^"]+)",\s*(\w+)\)/g)) mounts.set(m[2], m[1]);

  const knownPaths = new Set(["/"]);
  for (const file of walk("packages/gateway/src/routes", /\.(ts|tsx)$/)) {
    // 只剥整行注释：块注释正则会把 app.get("/assets/*") 里的 /* 一起吃掉
    const src = read(file)
      .split("\n")
      .filter((line) => {
        const t = line.trimStart();
        return !t.startsWith("//") && !t.startsWith("*") && !t.startsWith("/*");
      })
      .join("\n");
    for (const d of src.matchAll(/(\w+)\.(?:get|post|use)\("([^"]+)"/g)) {
      const prefix = mounts.get(d[1]);
      if (prefix === undefined || d[2].includes("*")) continue;
      const full = prefix === "/" ? d[2] : prefix + d[2];
      knownPaths.add(full.length > 1 && full.endsWith("/") ? full.slice(0, -1) : full);
    }
  }

  const usedPaths = new Set();
  for (const file of ["client.ts", "security-client.ts", "password-client.ts"]) {
    const src = read(`packages/gateway/src/pages/${file}`);
    const quotes = ['"', "'", "`"];
    const stops = ["?", "$", "{"];
    for (let i = 0; i < src.length; i++) {
      if (!quotes.includes(src[i])) continue;
      // 前缀最长的是 /account（8 字符），切片必须够长 ——
      // 早先写成 slice(i+1, i+8) 只给 7 个字符，/account/* 全部漏检。
      if (!/^\/(admin|account|auth|oauth)[\/"]/.test(src.slice(i + 1, i + 10))) continue;
      let j = i + 1;
      while (j < src.length && src[j] !== src[i] && !stops.includes(src[j]) && !/\s/.test(src[j])) j++;
      const path = src.slice(i + 1, j);
      if (path.length > 1) usedPaths.add(path.endsWith("/") ? path.slice(0, -1) : path);
    }
  }
  const missing = [...usedPaths].filter((p) => !knownPaths.has(p));
  must(missing.length === 0, `前端调用了不存在的路径: ${missing.join(", ")}`);

  // ---- 异常必须留住原因 ----
  for (const file of ["client.ts", "security-client.ts"]) {
    const src = read(`packages/gateway/src/pages/${file}`);
    // 不带绑定的 catch 只有"静默忽略"时才可接受（例如能力探测）；
    // 一旦它给用户看提示，真实原因就被替换成一个猜测。
    for (const m of src.matchAll(/\}\s*catch\s*\{([\s\S]{0,400}?)\n\s*\}/g)) {
      mustNotMatch(m[1], /\bhint\s*\(/, `${file}: 不绑定异常的 catch 里给用户提示，真实原因会丢失`);
    }
    mustInclude(src, "console.error", `${file}: 捕获异常后没有 console.error，线上无从排查`);
  }
  // 翻译函数必须只有一份，否则两处文案各自漂移
  mustNotMatch(
    read("packages/gateway/src/pages/security-client.ts"),
    /function describeWebAuthnException/,
    "security-client.ts 又复制了一份 describeWebAuthnException，应共用 webauthn.ts",
  );
  mustMatch(
    read("packages/gateway/src/pages/webauthn.ts"),
    /export function describeWebAuthnException/,
    "webauthn.ts 缺少共用的 describeWebAuthnException",
  );

  // ---- 提示必须写到常驻元素 ----
  mustInclude(read("packages/gateway/src/pages/security-client.ts"), "security-hint", "安全页提示必须写入常驻元素");
  mustInclude(
    read("packages/gateway/src/pages/mfa.tsx"),
    'action="/auth/mfa/recovery"',
    "MFA 页面缺少恢复码入口，设备丢失后无路可走",
  );
});

// ============================================================ 7. 用户旅程
check("用户旅程：每个后端能力都有入口，每次操作都有反馈", () => {
  const admin = code("packages/gateway/src/routes/admin.tsx");
  const account = code("packages/gateway/src/routes/account.tsx");

  // 后端接口存在，前端就必须有提交入口
  for (const route of ["/users/reset-mfa", "/users/set-status", "/invites/create", "/invites/revoke"]) {
    mustInclude(admin, `adminRoutes.post("${route}"`, `缺少 ${route} 的提交路由`);
  }
  // 改密页 GET 与 POST 必须成对
  mustInclude(account, 'accountRoutes.get("/password"', "缺少改密页 GET");
  mustInclude(account, 'accountRoutes.post("/password"', "缺少改密提交 POST");
  mustInclude(account, "/user/change-password", "改密 POST 未调用 Core 的改密方法");
  mustInclude(account, "setSessionCookie", "Gateway 必须把轮换后的 token 写回 Cookie");
  // 普通用户要有自己的落地页：user 进 /admin 只会撞「无权限」
  mustInclude(account, 'accountRoutes.get("/"', "缺少普通用户的账户首页");
  mustInclude(code("packages/gateway/src/routes/auth.tsx"), 'role === "user"', "登录后未按角色分流");

  // 跳转带了参数却没人读，等于操作结果永远不可见
  for (const file of [
    "packages/gateway/src/routes/admin.tsx",
    "packages/gateway/src/routes/admin-apps.tsx",
    "packages/gateway/src/routes/account.tsx",
  ]) {
    const src = read(file);
    const written = new Set([...src.matchAll(/\?(done|error|deleted)=/g)].map((m) => m[1]));
    if (written.size === 0) continue;
    const readParams = new Set([...src.matchAll(/c\.req\.query\("(\w+)"\)/g)].map((m) => m[1]));
    for (const param of written) {
      must(readParams.has(param), `${file} 跳转带了 ?${param}= 但页面从不读取，用户看不到结果`);
    }
  }
  mustNotMatch(admin, /id="page-notice"/, "page-notice 是死元素，没有任何代码给它填内容");

  // 丢弃 callCore 返回值 = 失败也报成功。登出/吊销这类"协议要求无条件成功"的除外，
  // 它们必须在上一行显式标注 best-effort。
  for (const file of ["packages/gateway/src/routes/admin.tsx", "packages/gateway/src/routes/admin-apps.tsx"]) {
    const lines = read(file).split("\n");
    const offenders = [];
    for (let i = 0; i < lines.length; i++) {
      if (!/await callCore/.test(lines[i]) || /=\s*await callCore/.test(lines[i])) continue;
      if (/best-effort/.test(lines[i - 1] ?? "") || /best-effort/.test(lines[i])) continue;
      offenders.push(i + 1);
    }
    must(offenders.length === 0, `${file} 第 ${offenders.join(", ")} 行丢弃了 callCore 的返回值，失败会假装成功`);
  }

  // 面向普通用户的页面不传 role，会让 user 看到完整管理菜单
  for (const file of [
    "packages/gateway/src/routes/admin.tsx",
    "packages/gateway/src/routes/admin-apps.tsx",
    "packages/gateway/src/routes/account.tsx",
    "packages/gateway/src/routes/security.tsx",
  ]) {
    for (const use of read(file).matchAll(/<AdminLayout[^>]*>/g)) {
      if (use[0].includes('current="/account"')) {
        mustInclude(use[0], "role=", `${file} 的账户页没传 role，普通用户会看到管理菜单`);
      }
    }
  }
});

// ============================================================ 8. 危险动作
check("危险动作：重置 / 恢复 / 改密后的会话处理", () => {
  const mfa = code("packages/core/src/routes/mfa.ts");

  const reset = block(mfa, '"/mfa/reset"', "mfaRoutes.post(");
  mustInclude(reset, "revokeMfaStatements", "超管重置 MFA 必须吊销因子");
  mustInclude(reset, "revokeAllStatements", "超管重置 MFA 必须吊销会话");
  mustInclude(reset, "db.batch", "重置必须走单事务");
  mustInclude(reset, "Role.SuperAdmin", "重置仅限超管");

  const recovery = block(mfa, '"/mfa/verify-recovery"', "mfaRoutes.post(");
  mustInclude(recovery, "revokeAllStatements", "使用恢复码后必须吊销其余会话");
  mustInclude(recovery, "keepSessionId", "恢复码登录应保留当前新会话");

  const change = block(
    code("packages/core/src/routes/internal.ts"),
    'internalRoutes.post("/user/change-password"',
    "internalRoutes.post(",
  );
  mustInclude(change, "keepSessionId", "改密不得吊销当前会话");
  mustInclude(change, "rotateSessionToken", "改密后必须轮换当前会话 token");
});

// ============================================================ 9. 后台防护
check("后台：超管门禁、审计不阻断、管理接口有角色校验", () => {
  const gate = code("packages/gateway/src/middleware/mfaGate.ts");
  mustInclude(gate, "Role.SuperAdmin", "MFA 门禁必须区分超管");
  mustInclude(gate, "/account/security", "门禁必须放行绑定页，否则死循环");
  mustInclude(gate, "mfa_binding_required", "门禁缺少拒绝码");

  mustInclude(code("packages/gateway/src/routes/admin.tsx"), "mfaGate", "admin 路由必须挂 MFA 门禁");

  // 审计是 best-effort：写失败绝不能阻断认证
  mustInclude(code("packages/core/src/services/audit.ts"), "try {", "审计写入失败必须隔离，不得阻断认证");
});

// ============================================================ 10. Cron 与容量
check("Cron：分批清理、密钥同步稳态零写入、任务不串行", () => {
  const toml = code("packages/core/wrangler.toml");
  mustInclude(toml, 'crons = ["*/15 * * * *"]', "Cron 频率必须为 15 分钟");

  const cron = code("packages/core/src/cron.ts");
  mustInclude(cron, "CRON_DELETE_BATCH", "清理必须分批，不得扫全表");

  const keys = code("packages/core/src/services/signingKeys.ts");
  // 每轮无条件 UPDATE 每把钥匙 = 96 tick × 2 把 = 192 行白写/天，且共用写入配额
  mustMatch(keys, /if \(changes\.length === 0\) return 0;/, "缺少数值相等时提前返回，稳态仍会产生写入");
  const loop = keys.slice(keys.indexOf("for (const [index, key]"), keys.indexOf("export async function"));
  mustNotMatch(loop, /else \{\s*await db\s*\.update/, "循环里仍然无条件 UPDATE");
  mustInclude(keys, "await db.batch(", "多次写入应合并为一次 batch");
  mustMatch(keys, /wantRetiredAt/, "降级为 retired 时没有写 retiredAt");
  mustMatch(keys, /retiredAt: null|\? current\.retiredAt \?\? now : null/, "active 的键没有清空 retiredAt");

  // 同步与清理都放 waitUntil：串行 await 会挤占 10ms CPU 预算
  const scheduled = code("packages/core/src/index.ts");
  const sched = scheduled.slice(scheduled.indexOf("async scheduled("));
  mustMatch(sched, /ctx\.waitUntil\([\s\S]*runCleanup/, "runCleanup 没有放进 waitUntil");
  mustMatch(sched, /ctx\.waitUntil\([\s\S]*syncSigningKeys/, "syncSigningKeys 仍在 await 串行");
  mustNotMatch(sched, /^\s*await syncSigningKeys/m, "scheduled 里仍然直接 await syncSigningKeys");

  // 退役公钥必须有清理，且不能挂在只读路径上
  mustMatch(keys, /export async function pruneRetiredKeys/, "退役公钥没有清理路径，每次轮换净增一行");
  mustNotMatch(
    keys.slice(keys.indexOf("export async function buildJwks")),
    /await pruneRetiredKeys\(db\)/,
    "buildJwks 是只读路径，不得在其中写库",
  );
  mustMatch(cron, /report\.signingKeys = await pruneRetiredKeys\(db\)/, "pruneRetiredKeys 没有挂到 cron 上");
  mustInclude(
    keys.slice(keys.indexOf('eq(signingKeys.status, "retired")')),
    "RETAINED_RETIRED_KEYS",
    "JWKS 输出与清理用的保留常量不一致",
  );
});

// ============================================================ 11. 迁移
check("迁移：目录扫描、编号连续、与 schema 双向一致", () => {
  const migrations = readdirSync(join(ROOT, "packages/core/migrations")).filter((f) => f.endsWith(".sql"));
  must(migrations.length > 0, "migrations 目录为空");
  for (const file of migrations) {
    mustMatch(file, /^\d{4}_[a-z0-9_]+\.sql$/, `迁移文件名不符合 NNNN_name.sql: ${file}`);
  }

  // 编号必须连续：乱序会被 wrangler 按文件名顺序应用
  const numbers = migrations.map((f) => Number(f.slice(0, 4))).sort((a, b) => a - b);
  must(numbers.every((n, i) => n === i + 1), `迁移编号不连续: ${numbers.join(", ")}`);

  // schema.ts 声明的表必须都在迁移里建过；反之说明代码已落后于库
  const declared = [...schemaOf().matchAll(/sqliteTable\(\s*"([a-z_]+)"/g)].map((m) => m[1]);
  must(declared.length > 0, "schema.ts 未解析到任何表");
  const created = new Set();
  for (const file of migrations) {
    for (const m of read(`packages/core/migrations/${file}`).matchAll(/CREATE TABLE (?:IF NOT EXISTS )?([a-z_]+)/g)) {
      created.add(m[1]);
    }
  }
  const missingInSql = declared.filter((t) => !created.has(t));
  must(missingInSql.length === 0, `schema 声明了但迁移未建表: ${missingInSql.join(", ")}`);
  const missingInSchema = [...created].filter((t) => !declared.includes(t));
  must(missingInSchema.length === 0, `迁移建了表但 schema 未声明: ${missingInSchema.join(", ")}`);

  // 只比对表名不够：schema 里加一列而迁移忘了 ALTER，能一路过门禁到线上。
  //
  // 列必须落在「这张表自己的定义段」里 —— 全局搜索会被同名列误导
  // （access_tokens.session_id 和 authorization_codes.session_id 是两个不同的东西）。
  const sqlByFile = migrations.map((f) => read(`packages/core/migrations/${f}`));
  const missingColumns = [];

  const schema = schemaOf();
  const tableStarts = [...schema.matchAll(/sqliteTable\(\s*"([a-z_]+)"/g)].map((m) => ({
    table: m[1],
    start: m.index,
  }));
  for (let i = 0; i < tableStarts.length; i++) {
    const { table, start } = tableStarts[i];
    const end = i + 1 < tableStarts.length ? tableStarts[i + 1].start : schema.length;
    const tableBlock = schema.slice(start, end);

    // 这张表在迁移里的所有相关片段：CREATE TABLE 段 + 针对它的 ALTER TABLE
    const relevant = sqlByFile
      .map((sql) => {
        const create = sql.match(new RegExp(`CREATE TABLE (?:IF NOT EXISTS )?${table} \\([\\s\\S]*?\\n\\);`))?.[0] ?? "";
        const alters = [...sql.matchAll(new RegExp(`ALTER TABLE ${table} [^;]+;`, "g"))].map((m) => m[0]).join("\n");
        return create + "\n" + alters;
      })
      .join("\n")
      .toLowerCase();

    if (!relevant.trim()) continue; // 表本身已由上面的双向比对覆盖

    for (const col of tableBlock.matchAll(/^\s{4}([a-zA-Z][\w]*):\s*(?:text|integer)\(/gm)) {
      const snake = col[1].replace(/[A-Z]/g, (ch) => "_" + ch.toLowerCase());
      if (!relevant.includes(snake)) missingColumns.push(`${table}.${snake}`);
    }
  }
  must(
    missingColumns.length === 0,
    `schema 声明了列但迁移里找不到（漏了 ALTER TABLE）: ${missingColumns.join(", ")}`,
  );

  // 必须走 wrangler 的版本表：手工执行过的文件不会被记录，下次 apply 会重跑
  mustInclude(read(".github/workflows/deploy.yml"), "d1 migrations apply", "deploy.yml 未通过 wrangler 应用迁移");
  mustNotMatch(
    read("docs/deploy.md"),
    /0001_init\.sql[^\n]{0,80}0002/,
    "docs/deploy.md 又硬编码了迁移文件清单，加迁移时会过期",
  );
});

// ============================================================ 12. 构建与禁止项
check("构建：包管理器锁定、命名匹配、未引入被禁依赖", () => {
  for (const rel of ["package.json", "packages/core/package.json", "packages/gateway/package.json"]) {
    mustMatch(
      String(JSON.parse(read(rel)).packageManager ?? ""),
      /^pnpm@/,
      `${rel} 缺少 packageManager`,
    );
  }

  mustMatch(code("packages/core/wrangler.toml"), /^name = "sso-core"$/m, "Core 名必须为 sso-core");
  mustMatch(code("packages/gateway/wrangler.toml"), /^name = "sso-gateway"$/m, "Gateway 名必须为 sso-gateway");
  mustInclude(
    code("packages/gateway/wrangler.toml"),
    'service = "sso-core"',
    "Gateway 的 Service Binding 必须指向 sso-core",
  );

  const gi = read(".gitignore");
  for (const pattern of ["dist/", "packages/gateway/public/assets/", ".dev.vars"]) {
    mustInclude(gi, pattern, `.gitignore 缺少 ${pattern}`);
  }
  mustInclude(gi, "!packages/core/migrations/*.sql", "迁移文件被 *.sql 误伤");

  const gatewayPkg = JSON.parse(read("packages/gateway/package.json"));
  const deps = { ...gatewayPkg.dependencies, ...gatewayPkg.devDependencies };
  mustNotMatch(Object.keys(deps).join(" "), /astro/, "不得引入 astro");

  for (const file of walk("packages", /\.(ts|tsx|sql|toml)$/)) {
    const src = code(file);
    mustNotMatch(src, /r2_buckets|kv_namespaces|CREATE TABLE content\b/, `${file} 出现被禁资源`);
    mustNotMatch(src, /from ["']hono\/css["']/, `${file} 使用了 hono/css`);
  }
});

// ============================================================ 13. 公开仓库
check("公开仓库：不泄露 database_id 与真实域名", () => {
  const toml = read("packages/core/wrangler.toml");
  const dbId = toml.match(/database_id\s*=\s*"([^"]*)"/);
  must(dbId, "缺少 database_id 配置项");
  must(dbId[1] === "REPLACE_WITH_D1_DATABASE_ID", "database_id 已填入真实值，公开仓库不应包含");

  const deploy = read("docs/deploy.md");
  const allowed = ["your-domain.com", "example.com", "localhost"];
  const skip = /cloudflare\.com|github\.com|rfc-editor\.org|developer\.mozilla\.org/;
  const offenders = (deploy.match(/https:\/\/[a-z0-9.-]+\.[a-z]{2,}/gi) ?? []).filter((url) => {
    const host = url.replace(/^https:\/\//i, "").toLowerCase();
    return !allowed.some((a) => host.includes(a)) && !skip.test(host);
  });
  must(offenders.length === 0, `文档含疑似真实域名: ${[...new Set(offenders)].join(", ")}`);
});

// ============================================================ 14. CI 与部署
check("CI：部署全程手动、配置注入安全、种子脚本幂等", () => {
  const deploy = read(".github/workflows/deploy.yml");
  mustInclude(deploy, "workflow_dispatch", "deploy.yml 必须手动触发");
  mustNotMatch(deploy, /^  push:/m, "deploy.yml 不得由 push 触发");
  mustInclude(deploy, "inputs.confirm", "缺少 DEPLOY 确认输入");

  // d1 create 不支持 --json；sed 改 TOML 会丢引号
  mustNotMatch(deploy, /d1 create[^\n]*--json/, "d1 create 不支持 --json");
  mustNotMatch(deploy, /sed -i[^\n]*wrangler\.toml/, "不得用 sed 改 wrangler.toml");
  mustInclude(deploy, "JSON.stringify(issuer)", "ISSUER 注入应使用 JSON.stringify 保证引号");
  // 自校验必须离线：d1 list 需要凭证
  mustNotMatch(deploy, /wrangler d1 list[^\n]*\|\|\s*\{/, "d1 list 需要凭证，不能用作配置自校验");
  mustInclude(deploy, "deploy --dry-run", "缺少离线配置校验");
  must((deploy.match(/secret bulk/g) ?? []).length >= 2, "两个 Worker 都应注入 secret");

  // deploy-quick 能部署 Core 却不跑迁移，必须自己拦住未应用的迁移
  const quick = read(".github/workflows/deploy-quick.yml");
  mustInclude(quick, "workflow_dispatch", "deploy-quick.yml 必须手动触发");
  mustInclude(quick, "inputs.confirm", "deploy-quick.yml 缺少 DEPLOY 确认");
  const quickCore = quick.slice(quick.indexOf("deploy-core:"));
  must(quickCore.length > 0, "deploy-quick.yml 缺少 deploy-core 作业");
  mustMatch(quickCore, /d1 migrations list\s+sso-db/, "deploy-quick 没有检查未应用迁移，可能部署出代码新库旧的状态");
  mustInclude(quickCore, "Migrations to be applied", "deploy-quick 没有对未应用迁移做拦截");
  must(
    quickCore.search(/d1 migrations list\s+sso-db/) < quickCore.search(/wrangler deploy/),
    "迁移检查必须在部署之前执行",
  );

  // 种子脚本：幂等、不强制改密、不把两件事混成一句话
  const seed = read("scripts/seed-admin-ci.mjs");
  mustInclude(seed, "role = 'super_admin'", "种子脚本缺少已有超管检查");
  mustInclude(seed, "created=false", "种子脚本缺少跳过输出");
  mustInclude(seed, "至少 12 位", "种子脚本未校验密码长度");
  mustNotMatch(seed, /首次登录会强制绑定 MFA/, "种子脚本把改密与 MFA 混成一句话，容易被读成互相矛盾");
  for (const file of ["scripts/seed-admin-ci.mjs", "scripts/seed-superadmin.mjs"]) {
    const match = read(file).match(/must_change_password[\s\S]{0,200}?'active',\s*([01]),/);
    must(match, `${file} 找不到 must_change_password 的值`);
    must(match[1] === "0", `${file} 强制用户改密（密码是部署者自己设的）`);
  }
  mustInclude(deploy, "seed-admin-ci.mjs", "deploy.yml 未调用种子脚本");

  // 单元测试跑在构建之前（Install → Typecheck → Test → … → Build）。
  // 测试若去读 dist/ 或 public/assets/，干净的 CI 上必然 ENOENT ——
  // 本地因为早就构建过，完全看不出来。
  for (const file of walk("packages/gateway/test", /\.test\.tsx?$/)) {
    const src = read(file);
    for (const forbidden of ["../public/assets", "../dist"]) {
      mustNotMatch(
        src,
        new RegExp(forbidden.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
        `${file} 读取构建产物，构建前跑测试会失败`,
      );
    }
  }

  // 三个 workflow 都必须用推导脚本，不得再手写产物清单
  const workflows = ["deploy.yml", "deploy-quick.yml", "verify.yml"];
  for (const file of workflows) {
    const src = read(`.github/workflows/${file}`);
    mustNotMatch(src, /dist\/assets\/app\.css/, `${file} 又手写了产物清单，加脚本时会漏`);
  }
  for (const file of ["deploy.yml", "deploy-quick.yml", "verify.yml"]) {
    mustInclude(
      read(`.github/workflows/${file}`),
      "verify-build-output.mjs",
      `${file} 没有用推导脚本检查产物`,
    );
  }
});

// ============================================================ 15. 文档统计
check("文档：统计数字与实际一致", () => {
  // 手写的数字每加一条用例就过期一次，而没人会因为数字错了而察觉
  const tests = walk("packages", /\.test\.tsx?$/).reduce(
    (sum, file) => sum + (read(file).match(/^\s*it\(/gm) ?? []).length,
    0,
  );
  must(tests > 0, "未统计到任何测试用例");

  const deployDoc = read("docs/deploy.md");
  const claimed = deployDoc.match(/单元测试（(\d+) 个）/)?.[1];
  if (claimed !== undefined) {
    must(Number(claimed) === tests, `docs/deploy.md 写的是 ${claimed} 个测试，实际 ${tests} 个`);
  }
});

// ============================================================ 输出
// 门禁条数自检必须放在最后：它要数 checks.length，
// 而文档里写的「N 条门禁」一旦过期，不会有任何症状。
{
  const actual = checks.length + 1;
  const mismatched = [];
  let claims = 0;
  for (const file of ["README.md", "SECURITY.md", "CONTRIBUTING.md", "docs/deploy.md"]) {
    for (const line of read(file).split("\n")) {
      if (!/门禁|不可退让|硬约束/.test(line)) continue;
      // 两种写法都算声明：「N 条门禁」与「N/N 通过」
      for (const m of line.matchAll(/(\d+)\s*条|(\d+)\/\d+\s*通过/g)) {
        claims++;
        if (Number(m[1] ?? m[2]) !== actual) {
          mismatched.push(`${file}: "${line.trim().slice(0, 40)}" 里的 ${m[1] ?? m[2]}`);
        }
      }
    }
  }
  // 文档里一条声明都找不到，说明它们被改写了 —— 那等于这条检查静默失效
  if (claims === 0) mismatched.push("四份文档里都没找到门禁条数声明");
  checks.push(
    mismatched.length > 0
      ? { name: "文档：门禁条数与实际一致", ok: false, detail: `实际 ${actual} 条，但 ${mismatched.join("; ")}` }
      : { name: "文档：门禁条数与实际一致", ok: true },
  );
}

for (const c of checks) {
  console.log(`${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.ok ? "" : `\n      ${c.detail}`}`);
}
const failed = checks.filter((c) => !c.ok);
console.log();
console.log(`${checks.length - failed.length}/${checks.length} 通过`);
if (failed.length) process.exit(1);