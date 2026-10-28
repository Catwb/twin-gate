#!/usr/bin/env node
/**
 * 硬约束门禁。
 *
 * 判定标准只有一条：**改了会导致数据泄露、认证绕过或部署失效，且测试覆盖不到。**
 *
 * 凡是「改错后测试或运行时会立刻暴露」的（比如响应字段名、配置项取值），
 * 交给 typecheck 和单元测试，不在这里重复。
 *
 * 每条 check 内部可以断言多件事，按领域聚合，不再一行一条。
 */
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join, resolve, relative } from "node:path";
import { checkFrontendPaths } from "./checks/frontend-paths.mjs";

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

const read = (rel) => readFileSync(join(ROOT, rel), "utf8");
const exists = (rel) => existsSync(join(ROOT, rel));

/** 剥离注释后再匹配，避免说明文字里的词被判成违规。 */
function stripComments(content, kind) {
  if (kind === "toml") {
    return content.split("\n").map((l) => l.replace(/(^|\s)#.*$/, "$1")).join("\n");
  }
  if (kind === "sql") {
    return content.split("\n").map((l) => l.replace(/--.*$/, "")).join("\n");
  }
  return content.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

const code = (rel) => {
  const raw = read(rel);
  if (rel.endsWith(".toml")) return stripComments(raw, "toml");
  if (rel.endsWith(".sql")) return stripComments(raw, "sql");
  return stripComments(raw, "ts");
};

/** 取某个函数/路由的代码块，截到下一个同级定义为止。 */
function block(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  if (start < 0) return "";
  const end = endMarker ? source.indexOf(endMarker, start + startMarker.length) : -1;
  return source.slice(start, end > start ? end : start + 3000);
}

function expect(condition, message) {
  if (!condition) throw new Error(message);
}

// ============================================================ 1. 部署边界
check("部署边界：Core 不可达，绑定面最小", () => {
  const core = code("packages/core/wrangler.toml");
  expect(core.includes("workers_dev = false"), "Core 必须 workers_dev = false");
  expect(!/^routes\s*=/m.test(core), "Core 不得配置 routes");
  expect(core.includes("[[d1_databases]]"), "Core 应有 D1 binding");
  expect(!core.includes("kv_namespaces"), "Core 不得有 KV");
  expect(!core.includes("r2_buckets"), "Core 不得有 R2");

  const gateway = code("packages/gateway/wrangler.toml");
  expect(gateway.includes("[[services]]"), "Gateway 应有 Service Binding");
  expect(gateway.includes("[assets]"), "Gateway 应有 Assets");
  for (const forbidden of ["d1_databases", "kv_namespaces", "r2_buckets"]) {
    expect(!gateway.includes(forbidden), `Gateway 不得有 ${forbidden}`);
  }
  // 免费版：配了 run_worker_first 会在超额时 429 且不回退静态资源
  expect(!gateway.includes("run_worker_first"), "生产配置不得含 run_worker_first");
});

// ============================================================ 2. 身份传播
check("身份传播：只走 body，Core 无透传口", () => {
  const files = [];
  const walk = (dir) => {
    for (const entry of readdirSync(join(ROOT, dir), { withFileTypes: true })) {
      const path = `${dir}/${entry.name}`;
      if (entry.isDirectory()) walk(path);
      else if (/\.(ts|tsx)$/.test(entry.name)) files.push(path);
    }
  };
  walk("packages/gateway/src");

  const offenders = files.filter((f) => !f.endsWith("callCore.ts") && read(f).includes("CORE.fetch"));
  expect(offenders.length === 0, `env.CORE.fetch 出现在 ${offenders.join(", ")}`);

  const internal = code("packages/core/src/routes/internal.ts");
  expect(!internal.includes('"/query"'), "Core 不得有 /query 透传端点");
  expect(!internal.includes("payload: z.object({ sql"), "Core 不得接受裸 SQL");
});

// ============================================================ 3. 密码与 Cookie
check("密码与会话凭证：HMAC + __Host- + 安全属性", () => {
  const crypto = code("packages/core/src/lib/crypto.ts");
  expect(!/PBKDF2|deriveBits/.test(crypto), "不得使用 PBKDF2");
  expect(crypto.includes("HMAC"), "密码必须经 HMAC 处理");

  const schema = code("packages/core/src/db/schema.ts");
  expect(schema.includes("password_hash"), "密码字段必须叫 password_hash");
  expect(!/\bpassword:\s*text\(/.test(schema), "不得有裸 password 字段");

  const shared = code("packages/shared/src/index.ts");
  expect(shared.includes('"__Host-sid"'), "会话 Cookie 必须带 __Host- 前缀");

  const session = code("packages/gateway/src/middleware/session.ts");
  for (const attr of ["httpOnly: true", "secure: true", 'sameSite: "Lax"', 'path: "/"']) {
    expect(session.includes(attr), `Cookie 缺少 ${attr}`);
  }
});

// ============================================================ 4. 会话状态
check("会话状态：mfa_pending 不得鉴权，升级必须轮换", () => {
  const session = code("packages/core/src/services/session.ts");
  expect(session.includes("SessionStatus.MfaPending"), "lookupSession 必须显式拒绝 mfa_pending");

  const internal = code("packages/core/src/routes/internal.ts");
  expect(internal.includes('"/session/lookup-pending"'), "需要 pending 专用查询，与鉴权查询分离");

  const mfa = code("packages/core/src/routes/mfa.ts");
  const upgrade = block(mfa, '"/mfa/verify-totp"', 'mfaRoutes.post(');
  expect(upgrade.includes("rotateSessionToken"), "MFA 升级必须轮换 token");
  expect(!upgrade.includes("createSession("), "MFA 升级不得新建会话（会撞主键）");
});

// ============================================================ 5. OIDC 令牌
check("OIDC：令牌可吊销，协议参数强制", () => {
  const oidc = code("packages/core/src/services/oidc.ts");

  const issue = block(oidc, "export async function issueAccessToken", "export type IntrospectionResult");
  expect(issue.includes("randomHex"), "访问令牌必须是随机串");
  expect(!issue.includes("signJwt"), "访问令牌不得是 JWT（否则无法即时吊销）");

  // 无效、吊销、过期三种情况必须给出完全相同的响应
  const introspect = block(oidc, "export async function introspect", "export async function revokeToken");
  const falses = (introspect.match(/\{ active: false \}/g) ?? []).length;
  expect(falses >= 3, `introspect 无效分支只有 ${falses} 处，应覆盖不存在/已吊销/已过期`);

  // 授权码必须原子消费且强制 PKCE
  expect(oidc.includes('method === "S256"'), "PKCE 只接受 S256");
  expect(oidc.includes("isNull(authorizationCodes.usedAt)"), "授权码消费必须原子");
  expect(oidc.includes("returning()"), "授权码消费必须以受影响行数判定");

  // 私钥不落 D1，JWKS 只读 public_jwk
  const keys = code("packages/core/src/services/signingKeys.ts");
  const jwks = block(keys, "export async function buildJwks", "export async function listSigningKeys");
  expect(!jwks.includes("private_jwk"), "buildJwks 不得读取私钥");
  expect(jwks.includes("row.publicJwk"), "JWKS 必须从 publicJwk 生成");

  const schema = code("packages/core/src/db/schema.ts");
  const keyTable = block(schema, "export const signingKeys", "export const passkeys");
  expect(!/private/i.test(keyTable), "signing_keys 表不得有私钥字段");

  // ID Token 需要 sid，为将来 Back-channel Logout 留钩子
  const routes = code("packages/core/src/routes/oidc.ts");
  expect(routes.includes("sid: sessionId"), "ID Token 必须含 sid");

  // CSRF 豁免范围必须精确
  const csrf = code("packages/gateway/src/middleware/csrf.ts");
  const exempt = csrf.match(/EXEMPT_PREFIXES = \[([^\]]*)\]/);
  expect(exempt, "未声明 CSRF 豁免前缀");
  const entries = exempt[1].split(",").map((x) => x.trim()).filter(Boolean);
  expect(entries.length === 1 && entries[0] === '"/oauth/"', `CSRF 豁免范围过大: ${entries.join(", ")}`);
});

// ============================================================ 6. MFA 数据安全
check("MFA：secret 加密、防重放、单次使用", () => {
  const aes = code("packages/core/src/lib/aes.ts");
  expect(aes.includes('"AES-GCM"'), "TOTP secret 必须 AES-GCM 加密");
  expect(aes.includes("deriveKey"), "必须从主密钥派生");

  const totp = code("packages/core/src/services/totp.ts");
  expect(totp.includes("encryptSecret"), "TOTP secret 未加密");
  expect(totp.includes("lastUsedStep"), "TOTP 未记录已用步长");
  expect(totp.includes("lt(mfaFactors.lastUsedStep"), "TOTP 缺少严格递增判定");

  const recovery = code("packages/core/src/services/recovery.ts");
  expect(recovery.includes("sha256Hex"), "恢复码必须哈希存储");
  expect(recovery.includes("isNull(mfaRecoveryCodes.usedAt)"), "恢复码必须单次使用");
  expect(recovery.includes("returning("), "恢复码必须以受影响行数判定");

  const passkey = code("packages/core/src/services/passkey.ts");
  const auth = block(passkey, "export async function completeAuthentication", "// ---- 编解码");
  expect(auth.includes("newCounter"), "Passkey 认证后必须更新 counter");

  // challenge 的单次使用与过期在 consumeChallenge 里，不在 completeAuthentication 内
  const consume = block(passkey, "export async function consumeChallenge", "export async function lazyCleanupChallenges");
  expect(consume.includes("isNull(passkeyChallenges.consumedAt)"), "challenge 必须单次使用");
  expect(consume.includes("gt(passkeyChallenges.expiresAt"), "challenge 必须校验过期");
});

// ============================================================ 7. 危险动作吊销
check("危险动作：重置/恢复/改密后的会话处理", () => {
  const mfa = code("packages/core/src/routes/mfa.ts");

  const reset = block(mfa, '"/mfa/reset"', "mfaRoutes.post(");
  expect(reset.includes("revokeMfaStatements"), "超管重置 MFA 必须吊销因子");
  expect(reset.includes("revokeAllStatements"), "超管重置 MFA 必须吊销会话");
  expect(reset.includes("db.batch"), "重置必须走单事务");
  expect(reset.includes("Role.SuperAdmin"), "重置仅限超管");

  const recovery = block(mfa, '"/mfa/verify-recovery"', "mfaRoutes.post(");
  expect(recovery.includes("revokeAllStatements"), "使用恢复码后必须吊销其余会话");
  expect(recovery.includes("keepSessionId"), "恢复码登录应保留当前新会话");

  const internal = code("packages/core/src/routes/internal.ts");
  const change = block(internal, 'internalRoutes.post("/user/change-password"', "internalRoutes.post(");
  expect(change.includes("keepSessionId"), "改密不得吊销当前会话");
  expect(change.includes("rotateSessionToken"), "改密后必须轮换当前会话 token");

  const account = code("packages/gateway/src/routes/account.tsx");
  expect(account.includes("setSessionCookie"), "Gateway 必须把轮换后的 token 写回 Cookie");
});

// ============================================================ 8. 后台防护
check("后台：超管门禁、审计不阻断、提示可见", () => {
  const gate = code("packages/gateway/src/middleware/mfaGate.ts");
  expect(gate.includes("Role.SuperAdmin"), "MFA 门禁必须区分超管");
  expect(gate.includes("/account/security"), "门禁必须放行绑定页，否则死循环");
  expect(gate.includes("mfa_binding_required"), "门禁缺少拒绝码");

  const admin = code("packages/gateway/src/routes/admin.tsx");
  expect(admin.includes("mfaGate"), "admin 路由必须挂 MFA 门禁");

  const audit = code("packages/core/src/services/audit.ts");
  expect(audit.includes("try {"), "审计写入失败必须隔离，不得阻断认证");

  // 安全页的提示必须写到常驻元素，不能写进 hidden 面板
  const securityClient = code("packages/gateway/src/pages/security-client.ts");
  expect(securityClient.includes("security-hint"), "安全页提示必须写入常驻元素");
  expect(securityClient.includes("console.error"), "Passkey 异常必须打印到控制台");

  // 恢复码必须有 UI 入口，否则恢复路径等于不存在
  const mfaPage = code("packages/gateway/src/pages/mfa.tsx");
  expect(mfaPage.includes('action="/auth/mfa/recovery"'), "MFA 页面缺少恢复码表单");

  // 普通用户要有自己的落地页：user 进 /admin 会撞「无权限」
  const auth = code("packages/gateway/src/routes/auth.tsx");
  expect(auth.includes('role === "user"'), "登录后未按角色分流，user 会被送去 /admin");
  const account = code("packages/gateway/src/routes/account.tsx");
  expect(account.includes('accountRoutes.get("/"'), "缺少普通用户的账户首页");

  // 管理操作不能只有只读表格：后端接口存在就必须有入口
  const adminRoutesSrc = code("packages/gateway/src/routes/admin.tsx");
  for (const route of ["/users/reset-mfa", "/users/set-status", "/invites/create"]) {
    expect(adminRoutesSrc.includes(`adminRoutes.post("${route}"`), `缺少 ${route} 的提交路由`);
  }

  // 会话最后活动时间必须真的更新
  const session = code("packages/gateway/src/middleware/session.ts");
  expect(session.includes("/session/touch"), "requireAuth 未更新 lastUsedAt，活动会话页会显示错误时间");
});

// ============================================================ 9. Cron 与容量
check("容量：Cron 分批清理，频率合规", () => {
  const toml = code("packages/core/wrangler.toml");
  expect(toml.includes('crons = ["*/15 * * * *"]'), "Cron 频率必须为 15 分钟");

  const cron = code("packages/core/src/cron.ts");
  expect(cron.includes("CRON_DELETE_BATCH"), "清理必须分批，不得扫全表");
});

// ============================================================ 10. 禁止项
check("禁止项：无 CMS、无缓存层、无多余框架", () => {
  const pkg = JSON.parse(read("packages/gateway/package.json"));
  const all = { ...pkg.dependencies, ...pkg.devDependencies };
  expect(!Object.keys(all).some((n) => n.includes("astro")), "不得引入 astro");

  const files = [];
  const walk = (dir) => {
    for (const entry of readdirSync(join(ROOT, dir), { withFileTypes: true })) {
      const path = `${dir}/${entry.name}`;
      if (entry.isDirectory()) walk(path);
      else if (/\.(ts|tsx|sql|toml)$/.test(entry.name)) files.push(path);
    }
  };
  walk("packages");

  for (const file of files) {
    const src = code(file);
    expect(!/r2_buckets|kv_namespaces|CREATE TABLE content\b/.test(src), `${file} 出现被禁资源`);
    expect(!/from ["']hono\/css["']/.test(src), `${file} 使用了 hono/css`);
  }
});

// ============================================================ 11. 构建一致性
check("构建：包管理器锁定、Worker 名匹配、产物不入库", () => {
  for (const rel of ["package.json", "packages/core/package.json", "packages/gateway/package.json"]) {
    const pkg = JSON.parse(read(rel));
    expect(String(pkg.packageManager ?? "").startsWith("pnpm@"), `${rel} 缺少 packageManager`);
  }

  expect(/^name = "sso-core"$/m.test(code("packages/core/wrangler.toml")), "Core 名必须为 sso-core");
  expect(/^name = "sso-gateway"$/m.test(code("packages/gateway/wrangler.toml")), "Gateway 名必须为 sso-gateway");
  expect(
    code("packages/gateway/wrangler.toml").includes('service = "sso-core"'),
    "Gateway 的 Service Binding 必须指向 sso-core",
  );

  const gi = read(".gitignore");
  for (const pattern of ["dist/", "packages/gateway/public/assets/", ".dev.vars"]) {
    expect(gi.includes(pattern), `.gitignore 缺少 ${pattern}`);
  }
  expect(gi.includes("!packages/core/migrations/*.sql"), "迁移文件被 *.sql 误伤");
});

// ============================================================ 12. 公开仓库卫生
check("公开仓库：不泄露敏感信息", () => {
  for (const file of ["0001_init.sql", "0002_mfa.sql"]) {
    expect(exists(`packages/core/migrations/${file}`), `缺少迁移 ${file}`);
  }

  const toml = read("packages/core/wrangler.toml");
  const dbId = toml.match(/database_id\s*=\s*"([^"]*)"/);
  expect(dbId, "缺少 database_id 配置项");
  expect(dbId[1] === "REPLACE_WITH_D1_DATABASE_ID", "database_id 已填入真实值，公开仓库不应包含");

  // 文档里不得出现真实域名
  const deploy = read("docs/deploy.md");
  const allowed = ["your-domain.com", "example.com", "localhost"];
  const urls = deploy.match(/https:\/\/[a-z0-9.-]+\.[a-z]{2,}/gi) ?? [];
  const offenders = urls.filter((url) => {
    const host = url.replace(/^https:\/\//i, "").toLowerCase();
    if (allowed.some((a) => host.includes(a))) return false;
    if (/cloudflare\.com|github\.com|rfc-editor\.org|developer\.mozilla\.org/.test(host)) return false;
    return true;
  });
  expect(offenders.length === 0, `文档含疑似真实域名: ${[...new Set(offenders)].join(", ")}`);
});

// ============================================================ 13. Workflow 正确性
check("Workflow：手动部署、离线自校验、参数正确", () => {
  const deploy = read(".github/workflows/deploy.yml");

  expect(deploy.includes("workflow_dispatch"), "deploy.yml 必须手动触发");
  expect(!/^  push:/m.test(deploy), "deploy.yml 不得由 push 触发");
  expect(deploy.includes("inputs.confirm"), "缺少 DEPLOY 确认输入");

  // d1 create 不支持 --json
  expect(!/d1 create[^\n]*--json/.test(deploy), "d1 create 不支持 --json");

  // sed 改 TOML 会丢引号
  expect(!/sed -i[^\n]*wrangler\.toml/.test(deploy), "不得用 sed 改 wrangler.toml");
  expect(deploy.includes("JSON.stringify(issuer)"), "ISSUER 注入应使用 JSON.stringify 保证引号");

  // 自校验必须离线，d1 list 需要凭证
  expect(!/wrangler d1 list[^\n]*\|\|\s*\{/.test(deploy), "d1 list 需要凭证，不能用作配置自校验");
  expect(deploy.includes("deploy --dry-run"), "缺少离线配置校验");

  // 两个 Worker 都要注入 secret
  expect((deploy.match(/secret bulk/g) ?? []).length >= 2, "两个 Worker 都应注入 secret");
});

// ============================================================ 14. 种子超管
check("种子超管：幂等、不强制改密", () => {
  const seed = read("scripts/seed-admin-ci.mjs");
  expect(seed.includes("role = 'super_admin'"), "种子脚本缺少已有超管检查");
  expect(seed.includes("created=false"), "种子脚本缺少跳过输出");
  expect(seed.includes("至少 12 位"), "种子脚本未校验密码长度");

  for (const file of ["scripts/seed-admin-ci.mjs", "scripts/seed-superadmin.mjs"]) {
    const src = read(file);
    const match = src.match(/must_change_password[\s\S]{0,200}?'active',\s*([01]),/);
    expect(match, `${file} 找不到 must_change_password 的值`);
    expect(match[1] === "0", `${file} 强制用户改密（密码是部署者自己设的）`);
  }

  expect(read(".github/workflows/deploy.yml").includes("seed-admin-ci.mjs"), "deploy.yml 未调用种子脚本");
});

// ============================================================ 15. 改密页成对
check("改密页：GET 与 POST 成对存在", () => {
  const account = code("packages/gateway/src/routes/account.tsx");
  expect(account.includes('accountRoutes.get("/password"'), "缺少改密页 GET");
  expect(account.includes('accountRoutes.post("/password"'), "缺少改密提交 POST");
  expect(account.includes("/user/change-password"), "POST 未调用 Core 的改密方法");
});

// ============================================================ 16. 前端路径一致性
checkFrontendPaths({ check, ROOT });

// ============================================================ 输出
for (const c of checks) {
  console.log(`${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.ok ? "" : `\n      ${c.detail}`}`);
}
const failed = checks.filter((c) => !c.ok);
console.log();
console.log(`${checks.length - failed.length}/${checks.length} 通过`);
if (failed.length) process.exit(1);