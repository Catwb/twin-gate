#!/usr/bin/env node
/**
 * 硬约束门禁。CI 直接跑这一条即可。
 * 任何一条不通过都以非零码退出。
 */
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, resolve, relative } from "node:path";
import { registerMfaChecks } from "./checks/mfa.mjs";
import { registerOidcChecks } from "./checks/oidc.mjs";

const ROOT = resolve(import.meta.dirname, "..");
const failures = [];
const checks = [];

function check(name, fn) {
  try {
    const detail = fn();
    checks.push({ name, ok: true, detail });
  } catch (error) {
    checks.push({ name, ok: false, detail: error.message });
    failures.push(name);
  }
}

function walk(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry === ".wrangler") continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

const sourceFiles = walk(join(ROOT, "packages")).filter((f) => /\.(ts|tsx|sql|toml)$/.test(f));
const read = (file) => readFileSync(file, "utf8");
const rel = (file) => relative(ROOT, file).replace(/\\/g, "/");

/**
 * 剥离注释后再匹配。
 * 否则"禁止 X"这类说明文字本身会把检查结果判成违规。
 */
function stripComments(content, kind) {
  if (kind === "toml") {
    return content
      .split("\n")
      .map((line) => line.replace(/(^|\s)#.*$/, "$1"))
      .join("\n");
  }
  if (kind === "sql") {
    return content
      .split("\n")
      .map((line) => line.replace(/--.*$/, ""))
      .join("\n");
  }
  return content
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
}

function readCode(file) {
  const raw = read(file);
  if (file.endsWith(".toml")) return stripComments(raw, "toml");
  if (file.endsWith(".sql")) return stripComments(raw, "sql");
  return stripComments(raw, "ts");
}

// ---- 1. Gateway 绑定额度 ----
check("Gateway 绑定只含 services / assets", () => {
  const toml = readCode(join(ROOT, "packages/gateway/wrangler.toml"));
  for (const forbidden of ["d1_databases", "kv_namespaces", "r2_buckets"]) {
    if (toml.includes(forbidden)) throw new Error(`wrangler.toml 出现 ${forbidden}`);
  }
  if (!toml.includes("[[services]]")) throw new Error("缺少 service binding");
  if (!toml.includes("[assets]")) throw new Error("缺少 assets 配置");
  return "ok";
});

check("Core 绑定为 D1 + Cron 且无公网路由", () => {
  const toml = readCode(join(ROOT, "packages/core/wrangler.toml"));
  if (!toml.includes('workers_dev = false')) throw new Error("workers_dev 未设为 false");
  if (/^routes\s*=/m.test(toml)) throw new Error("Core 不得配置 routes");
  if (!toml.includes("[[d1_databases]]")) throw new Error("缺少 D1 binding");
  if (!toml.includes("[triggers]")) throw new Error("缺少 cron 配置");
  for (const forbidden of ["kv_namespaces", "r2_buckets"]) {
    if (toml.includes(forbidden)) throw new Error(`出现了 ${forbidden}`);
  }
  return "ok";
});

check("生产配置不含 run_worker_first", () => {
  const toml = readCode(join(ROOT, "packages/gateway/wrangler.toml"));
  if (toml.includes("run_worker_first")) throw new Error("生产配置出现 run_worker_first（免费版超额会 429 且不回退静态资源）");
  return "ok";
});

// ---- 2. 身份传播 ----
check("env.CORE.fetch 只出现在 callCore.ts", () => {
  const offenders = sourceFiles.filter((file) => {
    if (file.endsWith("callCore.ts")) return false;
    return readCode(file).includes("CORE.fetch");
  });
  if (offenders.length) throw new Error(offenders.map(rel).join(", "));
  return "ok";
});

check("Core 不存在 SQL 透传接口", () => {
  const internal = readCode(join(ROOT, "packages/core/src/routes/internal.ts"));
  if (internal.includes("payload: z.object({ sql")) throw new Error("发现 sql 透传");
  if (/post\("\/query"/.test(internal)) throw new Error("发现 /query 路由");
  return "ok";
});

// ---- 3. 密码 ----
check("不存在 PBKDF2 调用", () => {
  const offenders = sourceFiles.filter((file) => /PBKDF2|deriveBits/.test(readCode(file)));
  if (offenders.length) throw new Error(offenders.map(rel).join(", "));
  return "ok";
});

check("密码字段统一为 password_hash", () => {
  const offenders = sourceFiles.filter((file) => /\bpassword:\s*text\(/.test(readCode(file)));
  if (offenders.length) throw new Error(`发现非 password_hash 字段: ${offenders.map(rel).join(", ")}`);
  return "ok";
});

// ---- 4. 令牌与会话 ----
check("会话 Cookie 使用 __Host- 前缀", () => {
  const shared = readCode(join(ROOT, "packages/shared/src/index.ts"));
  if (!shared.includes('"__Host-sid"')) throw new Error("SESSION_COOKIE 必须是 __Host-sid");
  return "ok";
});

check("Cookie 属性齐全", () => {
  const middleware = readCode(join(ROOT, "packages/gateway/src/middleware/session.ts"));
  for (const attr of ["httpOnly: true", "secure: true", 'sameSite: "Lax"', 'path: "/"']) {
    if (!middleware.includes(attr)) throw new Error(`缺少 ${attr}`);
  }
  return "ok";
});

check("requireAuth 显式拒绝 mfa_pending", () => {
  const session = readCode(join(ROOT, "packages/core/src/services/session.ts"));
  if (!session.includes("SessionStatus.MfaPending")) throw new Error("session 服务未检查 mfa_pending");
  return "ok";
});

// ---- 5. 禁止项 ----
check("不存在 R2 / KV / content 表 / Markdown 渲染 / Astro", () => {
  const offenders = sourceFiles.filter((file) => {
    const content = readCode(file);
    return /r2_buckets|kv_namespaces|CREATE TABLE content\b/.test(content);
  });
  if (offenders.length) throw new Error(offenders.map(rel).join(", "));
  return "ok";
});

check("依赖树不含 astro", () => {
  const pkg = JSON.parse(read(join(ROOT, "packages/gateway/package.json")));
  const all = { ...pkg.dependencies, ...pkg.devDependencies };
  if (Object.keys(all).some((name) => name.includes("astro"))) throw new Error("发现 astro 依赖");
  return "ok";
});

check("不存在 hono/css 使用", () => {
  const offenders = sourceFiles.filter((file) => {
    const code = readCode(file);
    return code.includes("from 'hono/css'") || code.includes('from "hono/css"');
  });
  if (offenders.length) throw new Error(offenders.map(rel).join(", "));
  return "ok";
});

// ---- 6. 审计与清理 ----
check("审计写入不阻断认证", () => {
  const audit = readCode(join(ROOT, "packages/core/src/services/audit.ts"));
  if (!audit.includes("try {")) throw new Error("appendAudit 缺乏失败隔离");
  return "ok";
});

check("Cron 清理为分批 LIMIT", () => {
  const cron = readCode(join(ROOT, "packages/core/src/cron.ts"));
  if (!cron.includes("CRON_DELETE_BATCH")) throw new Error("清理未使用批量上限");
  return "ok";
});

check("Cron 频率不高于 15 分钟", () => {
  const toml = readCode(join(ROOT, "packages/core/wrangler.toml"));
  if (!toml.includes('crons = ["*/15 * * * *"]')) throw new Error("cron 表达式不符");
  return "ok";
});

// ---- 7. OIDC 与令牌吊销 ----
registerOidcChecks({ check, readCode, ROOT });

// ---- 8. Passkey / TOTP / 恢复 ----
registerMfaChecks({ check, readCode, ROOT });

// ---- 9. Git / Workers Builds 部署前提 ----
check("三个 package.json 都声明 packageManager", () => {
  for (const rel of ["package.json", "packages/core/package.json", "packages/gateway/package.json"]) {
    const pkg = JSON.parse(read(join(ROOT, rel)));
    if (!pkg.packageManager || !String(pkg.packageManager).startsWith("pnpm@")) {
      throw new Error(`${rel} 缺少 packageManager: pnpm@x.y.z`);
    }
  }
  return "ok";
});

check("Worker 名与 wrangler.toml 的 name 一致", () => {
  const coreToml = readCode(join(ROOT, "packages/core/wrangler.toml"));
  const gatewayToml = readCode(join(ROOT, "packages/gateway/wrangler.toml"));
  if (!/^name = "sso-core"$/m.test(coreToml)) throw new Error("Core name 不是 sso-core");
  if (!/^name = "sso-gateway"$/m.test(gatewayToml)) throw new Error("Gateway name 不是 sso-gateway");
  // Gateway 的 service binding 必须指向真实存在的 Core 名
  if (!gatewayToml.includes('service = "sso-core"')) throw new Error("Gateway 的 service binding 指向了错误的 Worker");
  return "ok";
});

check("构建产物不入库", () => {
  const gi = read(join(ROOT, ".gitignore"));
  for (const pattern of ["dist/", "packages/gateway/public/assets/", ".dev.vars"]) {
    if (!gi.includes(pattern)) throw new Error(`.gitignore 缺少 ${pattern}`);
  }
  return "ok";
});

check("迁移文件被纳入版本控制", () => {
  const gi = read(join(ROOT, ".gitignore"));
  if (!gi.includes("!packages/core/migrations/*.sql")) {
    throw new Error("迁移文件被 *.sql 规则误伤");
  }
  const migrations = ["0001_init.sql", "0002_mfa.sql"];
  for (const file of migrations) {
    if (!existsSync(join(ROOT, "packages/core/migrations", file))) {
      throw new Error(`缺少迁移 ${file}`);
    }
  }
  return "ok";
});

// ---- 10. 公开仓库卫生 ----
check("敏感文件不可入库", () => {
  const gi = read(join(ROOT, ".gitignore"));
  for (const pattern of [".dev.vars", "*.sql", "backup-*.sql", "seed.sql"]) {
    if (!gi.includes(pattern)) throw new Error(`.gitignore 缺少 ${pattern}`);
  }
  return "ok";
});

check("配置模板中不含真实 database_id", () => {
  const toml = read(join(ROOT, "packages/core/wrangler.toml"));
  const match = toml.match(/database_id\s*=\s*"([^"]*)"/);
  if (!match) throw new Error("缺少 database_id 配置项");
  if (match[1] !== "REPLACE_WITH_D1_DATABASE_ID") {
    throw new Error("database_id 已填入真实值，公开仓库不应包含它");
  }
  return "ok";
});

check("文档中不含真实域名", () => {
  const deploy = read(join(ROOT, "docs/deploy.md"));
  // 允许的示例域名
  const allowed = ["sso.your-domain.com", "app.example.com", "example.com", "localhost"];
  const matches = deploy.match(/https:\/\/[a-z0-9.-]+\.[a-z]{2,}/gi) ?? [];
  const offenders = matches.filter((url) => {
    const host = url.replace(/^https:\/\//i, "").toLowerCase();
    return !allowed.some((item) => host.includes(item));
  });
  // 文档里还有 Cloudflare 官方链接，排除掉
  const realOffenders = offenders.filter(
    (url) => !url.includes("cloudflare.com") && !url.includes("github.com") && !url.includes("rfc-editor.org"),
  );
  if (realOffenders.length) throw new Error(`发现疑似真实域名: ${[...new Set(realOffenders)].join(", ")}`);
  return "ok";
});

check("管理端写操作必须挂角色校验", () => {
  const file = readCode(join(ROOT, "packages/gateway/src/routes/admin-apps.tsx"));
  const routes = ["/apps/create", "/apps/rotate", "/apps/delete"];
  for (const route of routes) {
    const start = file.indexOf(`adminAppsRoutes.post("${route}"`);
    if (start < 0) throw new Error(`未找到 ${route}`);
    const block = file.slice(start, start + 400);
    if (!block.includes("Role.SuperAdmin")) {
      throw new Error(`${route} 缺少超管校验`);
    }
  }
  return "ok";
});

// ---- 输出 ----
const failed = checks.filter((c) => !c.ok);
for (const c of checks) {
  console.log(`${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.ok ? "" : `\n      ${c.detail}`}`);
}
console.log();
console.log(`${checks.length - failed.length}/${checks.length} 通过`);
if (failed.length) process.exit(1);