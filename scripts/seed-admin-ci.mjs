#!/usr/bin/env node
/**
 * 幂等地创建第一个超级管理员。
 *
 * CI 里运行：已存在任意 super_admin 时直接跳过，可安全重复执行。
 *
 * 环境变量：
 *   SESSION_PEPPER       必填，用于计算 password_hash
 *   SEED_ADMIN_EMAIL     必填
 *   SEED_ADMIN_PASSWORD  必填，至少 12 位
 */
import { createHmac, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

const pepper = process.env.SESSION_PEPPER;
const email = process.env.SEED_ADMIN_EMAIL;
const password = process.env.SEED_ADMIN_PASSWORD;

function fail(message) {
  console.error(`[seed] 失败：${message}`);
  process.exit(1);
}

if (!pepper) fail("缺少 SESSION_PEPPER");
if (!email) fail("缺少 SEED_ADMIN_EMAIL");
if (!password) fail("缺少 SEED_ADMIN_PASSWORD");
if (password.length < 12) fail(`SEED_ADMIN_PASSWORD 至少 12 位，当前 ${password.length} 位`);
if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) fail(`SEED_ADMIN_EMAIL 格式无效：${email}`);

const normalizedEmail = email.toLowerCase().trim();

// d1 命令必须定位到 packages/core/wrangler.toml，显式传 --cwd 不依赖调用方目录。
const CORE_DIR = fileURLToPath(new URL("../packages/core", import.meta.url));

// 直接调 wrangler 入口 JS，绕开 pnpm 在 Windows 上的 .cmd 解析问题。
// 注意：wrangler 的 package.json exports 不包含 ./bin/wrangler.js，
// 所以不能用 resolve('wrangler/bin/wrangler.js')，只能从包目录拼接。
const coreRequire = createRequire(join(CORE_DIR, "package.json"));
const wranglerPkgPath = coreRequire.resolve("wrangler/package.json");
const wranglerBin = join(dirname(wranglerPkgPath), "bin", "wrangler.js");

// SEED_TARGET=local 时操作本地 D1（仅用于开发自测），默认 remote。
const TARGET_FLAG = process.env.SEED_TARGET === "local" ? "--local" : "--remote";

function runWrangler(args) {
  return execFileSync(process.execPath, [wranglerBin, ...args, "--cwd", CORE_DIR], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: process.env,
  });
}

function queryCount(sql) {
  const raw = runWrangler([
    "d1", "execute", "sso-db", TARGET_FLAG, "--json", "-y",
    "--command", sql,
  ]);
  const parsed = JSON.parse(raw.trim());
  const first = Array.isArray(parsed) ? parsed[0] : parsed;
  return Number(first?.results?.[0]?.n ?? 0);
}

// ---- 1. 是否已有超管 ----
let existing = 0;
try {
  existing = queryCount("SELECT COUNT(*) AS n FROM users WHERE role = 'super_admin'");
} catch (error) {
  const stderr = (error.stderr ?? "").toString();
  const stdout = (error.stdout ?? "").toString();
  console.error("[seed] 查询现有超管失败：");
  console.error(stderr || stdout || error.message);
  process.exit(1);
}

if (existing > 0) {
  console.log(`[seed] 已有 ${existing} 个 super_admin，跳过创建`);
  console.log("created=false");
  process.exit(0);
}

// ---- 2. 邮箱是否被占用 ----
try {
  const escaped = normalizedEmail.replace(/'/g, "''");
  const taken = queryCount(`SELECT COUNT(*) AS n FROM users WHERE email = '${escaped}'`);
  if (taken > 0) {
    fail(`邮箱 ${normalizedEmail} 已被占用（但不是超管）。请换一个邮箱。`);
  }
} catch (error) {
  // 查询失败不阻断，插入时数据库还会再校验一次
}

// ---- 3. 插入 ----
const id = randomUUID();
const passwordHash = createHmac("sha256", pepper).update(password, "utf8").digest("hex");
const now = Math.floor(Date.now() / 1000);
const escapedEmail = normalizedEmail.replace(/'/g, "''");

const sql =
  "INSERT INTO users (id, email, password_hash, role, status, must_change_password, created_at) " +
  `VALUES ('${id}', '${escapedEmail}', '${passwordHash}', 'super_admin', 'active', 1, ${now})`;

try {
  runWrangler(["d1", "execute", "sso-db", TARGET_FLAG, "-y", "--command", sql]);
} catch (error) {
  const stderr = (error.stderr ?? "").toString();
  const stdout = (error.stdout ?? "").toString();
  console.error("[seed] 插入失败：");
  console.error(stderr || stdout || error.message);
  process.exit(1);
}

console.log(`[seed] 已创建超管：${normalizedEmail}`);
console.log("created=true");
console.log(`userId=${id}`);
console.log("首次登录会强制绑定 MFA。");