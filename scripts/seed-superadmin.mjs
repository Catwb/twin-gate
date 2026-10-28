#!/usr/bin/env node
/**
 * 生成第一条 super_admin 的 SQL。
 *
 * 用法：
 *   SESSION_PEPPER='<pepper>' node scripts/seed-superadmin.mjs \
 *     --email you@example.com --password '<临时密码>' > seed.sql
 *
 * 生成后用 wrangler d1 execute 执行，然后立刻删除 seed.sql。
 * 这是"所有 D1 操作必须经过 Core"的唯一运维例外，必须记录在 runbook。
 */
import { createHmac, randomUUID } from "node:crypto";

const args = process.argv.slice(2);
function arg(name, fallback = null) {
  const index = args.indexOf(`--${name}`);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
}

const pepper = process.env.SESSION_PEPPER;
const email = arg("email");
const password = arg("password");
const role = arg("role", "super_admin");

if (!pepper) {
  console.error("缺少环境变量 SESSION_PEPPER");
  process.exit(1);
}
if (!email || !password) {
  console.error("用法: SESSION_PEPPER=... node scripts/seed-superadmin.mjs --email <邮箱> --password <临时密码>");
  process.exit(1);
}
if (password.length < 12) {
  console.error("密码长度至少 12 位");
  process.exit(1);
}

const id = randomUUID();
const passwordHash = createHmac("sha256", pepper).update(password, "utf8").digest("hex");
const now = Math.floor(Date.now() / 1000);
const escapedEmail = email.toLowerCase().replace(/'/g, "''");

console.log("-- 由 scripts/seed-superadmin.mjs 生成，执行后请立即删除本文件");
console.log(
  `INSERT INTO users (id, email, password_hash, role, status, must_change_password, created_at) VALUES ('${id}', '${escapedEmail}', '${passwordHash}', '${role}', 'active', 0, ${now});`,
);