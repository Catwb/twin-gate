#!/usr/bin/env node
/**
 * 创建 OIDC 客户端。
 *
 * 直接调 Core 的具名方法需要 X-Gateway-Token，所以这个脚本要么走 Gateway
 * 那层（需要超管已登录），要么本地直连 Core 的 dev 实例。
 *
 * 生产环境推荐做法：超管登录后台，用 /admin/apps 页面查看；
 * 创建则用本脚本 —— 它生成 SQL，由 wrangler d1 execute 写入。
 *
 * 用法：
 *   node scripts/create-client.mjs \
 *     --name "My App" \
 *     --redirect https://app.example.com/callback \
 *     --post-logout https://app.example.com/ \
 *     --out client.sql
 *
 * 生成后用：pnpm --filter @sso/core exec wrangler d1 execute sso-db --remote --file=client.sql
 */
import { createHash, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";

const args = process.argv.slice(2);
function arg(name, fallback = null) {
  const index = args.indexOf(`--${name}`);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
}
function argAll(name) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === `--${name}` && args[i + 1]) out.push(args[i + 1]);
  }
  return out;
}

const name = arg("name");
const redirects = argAll("redirect");
const postLogout = argAll("post-logout");
const outFile = arg("out", "client.sql");

if (!name || redirects.length === 0) {
  console.error("用法: node scripts/create-client.mjs --name <名称> --redirect <回调地址> [--redirect ...] [--post-logout ...]");
  process.exit(1);
}

for (const uri of redirects) {
  try {
    new URL(uri);
  } catch {
    console.error(`无效的回调地址: ${uri}`);
    process.exit(1);
  }
}

const clientId = `app-${randomBytes(8).toString("hex")}`;
const clientSecret = randomBytes(32).toString("hex");
// D1 只存 SHA-256，明文 secret 只出现在本次输出里。
const clientSecretHash = createHash("sha256").update(clientSecret).digest("hex");
const now = Math.floor(Date.now() / 1000);

const escape = (value) => value.replace(/'/g, "''");
const sql =
  `-- 由 scripts/create-client.mjs 生成\n` +
  `INSERT INTO apps (client_id, client_secret_hash, name, redirect_uris, post_logout_redirect_uris, created_at)\n` +
  `VALUES ('${clientId}', '${clientSecretHash}', '${escape(name)}',
` +
  `        '${escape(JSON.stringify(redirects))}', '${escape(JSON.stringify(postLogout))}', ${now});\n`;

writeFileSync(outFile, sql, "utf8");

console.log("客户端已生成：");
console.log();
console.log(`  client_id     = ${clientId}`);
console.log(`  client_secret = ${clientSecret}`);
console.log(`  redirect_uris = ${redirects.join(", ")}`);
if (postLogout.length) console.log(`  post_logout   = ${postLogout.join(", ")}`);
console.log();
console.log(`SQL 已写入 ${outFile}`);
console.log();
console.log("下一步：");
console.log(`  pnpm --filter @sso/core exec wrangler d1 execute sso-db --remote --file=./${outFile}`);
console.log();
console.log("⚠️ client_secret 只显示这一次，请立刻保存。");
