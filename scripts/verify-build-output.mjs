#!/usr/bin/env node
/**
 * 构建产物完整性检查。
 *
 * 起因：这份清单在 verify.yml 和 deploy-quick.yml 里各手写了一遍，
 * 加 password.js 时两处都漏，CI 一直是绿的。
 *
 * 所以这里不再写清单，而是从「产出它的地方」推导：
 *   - JS / CSS   → package.json 的 build:js / build:css 里的 --outfile=
 *   - SSR 页面   → build.tsx 里 staticApp.get("/xxx") 的路由
 *   - _headers   → public/_headers（唯一一个不是构建产物、但要进 dist 的文件）
 *
 * 用法：在 packages/gateway 目录下执行，或 node scripts/verify-build-output.mjs。
 */
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const GATEWAY = join(ROOT, "packages/gateway");
const DIST = join(GATEWAY, "dist");

const read = (rel) => readFileSync(join(GATEWAY, rel), "utf8");

/** 从 package.json 的构建命令里解析 --outfile=<相对 public 的路径>。 */
function buildOutputs(scriptKey) {
  const pkg = JSON.parse(read("package.json"));
  const cmd = String(pkg.scripts?.[scriptKey] ?? "");
  const out = [];
  for (const m of cmd.matchAll(/--outfile=[^\s]*?\/?assets\/([\w.-]+)/g)) {
    // 统一用正斜杠：dist 里的相对路径，Windows 与 Linux 都要能比
    out.push(`assets/${m[1]}`);
  }
  return out;
}

/** build.tsx 里预渲染的页面路由 → dist/<route>.html */
function staticPages() {
  const src = readFileSync(join(GATEWAY, "build.tsx"), "utf8");
  const routes = [...src.matchAll(/staticApp\.get\("([^"]+)"[\s\S]*?c\.html\(/g)].map((m) => m[1]);
  return routes.map((route) => `${route.replace(/^\//, "")}.html`);
}

const expected = [
  ...staticPages(),
  ...buildOutputs("build:js"),
  ...buildOutputs("build:css"),
];

// _headers 不是构建产物，但它必须被拷进 dist，否则静态页缺安全头
if (existsSync(join(GATEWAY, "public/_headers"))) expected.push("_headers");

if (expected.length === 0) {
  console.error("[build-check] 未能推导出任何产物，检查 package.json 与 build.tsx");
  process.exit(1);
}

if (!existsSync(DIST)) {
  console.error("[build-check] dist/ 不存在，先跑 pnpm --filter @sso/gateway build");
  process.exit(1);
}

const missing = expected.filter((rel) => !existsSync(join(DIST, rel)));
if (missing.length > 0) {
  for (const rel of missing) console.error(`::error::构建产物缺失: dist/${rel}`);
  process.exit(1);
}

// 反向：dist/assets 里不该有构建脚本没声明的陈旧文件 ——
// 那是上一次构建的残留，会被一起上传，却没人知道它是谁产出的。
const declared = new Set(
  buildOutputs("build:js")
    .concat(buildOutputs("build:css"))
    .map((p) => p.replace("assets/", "")),
);
const assetsDir = join(DIST, "assets");
if (existsSync(assetsDir)) {
  const stale = readdirSync(assetsDir).filter((f) => !declared.has(f));
  if (stale.length > 0) {
    for (const f of stale) console.error(`::error::dist/assets 里有构建脚本未声明的残留: ${f}`);
    process.exit(1);
  }
}

console.log(`构建产物完整（${expected.length} 项）:`);
for (const rel of expected) console.log(`  dist/${rel}`);
