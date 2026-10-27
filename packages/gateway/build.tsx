/** @jsxImportSource hono/jsx */
import { toSSG } from "hono/ssg";
import fs from "node:fs/promises";
import { Hono } from "hono";
import { LoginPage } from "./src/pages/login";
import { MfaPage } from "./src/pages/mfa";
import { NotFoundPage } from "./src/pages/notFound";

/**
 * 只预渲染不需要用户数据的三个页面。
 * 管理页永远由运行时 SSR —— 它们要读会话和列表数据。
 */
const staticApp = new Hono();

staticApp.get("/login", (c) => c.html(<LoginPage />));
staticApp.get("/mfa", (c) => c.html(<MfaPage />));
staticApp.get("/404", (c) => c.html(<NotFoundPage />));

const result = await toSSG(staticApp, fs, { dir: "./dist" });

if (!result.success) {
  console.error("SSG failed", result.error);
  process.exit(1);
}

// toSSG 只负责页面；静态资源（CSS/JS/_headers）必须由 public/ 拷进 dist/，
// 否则 wrangler 上传的 Assets 目录里没有它们。
await copyDir("./public", "./dist");

console.log("SSG output:", result.files.join(", "));

async function copyDir(from: string, to: string): Promise<void> {
  await fs.mkdir(to, { recursive: true });
  const entries = await fs.readdir(from, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = `${from}/${entry.name}`;
    const destPath = `${to}/${entry.name}`;
    if (entry.isDirectory()) {
      await copyDir(srcPath, destPath);
    } else {
      await fs.copyFile(srcPath, destPath);
    }
  }
}