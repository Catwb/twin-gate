#!/usr/bin/env node
/**
 * 强制使用 pnpm。
 *
 * 背景：混用包管理器会产生两套 node_modules 布局和两份锁文件，
 * 而本项目依赖 pnpm 的 workspace 协议（workspace:*），npm 无法解析。
 * 一旦有人用 npm install，依赖树会静默损坏。
 *
 * 这里直接阻断，而不是事后清理。
 */
const ua = process.env.npm_config_user_agent ?? "";

if (!ua.startsWith("pnpm/")) {
  const used = ua.split("/")[0] || "未知工具";
  console.error("");
  console.error("  本项目只允许使用 pnpm 安装依赖。");
  console.error(`  检测到的包管理器：${used}`);
  console.error("");
  console.error("  请改用：");
  console.error("    pnpm install");
  console.error("");
  process.exit(1);
}
