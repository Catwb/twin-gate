#!/usr/bin/env node
/**
 * 校验 GitHub Actions workflow。
 *
 * 两类错误必须拦住：
 *   1. 表达式未闭合 —— ${{ ... } 少一个右括号（YAML 合法，只有 GitHub 拒绝）
 *   2. if: 里误用 ${{ }} —— 会导致二次求值
 *
 * 优先调用 actionlint（官方级校验器），没有安装时回退到内置检查。
 */
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";

const ROOT = resolve(import.meta.dirname, "..");
const DIR = join(ROOT, ".github/workflows");
const files = readdirSync(DIR).filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"));

let failed = 0;
const OPEN = "$" + "{{";
const CLOSE = "}" + "}";

// ---- 内置检查 ----
for (const file of files) {
  const full = join(DIR, file);
  const lines = readFileSync(full, "utf8").split("\n");

  lines.forEach((line, index) => {
    const trimmed = line.trimStart();
    if (trimmed.startsWith("#")) return;

    // 未闭合的表达式
    let pos = 0;
    while (true) {
      const open = line.indexOf(OPEN, pos);
      if (open < 0) break;
      const close = line.indexOf(CLOSE, open + 3);
      if (close < 0) {
        console.error(`FAIL  ${file}:${index + 1}  未闭合的表达式`);
        console.error(`      ${line.trim()}`);
        failed++;
        break;
      }
      pos = close + 2;
    }

    // 常见笔误：少写一个右花括号
    if (/\$\{\{[^}]*\}(?!\})/.test(line)) {
      console.error(`FAIL  ${file}:${index + 1}  表达式缺少右花括号`);
      console.error(`      ${line.trim()}`);
      failed++;
    }

    // if: 里不应出现 ${{ }}
    if (/^\s*if:\s/.test(line) && line.includes(OPEN)) {
      console.error(`FAIL  ${file}:${index + 1}  if: 条件不应包裹表达式`);
      console.error(`      ${line.trim()}`);
      failed++;
    }
  });

  if (!/^on:/m.test(lines.join("\n"))) {
    console.error(`FAIL  ${file}  缺少 on: 触发器`);
    failed++;
  }
}

// ---- actionlint（若可用）----
// 关键：必须真正能执行才算「可用」。
// 之前把字符串 "actionlint" 当作无条件候选，导致 CI 上 path 查找失败（ENOENT）
// 被误判成「校验不通过」。这里先用 --version 探测。
const candidates = [
  process.env.ACTIONLINT_PATH,
  join(process.env.TEMP ?? "", "actionlint", "actionlint.exe"),
  join(process.env.TEMP ?? "", "actionlint", "actionlint"),
  "/usr/local/bin/actionlint",
  "/usr/bin/actionlint",
  "actionlint",
].filter(Boolean);

function probe(candidate) {
  try {
    execFileSync(candidate, ["--version"], { stdio: "pipe" });
    return candidate;
  } catch {
    return null;
  }
}

const actionlint = candidates.map(probe).find(Boolean) ?? null;

if (actionlint) {
  console.log(`使用 actionlint: ${actionlint}`);
  for (const file of files) {
    try {
      execFileSync(actionlint, [join(DIR, file)], { stdio: "pipe" });
      console.log(`actionlint  ${file}  通过`);
    } catch (error) {
      const out = error.stdout?.toString() ?? "";
      const err = error.stderr?.toString() ?? "";
      console.error(`FAIL  actionlint ${file}`);
      if (out) console.error(out.trim());
      if (err) console.error(err.trim());
      failed++;
    }
  }
} else {
  console.warn("提示: 未找到 actionlint，仅执行内置检查");
  console.warn("      CI 中可通过以下步骤安装：");
  console.warn("        uses: raven-actions/actionlint@v2");
}

if (failed > 0) {
  console.error(`\n${failed} 处问题`);
  process.exit(1);
}
console.log("workflow 检查全部通过");