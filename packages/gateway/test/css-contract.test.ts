import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = resolve(__dirname, "../src");

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

const files = walk(SRC);
const templateFiles = files.filter((f) => f.endsWith(".tsx"));
const tsFiles = files.filter((f) => f.endsWith(".ts"));

describe("CSS 单一来源约束", () => {
  it("模板文件不得导入 CSS", () => {
    for (const file of templateFiles) {
      const content = readFileSync(file, "utf8");
      expect(content, `${file} 不应导入 CSS`).not.toMatch(/import\s+["'][^"']+\.css["']/);
    }
  });

  it("全项目不得使用 hono/css", () => {
    for (const file of [...templateFiles, ...tsFiles]) {
      const content = readFileSync(file, "utf8");
      expect(content, `${file} 不应使用 hono/css`).not.toContain("hono/css");
    }
  });

  it("模板里只有 Layout 引用外部样式表", () => {
    const offenders = templateFiles.filter((file) => {
      if (file.endsWith("Layout.tsx")) return false;
      return readFileSync(file, "utf8").includes("stylesheet");
    });
    expect(offenders).toEqual([]);
  });

  it("样式入口只做 @import 汇总", () => {
    const index = readFileSync(join(SRC, "styles/index.css"), "utf8");
    const nonImport = index
      .split("\n")
      .filter((line) => line.trim() && !line.trim().startsWith("/*") && !line.trim().startsWith("@import"));
    expect(nonImport).toEqual([]);
  });
});
