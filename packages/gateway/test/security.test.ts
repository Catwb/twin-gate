import { describe, expect, it } from "vitest";
import { CONTENT_SECURITY_POLICY, securityHeaders } from "../src/lib/security";

describe("安全响应头", () => {
  const headers = securityHeaders();

  it("CSP 禁止内联脚本（强制脚本走外部文件）", () => {
    expect(headers["Content-Security-Policy"]).toContain("script-src 'self'");
    expect(headers["Content-Security-Policy"]).not.toContain("'unsafe-inline'");
    expect(headers["Content-Security-Policy"]).not.toContain("'unsafe-eval'");
  });

  it("禁止被嵌套（防点击劫持）", () => {
    expect(headers["Content-Security-Policy"]).toContain("frame-ancestors 'none'");
    expect(headers["X-Frame-Options"]).toBe("DENY");
  });

  it("禁止 MIME 嗅探", () => {
    expect(headers["X-Content-Type-Options"]).toBe("nosniff");
  });

  it("Permissions-Policy 不含已废弃的 interest-cohort", () => {
    // FLoC 已被 Topics API 取代，Chrome 不再识别该指令，
    // 保留它只会在每个页面控制台刷警告。
    expect(headers["Permissions-Policy"]).not.toContain("interest-cohort");
  });

  it("Permissions-Policy 仍禁用敏感能力", () => {
    const policy = headers["Permissions-Policy"];
    for (const feature of ["camera", "microphone", "geolocation"]) {
      expect(policy).toContain(`${feature}=()`);
    }
  });

  it("静态页与 SSR 页引用同一个 CSP 常量", () => {
    // _headers 无法在本测试里读，但这里断言 CSP 是模块级常量而非函数拼接，
    // 保证两处引用的是同一个值。
    expect(headers["Content-Security-Policy"]).toBe(CONTENT_SECURITY_POLICY);
  });
});
describe("CSRF 中间件", () => {
  it("豁免范围仅限 /oauth/，且必须显式声明", async () => {
    const { readFileSync } = await import("node:fs");
    const { resolve } = await import("node:path");
    const source = readFileSync(resolve(__dirname, "../src/middleware/csrf.ts"), "utf8");
    const match = source.match(/EXEMPT_PREFIXES = \[([^\]]*)\]/);
    expect(match).toBeTruthy();
    const entries = match![1].split(",").map((x) => x.trim()).filter(Boolean);
    expect(entries).toEqual(['"/oauth/"']);
  });

  it("自定义头与同源表单是仅有的两种通过方式", async () => {
    const { readFileSync } = await import("node:fs");
    const { resolve } = await import("node:path");
    const source = readFileSync(resolve(__dirname, "../src/middleware/csrf.ts"), "utf8");
    expect(source).toContain("CSRF_HEADER");
    expect(source).toContain("isSameOriginFormSubmission");
    // 不允许出现"没有校验直接放行"的分支
    expect(source).not.toMatch(/return next\(\);\s*\}\s*;?\s*\}/);
  });

  it("同源判定要求 Origin 或 Referer 存在", async () => {
    const { readFileSync } = await import("node:fs");
    const { resolve } = await import("node:path");
    const source = readFileSync(resolve(__dirname, "../src/middleware/csrf.ts"), "utf8");
    // 两者都缺失时必须返回 false（拒绝）
    expect(source).toMatch(/if \(!origin && !referer\) return false;/);
  });
});
describe("静态页与 SSR 页的安全头一致", () => {
  it("_headers 中的 CSP 与 CONTENT_SECURITY_POLICY 完全相同", async () => {
    const { readFileSync } = await import("node:fs");
    const { resolve } = await import("node:path");
    const raw = readFileSync(resolve(__dirname, "../public/_headers"), "utf8");

    const match = raw.match(/^\s*Content-Security-Policy:\s*(.+)$/m);
    expect(match, "_headers 中缺少 Content-Security-Policy").toBeTruthy();
    expect(match![1].trim()).toBe(CONTENT_SECURITY_POLICY);
  });

  it("_headers 也禁用了 interest-cohort", async () => {
    const { readFileSync } = await import("node:fs");
    const { resolve } = await import("node:path");
    const raw = readFileSync(resolve(__dirname, "../public/_headers"), "utf8");
    const policy = raw.match(/^\s*Permissions-Policy:\s*(.+)$/m)?.[1] ?? "";
    expect(policy).not.toContain("interest-cohort");
  });

  it("_headers 覆盖了静态页与静态资源", async () => {
    const { readFileSync } = await import("node:fs");
    const { resolve } = await import("node:path");
    const raw = readFileSync(resolve(__dirname, "../public/_headers"), "utf8");
    expect(raw).toContain("/*");
    expect(raw).toContain("/assets/app.css");
  });

  it("_headers 覆盖 build:js 产出的每一个脚本", async () => {
    // 上一次漏的是 password.js —— 构建脚本加了产物，_headers 和 CI 断言都没跟上。
    // 这里直接从 package.json 的构建命令里解析产物名，加了新脚本就自动覆盖。
    const { readFileSync } = await import("node:fs");
    const { resolve } = await import("node:path");

    const pkg = JSON.parse(readFileSync(resolve(__dirname, "../package.json"), "utf8")) as {
      scripts: Record<string, string>;
    };
    const buildJs = pkg.scripts["build:js"] ?? "";
    const outputs = [...buildJs.matchAll(/--outfile=\S*?\/?assets\/([\w.-]+\.js)/g)].map((m) => m[1]);
    expect(outputs.length).toBeGreaterThanOrEqual(4);

    const raw = readFileSync(resolve(__dirname, "../public/_headers"), "utf8");
    for (const name of outputs) {
      expect(raw, `_headers 缺少 /assets/${name} 的缓存策略`).toContain(`/assets/${name}`);
    }
  });

  it("CSS 产物同样被 _headers 覆盖", async () => {
    const { readFileSync } = await import("node:fs");
    const { resolve } = await import("node:path");
    const pkg = JSON.parse(readFileSync(resolve(__dirname, "../package.json"), "utf8")) as {
      scripts: Record<string, string>;
    };
    const outputs = [...(pkg.scripts["build:css"] ?? "").matchAll(/--outfile=\S*?\/?assets\/([\w.-]+\.css)/g)].map((m) => m[1]);
    expect(outputs.length).toBeGreaterThan(0);

    const raw = readFileSync(resolve(__dirname, "../public/_headers"), "utf8");
    for (const name of outputs) {
      expect(raw).toContain(`/assets/${name}`);
    }
  });
});
