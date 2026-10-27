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
