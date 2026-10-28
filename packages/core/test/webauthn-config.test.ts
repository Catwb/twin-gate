import { describe, expect, it } from "vitest";
import { deriveRpId, diagnoseWebAuthnConfig, normalizeOrigin } from "../src/lib/webauthn-config";

describe("normalizeOrigin", () => {
  it("去掉结尾斜杠", () => {
    expect(normalizeOrigin("https://sso.example.com/")).toBe("https://sso.example.com");
  });

  it("去掉路径", () => {
    expect(normalizeOrigin("https://sso.example.com/admin/security")).toBe("https://sso.example.com");
  });

  it("保留端口", () => {
    expect(normalizeOrigin("http://localhost:8787/")).toBe("http://localhost:8787");
  });

  it("空值返回空串", () => {
    expect(normalizeOrigin("")).toBe("");
    expect(normalizeOrigin("   ")).toBe("");
  });

  it("非法值只去尾斜杠，不抛错", () => {
    expect(normalizeOrigin("not-a-url/")).toBe("not-a-url");
  });
});

describe("deriveRpId", () => {
  it("从 origin 取 hostname", () => {
    expect(deriveRpId("https://sso.example.com")).toBe("sso.example.com");
  });

  it("剔除端口", () => {
    expect(deriveRpId("http://localhost:8787")).toBe("localhost");
  });

  it("保留子域", () => {
    expect(deriveRpId("https://sso.auth.example.com")).toBe("sso.auth.example.com");
  });
});

describe("diagnoseWebAuthnConfig", () => {
  it("正常配置通过", () => {
    const r = diagnoseWebAuthnConfig("https://sso.example.com", "sso.example.com");
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.origin).toBe("https://sso.example.com");
      expect(r.rpId).toBe("sso.example.com");
    }
  });

  it("未配 rpId 时从 origin 推导", () => {
    const r = diagnoseWebAuthnConfig("https://sso.example.com");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.rpId).toBe("sso.example.com");
  });

  it("rpId 是父域时允许", () => {
    const r = diagnoseWebAuthnConfig("https://sso.example.com", "example.com");
    expect(r.ok).toBe(true);
  });

  it("rpId 与域名无关时报错", () => {
    const r = diagnoseWebAuthnConfig("https://sso.example.com", "other-domain.com");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("不是 ISSUER 域名");
  });

  it("ISSUER 为空时报错", () => {
    const r = diagnoseWebAuthnConfig("");
    expect(r.ok).toBe(false);
  });

  it("ISSUER 带结尾斜杠不影响 rpId 推导", () => {
    const r = diagnoseWebAuthnConfig("https://sso.example.com/", "sso.example.com");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.rpId).toBe("sso.example.com");
  });
});
