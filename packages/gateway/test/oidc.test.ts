import { describe, expect, it } from "vitest";
import { discoveryDocument, isValidScope, normalizeScope } from "../src/lib/oidc";

describe("discovery 文档", () => {
  const doc = discoveryDocument("https://sso.example.com");

  it("声明 issuer", () => {
    expect(doc.issuer).toBe("https://sso.example.com");
  });

  it("所有端点都基于同一个 issuer", () => {
    const issuer = "https://sso.example.com";
    for (const field of [
      "authorization_endpoint",
      "token_endpoint",
      "userinfo_endpoint",
      "jwks_uri",
      "end_session_endpoint",
      "introspection_endpoint",
      "revocation_endpoint",
    ]) {
      expect(doc[field], field).toMatch(new RegExp(`^${issuer}/`));
    }
  });

  it("声明 introspect 与 revoke（否则下游根本不知道有吊销）", () => {
    expect(doc.introspection_endpoint).toBe("https://sso.example.com/oauth/introspect");
    expect(doc.revocation_endpoint).toBe("https://sso.example.com/oauth/revoke");
  });

  it("只支持 S256，且声明 EdDSA", () => {
    expect(doc.code_challenge_methods_supported).toEqual(["S256"]);
    expect(doc.id_token_signing_alg_values_supported).toEqual(["EdDSA"]);
  });

  it("不声明 refresh_token（本方案不签发）", () => {
    expect(doc.grant_types_supported).toEqual(["authorization_code"]);
  });
});

describe("scope 校验", () => {
  it("必须包含 openid", () => {
    expect(isValidScope("profile email")).toBe(false);
    expect(isValidScope("openid")).toBe(true);
  });

  it("拒绝未支持的 scope", () => {
    expect(isValidScope("openid admin")).toBe(false);
    expect(isValidScope("openid profile email")).toBe(true);
  });

  it("空 scope 拒绝", () => {
    expect(isValidScope("")).toBe(false);
    expect(isValidScope("   ")).toBe(false);
  });

  it("normalizeScope 去重并保序", () => {
    expect(normalizeScope("openid profile openid email")).toBe("openid profile email");
  });
});
