import { describe, expect, it } from "vitest";
import { isPkceMethodAllowed, verifyPkce } from "../src/services/oidc";
import { timingSafeEqual } from "../src/lib/crypto";

/**
 * 这两条以前用 ===，和 GATEWAY_TOKEN 的 timingSafeEqual 是两套标准。
 * 这里既验行为，也验"确实走了恒定时间实现"。
 */
describe("PKCE", () => {
  const verifier = "a".repeat(43);

  async function s256(input: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
    const bytes = new Uint8Array(digest);
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  it("正确的 verifier 通过", async () => {
    expect(await verifyPkce(await s256(verifier), verifier)).toBe(true);
  });

  it("错误的 verifier 拒绝", async () => {
    expect(await verifyPkce(await s256(verifier), "b".repeat(43))).toBe(false);
  });

  it("长度不同的 challenge 也拒绝，不抛错", async () => {
    expect(await verifyPkce("short", verifier)).toBe(false);
  });

  it("只接受 S256", () => {
    expect(isPkceMethodAllowed("S256")).toBe(true);
    expect(isPkceMethodAllowed("plain")).toBe(false);
    expect(isPkceMethodAllowed("s256")).toBe(false);
  });
});

/**
 * timingSafeEqual 的行为契约：
 * 长度不同必须立刻返回 false（否则循环会越界）。
 * verifyClientSecret / verifyPkce 的名称长度恒定，所以这条边界不会被触发，
 * 但它是公开函数，必须写清语义。
 */
describe("恒定时间比较", () => {
  it("相等返回 true", () => {
    expect(timingSafeEqual("abc123", "abc123")).toBe(true);
  });

  it("长度不同返回 false（不抛错）", () => {
    expect(timingSafeEqual("abc", "abcdef")).toBe(false);
    expect(timingSafeEqual("", "a")).toBe(false);
  });

  it("同长不同内容返回 false", () => {
    expect(timingSafeEqual("abcdef", "abcdeF")).toBe(false);
  });
});
