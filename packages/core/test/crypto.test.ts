import { describe, expect, it } from "vitest";
import { hashPassword, randomHex, sha256Hex, timingSafeEqual, toHex } from "../src/lib/crypto";

describe("hashPassword", () => {
  const pepper = "test-pepper-value";

  it("同样的输入产生同样的哈希", async () => {
    const a = await hashPassword(pepper, "correct horse battery staple");
    const b = await hashPassword(pepper, "correct horse battery staple");
    expect(a).toBe(b);
  });

  it("不同 pepper 产生不同哈希", async () => {
    const a = await hashPassword(pepper, "same-password");
    const b = await hashPassword("other-pepper", "same-password");
    expect(a).not.toBe(b);
  });

  it("哈希是 64 位十六进制（HMAC-SHA256）", async () => {
    const hash = await hashPassword(pepper, "x");
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("明文不出现在哈希里", async () => {
    const plaintext = "my-secret-password";
    const hash = await hashPassword(pepper, plaintext);
    expect(hash).not.toContain(plaintext);
  });
});

describe("sha256Hex", () => {
  it("对固定输入产生已知哈希", async () => {
    // echo -n "abc" | sha256sum
    expect(await sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("timingSafeEqual", () => {
  it("相同字符串返回 true", () => {
    expect(timingSafeEqual("abcdef", "abcdef")).toBe(true);
  });

  it("长度不同返回 false", () => {
    expect(timingSafeEqual("abc", "abcd")).toBe(false);
  });

  it("内容不同返回 false", () => {
    expect(timingSafeEqual("abcdef", "abcdeF")).toBe(false);
  });
});

describe("randomHex", () => {
  it("生成长度正确且不重复", () => {
    const a = randomHex(32);
    const b = randomHex(32);
    expect(a).toHaveLength(64);
    expect(a).not.toBe(b);
  });
});
