import { describe, expect, it } from "vitest";
import { checkPasswordPolicy, MIN_PASSWORD_LENGTH, verifyPassword } from "../src/services/password";
import { hashPassword } from "../src/lib/crypto";

describe("checkPasswordPolicy", () => {
  it("少于 12 位拒绝", () => {
    const result = checkPasswordPolicy("short");
    expect(result.ok).toBe(false);
  });

  it("恰好 12 位通过", () => {
    expect(checkPasswordPolicy("a".repeat(MIN_PASSWORD_LENGTH)).ok).toBe(true);
  });

  it("超过 256 位拒绝", () => {
    expect(checkPasswordPolicy("a".repeat(257)).ok).toBe(false);
  });
});

describe("verifyPassword", () => {
  const pepper = "pepper";

  it("正确密码通过", async () => {
    const hash = await hashPassword(pepper, "correct-password");
    expect(await verifyPassword(pepper, "correct-password", hash)).toBe(true);
  });

  it("错误密码失败", async () => {
    const hash = await hashPassword(pepper, "correct-password");
    expect(await verifyPassword(pepper, "wrong-password", hash)).toBe(false);
  });

  it("换了 pepper 就失败", async () => {
    const hash = await hashPassword(pepper, "correct-password");
    expect(await verifyPassword("other-pepper", "correct-password", hash)).toBe(false);
  });
});
