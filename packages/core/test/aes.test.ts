import { describe, expect, it } from "vitest";
import { decryptSecret, encryptSecret } from "../src/lib/aes";

const KEY_A = "master-key-alpha-aaaaaaaaaaaaaaaaaaaa";
const KEY_B = "master-key-beta-bbbbbbbbbbbbbbbbbbbbbb";

describe("AES-GCM 加密", () => {
  it("加密后可解密回原文", async () => {
    const payload = await encryptSecret(KEY_A, "JBSWY3DPEHPK3PXP");
    expect(await decryptSecret(KEY_A, payload)).toBe("JBSWY3DPEHPK3PXP");
  });

  it("密文不等于明文", async () => {
    const payload = await encryptSecret(KEY_A, "SECRET-SEED");
    expect(payload.ciphertext).not.toContain("SECRET-SEED");
  });

  it("同一明文两次加密产生不同密文（IV 随机）", async () => {
    const first = await encryptSecret(KEY_A, "same-secret");
    const second = await encryptSecret(KEY_A, "same-secret");
    expect(first.ciphertext).not.toBe(second.ciphertext);
    expect(first.iv).not.toBe(second.iv);
  });

  it("IV 长度为 12 字节", async () => {
    const payload = await encryptSecret(KEY_A, "x");
    expect(atob(payload.iv)).toHaveLength(12);
  });

  it("换主密钥后解密失败", async () => {
    const payload = await encryptSecret(KEY_A, "secret");
    await expect(decryptSecret(KEY_B, payload)).rejects.toThrow();
  });

  it("篡改密文后解密失败（GCM 认证）", async () => {
    const payload = await encryptSecret(KEY_A, "secret");
    const bytes = atob(payload.ciphertext).split("");
    bytes[0] = String.fromCharCode(bytes[0].charCodeAt(0) ^ 0xff);
    const tampered = { ...payload, ciphertext: btoa(bytes.join("")) };
    await expect(decryptSecret(KEY_A, tampered)).rejects.toThrow();
  });

  it("key_version 参与派生：不同版本互不兼容", async () => {
    const v1 = await encryptSecret(KEY_A, "secret", 1);
    const v2 = await encryptSecret(KEY_A, "secret", 2);
    expect(v1.ciphertext).not.toBe(v2.ciphertext);
    await expect(decryptSecret(KEY_A, { ...v2, keyVersion: 1 })).rejects.toThrow();
  });
});
