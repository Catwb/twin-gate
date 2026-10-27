import { hashPassword, timingSafeEqual } from "../lib/crypto";

/** 最小长度 12，不强制字符复杂度（强制符号只会催生 Passw0rd!）。 */
export const MIN_PASSWORD_LENGTH = 12;

export function checkPasswordPolicy(plaintext: string): { ok: true } | { ok: false; reason: string } {
  if (plaintext.length < MIN_PASSWORD_LENGTH) {
    return { ok: false, reason: `密码长度至少 ${MIN_PASSWORD_LENGTH} 位` };
  }
  if (plaintext.length > 256) {
    return { ok: false, reason: "密码过长" };
  }
  return { ok: true };
}

export async function verifyPassword(
  pepper: string,
  plaintext: string,
  storedHash: string,
): Promise<boolean> {
  const computed = await hashPassword(pepper, plaintext);
  return timingSafeEqual(computed, storedHash);
}

/**
 * 用户不存在时也调用一次，保证耗时与真实校验一致，防止用户名枚举。
 * 返回一个永远不会匹配的哈希。
 */
export async function dummyVerify(pepper: string, plaintext: string): Promise<false> {
  await hashPassword(pepper, plaintext);
  return false;
}

export async function makePasswordHash(pepper: string, plaintext: string): Promise<string> {
  return hashPassword(pepper, plaintext);
}
