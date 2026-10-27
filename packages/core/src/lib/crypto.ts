const enc = new TextEncoder();

export function toHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function randomHex(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

export function uuid(): string {
  return crypto.randomUUID();
}

/** 令牌只以 SHA-256 落库，任何地方都不得存原文。 */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(input));
  return toHex(digest);
}

/**
 * 密码哈希：HMAC-SHA256(pepper, 明文)。
 * 不做 PBKDF2 —— Workers 免费版 10 ms CPU 预算跑不动，且 workerd 硬性封顶 10 万次。
 * 代价是 pepper 成为唯一防线，因此 pepper 必须离线备份且与 D1 备份分开存放。
 */
export async function hashPassword(pepper: string, plaintext: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(pepper),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(plaintext));
  return toHex(sig);
}

/** 定长比较，避免通过响应时间泄露哈希前缀。 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
