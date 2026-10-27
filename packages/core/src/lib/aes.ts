const enc = new TextEncoder();
const dec = new TextDecoder();

export type EncryptedPayload = {
  ciphertext: string;
  iv: string;
  keyVersion: number;
};

/**
 * 从主密钥派生 AES-GCM 密钥。
 * TOTP_MASTER_KEY 与 SESSION_PEPPER 必须是两个独立的 secret ——
 * 一个泄露不应牵连另一个。
 */
async function deriveKey(masterKey: string, keyVersion: number): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(masterKey),
    { name: "HKDF" },
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: enc.encode(`sso-totp-salt-v${keyVersion}`),
      info: enc.encode("totp-secret-encryption"),
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export async function encryptSecret(
  masterKey: string,
  plaintext: string,
  keyVersion = 1,
): Promise<EncryptedPayload> {
  const key = await deriveKey(masterKey, keyVersion);
  // 每次加密都用全新 IV —— GCM 下重复 IV 会直接毁掉保密性。
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext),
  );

  return {
    ciphertext: toBase64(new Uint8Array(ciphertext)),
    iv: toBase64(iv),
    keyVersion,
  };
}

export async function decryptSecret(
  masterKey: string,
  payload: EncryptedPayload,
): Promise<string> {
  const key = await deriveKey(masterKey, payload.keyVersion);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(payload.iv) },
    key,
    fromBase64(payload.ciphertext),
  );
  return dec.decode(plaintext);
}
