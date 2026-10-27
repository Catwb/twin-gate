const enc = new TextEncoder();

export function base64urlEncode(input: Uint8Array | string): string {
  const bytes = typeof input === "string" ? enc.encode(input) : input;
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export type Jwk = {
  kty: string;
  crv?: string;
  x?: string;
  d?: string;
  kid?: string;
  alg?: string;
  use?: string;
};

export type SigningKeyMaterial = {
  kid: string;
  alg: string;
  /** 下发给 /jwks.json 的公钥。 */
  public_jwk: Jwk;
  /** 只在 secret 里，永不进 D1。 */
  private_jwk: Jwk;
};

export type JwtPayload = Record<string, unknown>;

/**
 * EdDSA（Ed25519）签名。Workers 的 Web Crypto 通过 Secure Curves API 支持。
 */
export async function signJwt(
  payload: JwtPayload,
  key: SigningKeyMaterial,
): Promise<string> {
  const header = { alg: "EdDSA", typ: "JWT", kid: key.kid };
  const signingInput = `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(
    JSON.stringify(payload),
  )}`;

  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    key.private_jwk as JsonWebKey,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("Ed25519", cryptoKey, enc.encode(signingInput));
  return `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`;
}

/** 仅用于测试与自检；生产下游用 JWKS 自己验。 */
export async function verifyJwt(token: string, publicJwk: Jwk): Promise<JwtPayload | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];

  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    publicJwk as JsonWebKey,
    { name: "Ed25519" },
    false,
    ["verify"],
  );

  const ok = await crypto.subtle.verify(
    "Ed25519",
    cryptoKey,
    base64urlDecode(signaturePart),
    enc.encode(`${headerPart}.${payloadPart}`),
  );
  if (!ok) return null;

  try {
    return JSON.parse(new TextDecoder().decode(base64urlDecode(payloadPart))) as JwtPayload;
  } catch {
    return null;
  }
}

/**
 * 私钥必须被剥离后才能进入任何响应。
 * JWKS 只允许出现这些字段。
 */
const PUBLIC_JWK_FIELDS = ["kty", "crv", "x", "kid", "alg", "use"] as const;

export function toPublicJwk(jwk: Jwk, kid: string): Jwk {
  const source = jwk as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const field of PUBLIC_JWK_FIELDS) {
    if (field === "kid") {
      out.kid = kid;
    } else if (source[field] !== undefined) {
      out[field] = source[field];
    }
  }
  out.alg = "EdDSA";
  out.use = "sig";
  return out as Jwk;
}
