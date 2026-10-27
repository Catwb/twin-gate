import { describe, expect, it } from "vitest";
import {
  base64urlDecode,
  base64urlEncode,
  signJwt,
  toPublicJwk,
  verifyJwt,
  type SigningKeyMaterial,
} from "../src/lib/jwt";

async function makeKey(kid = "test-k1"): Promise<SigningKeyMaterial> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const privateJwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as JsonWebKey;
  const publicJwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;

  return {
    kid,
    alg: "EdDSA",
    public_jwk: publicJwk as never,
    private_jwk: privateJwk as never,
  };
}

describe("base64url", () => {
  it("编码后不含 + / =", () => {
    const encoded = base64urlEncode(new Uint8Array([251, 255, 191, 0, 1]));
    expect(encoded).not.toMatch(/[+/=]/);
  });

  it("往返一致", () => {
    const original = "hello world 你好";
    const roundTrip = new TextDecoder().decode(base64urlDecode(base64urlEncode(original)));
    expect(roundTrip).toBe(original);
  });
});

describe("signJwt / verifyJwt", () => {
  it("签发的令牌能用对应公钥验签", async () => {
    const key = await makeKey();
    const token = await signJwt({ sub: "user-1", iss: "https://sso.test" }, key);
    const payload = await verifyJwt(token, toPublicJwk(key.private_jwk as never, key.kid));
    expect(payload?.sub).toBe("user-1");
  });

  it("令牌结构为三段", async () => {
    const key = await makeKey();
    const token = await signJwt({ sub: "x" }, key);
    expect(token.split(".")).toHaveLength(3);
  });

  it("篡改 payload 后验签失败", async () => {
    const key = await makeKey();
    const token = await signJwt({ sub: "user-1" }, key);
    const [header, , signature] = token.split(".");
    const forgedPayload = base64urlEncode(JSON.stringify({ sub: "admin" }));
    const forged = `${header}.${forgedPayload}.${signature}`;
    const payload = await verifyJwt(forged, toPublicJwk(key.private_jwk as never, key.kid));
    expect(payload).toBeNull();
  });

  it("换一把公钥后验签失败", async () => {
    const key = await makeKey();
    const other = await makeKey("other");
    const token = await signJwt({ sub: "user-1" }, key);
    const payload = await verifyJwt(token, toPublicJwk(other.private_jwk as never, other.kid));
    expect(payload).toBeNull();
  });

  it("header 里带 kid 与 EdDSA", async () => {
    const key = await makeKey("k-42");
    const token = await signJwt({ sub: "x" }, key);
    const header = JSON.parse(new TextDecoder().decode(base64urlDecode(token.split(".")[0]!)));
    expect(header.alg).toBe("EdDSA");
    expect(header.kid).toBe("k-42");
  });
});

describe("toPublicJwk —— 私钥剥离", () => {
  it("输出只含 kty/crv/x/kid/alg/use", async () => {
    const key = await makeKey();
    const pub = toPublicJwk(key.private_jwk as never, key.kid);
    expect(Object.keys(pub).sort()).toEqual(["alg", "crv", "kid", "kty", "use", "x"]);
  });

  it("绝对不含私钥字段 d", async () => {
    const key = await makeKey();
    const pub = toPublicJwk(key.private_jwk as never, key.kid);
    expect("d" in pub).toBe(false);
  });

  it("即使输入带 d 也会被剥离", async () => {
    const key = await makeKey();
    const privateJwk = key.private_jwk as Record<string, unknown>;
    expect(privateJwk.d).toBeTruthy();

    const pub = toPublicJwk(privateJwk as never, key.kid);
    expect(JSON.stringify(pub)).not.toContain('"d"');
  });
});
