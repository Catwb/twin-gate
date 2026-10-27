import { desc, eq } from "drizzle-orm";
import type { Db } from "../db/client";
import { signingKeys } from "../db/schema";
import type { Jwk, SigningKeyMaterial } from "../lib/jwt";
import { toPublicJwk } from "../lib/jwt";
import { nowSeconds } from "../lib/time";

/** JWKS 里保留多少把已退役公钥。覆盖 ID Token 最长寿命 + 客户端缓存 TTL 即可。 */
const RETAINED_RETIRED_KEYS = 3;

export type KeySet = {
  keys: SigningKeyMaterial[];
};

/**
 * 私钥只存在于 SIGNING_KEYS_JSON（wrangler secret）。
 * 格式：
 *   [{ "kid": "k20261026", "alg": "EdDSA",
 *      "public_jwk": {...}, "private_jwk": {...} }]
 *
 * 第一项是当前签名密钥，其余用于轮换过渡期的验签。
 */
export function parseKeySet(raw: string): KeySet {
  const parsed = JSON.parse(raw) as unknown;
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error("SIGNING_KEYS_JSON 必须是非空数组");
  }
  const keys = parsed.map((item, index) => {
    const key = item as Partial<SigningKeyMaterial>;
    if (!key.kid || !key.private_jwk || !key.alg) {
      throw new Error(`SIGNING_KEYS_JSON 第 ${index} 项缺少 kid / alg / private_jwk`);
    }
    return {
      kid: key.kid,
      alg: key.alg,
      public_jwk: key.public_jwk ?? toPublicJwk(key.private_jwk, key.kid),
      private_jwk: key.private_jwk,
    } satisfies SigningKeyMaterial;
  });
  return { keys };
}

export function activeKey(set: KeySet): SigningKeyMaterial {
  const key = set.keys[0];
  if (!key) throw new Error("没有可用的签名密钥");
  return key;
}

/**
 * 把 secret 里的密钥同步进 D1。
 * D1 只保留公钥，私钥永远不进库。
 */
export async function syncSigningKeys(db: Db, set: KeySet): Promise<void> {
  const now = nowSeconds();
  const existing = await db.select().from(signingKeys);
  const known = new Set(existing.map((row) => row.kid));

  for (const [index, key] of set.keys.entries()) {
    const publicJwk = JSON.stringify(toPublicJwk(key.private_jwk, key.kid));
    if (!known.has(key.kid)) {
      await db.insert(signingKeys).values({
        kid: key.kid,
        alg: key.alg,
        publicJwk,
        status: index === 0 ? "active" : "retired",
        createdAt: now,
        retiredAt: index === 0 ? null : now,
      });
    } else {
      await db
        .update(signingKeys)
        .set({ status: index === 0 ? "active" : "retired" })
        .where(eq(signingKeys.kid, key.kid));
    }
  }
}

/**
 * 生成 JWKS 响应。
 * 只从 D1 的 public_jwk 读出，这条代码路径不接触任何私钥材料。
 *
 * 首次部署时 D1 还是空的 —— 那时如果直接返回空数组，下游会拿不到任何公钥，
 * 表现为"登录成功但 ID Token 验不过"。所以这里做一次惰性同步：
 * 只有表为空且 secret 存在时才写入，之后走正常读取路径。
 */
export async function buildJwks(db: Db, signingKeysJson?: string): Promise<{ keys: Jwk[] }> {
  const existing = await db.select({ kid: signingKeys.kid }).from(signingKeys).limit(1);
  if (existing.length === 0 && signingKeysJson) {
    await syncSigningKeys(db, parseKeySet(signingKeysJson));
  }

  const active = await db
    .select()
    .from(signingKeys)
    .where(eq(signingKeys.status, "active"))
    .orderBy(desc(signingKeys.createdAt))
    .limit(1);

  const retired = await db
    .select()
    .from(signingKeys)
    .where(eq(signingKeys.status, "retired"))
    .orderBy(desc(signingKeys.createdAt))
    .limit(RETAINED_RETIRED_KEYS);

  const rows = [...active, ...retired];
  const keys = rows.map((row) => {
    const jwk = JSON.parse(row.publicJwk) as Jwk;
    return toPublicJwk(jwk, row.kid);
  });

  return { keys };
}

export async function listSigningKeys(db: Db) {
  return db
    .select({
      kid: signingKeys.kid,
      alg: signingKeys.alg,
      status: signingKeys.status,
      createdAt: signingKeys.createdAt,
      retiredAt: signingKeys.retiredAt,
    })
    .from(signingKeys)
    .orderBy(desc(signingKeys.createdAt));
}