import { desc, eq, inArray } from "drizzle-orm";
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
 * 计算「要让 D1 与 secret 一致，需要做哪些写入」。
 *
 * 抽成纯函数有两个理由：
 *   1. 稳态下必须返回空数组 —— 之前的实现每轮无条件 UPDATE 每把钥匙，
 *      96 tick/天 × 2 把 = 192 行写入，全都写的是同一个值。
 *   2. 没有 D1 也能测。这段逻辑以前一行测试都没有。
 */
export type KeyChange =
  | { kind: "insert"; kid: string; alg: string; publicJwk: string; status: "active" | "retired"; retiredAt: number | null }
  | { kind: "update"; kid: string; status: "active" | "retired"; retiredAt: number | null };

export function planKeyChanges(
  existing: { kid: string; status: string; retiredAt: number | null }[],
  set: KeySet,
  now: number,
): KeyChange[] {
  const byKid = new Map(existing.map((row) => [row.kid, row]));
  const changes: KeyChange[] = [];

  for (const [index, key] of set.keys.entries()) {
    const status = index === 0 ? "active" : "retired";
    const publicJwk = JSON.stringify(toPublicJwk(key.private_jwk, key.kid));
    const current = byKid.get(key.kid);

    if (!current) {
      changes.push({
        kind: "insert",
        kid: key.kid,
        alg: key.alg,
        publicJwk,
        status,
        retiredAt: status === "active" ? null : now,
      });
      continue;
    }

    // 只在真的需要变时才写：
    //   - status 变了（密钥晋升 / 降级）
    //   - retiredAt 与 status 不自洽（历史数据里 retired 的键 retiredAt 是 NULL）
    const wantRetiredAt = status === "retired" ? current.retiredAt ?? now : null;
    const statusChanged = current.status !== status;
    const retiredAtChanged = current.retiredAt !== wantRetiredAt;

    if (statusChanged || retiredAtChanged) {
      changes.push({ kind: "update", kid: key.kid, status, retiredAt: wantRetiredAt });
    }
  }

  return changes;
}

/**
 * 把 secret 里的密钥同步进 D1。
 * D1 只保留公钥，私钥永远不进库。
 *
 * 稳态下这里只做一次 SELECT、零次写入；有变化时合并成一次 batch
 * （D1 的 batch 是单事务、单次往返）。
 */
export async function syncSigningKeys(db: Db, set: KeySet): Promise<number> {
  const now = nowSeconds();
  const existing = await db.select().from(signingKeys);
  const changes = planKeyChanges(existing, set, now);
  if (changes.length === 0) return 0;

  const statements = changes.map((change) => {
    if (change.kind === "insert") {
      return db.insert(signingKeys).values({
        kid: change.kid,
        alg: change.alg,
        publicJwk: change.publicJwk,
        status: change.status,
        createdAt: now,
        retiredAt: change.retiredAt,
      });
    }
    return db
      .update(signingKeys)
      .set({ status: change.status, retiredAt: change.retiredAt })
      .where(eq(signingKeys.kid, change.kid));
  });

  await db.batch(statements as [(typeof statements)[number], ...(typeof statements)[number][]]);
  return changes.length;
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

/**
 * 只保留最近 RETAINED_RETIRED_KEYS 把退役公钥。
 *
 * buildJwks 本来就只输出这么多，多出来的行永远不会被任何人读到，
 * 却会一直躺在表里。删除条件与 buildJwks 的保留条件必须一致。
 */
export async function pruneRetiredKeys(db: Db): Promise<number> {
  const keep = await db
    .select({ kid: signingKeys.kid })
    .from(signingKeys)
    .where(eq(signingKeys.status, "retired"))
    .orderBy(desc(signingKeys.createdAt))
    .limit(RETAINED_RETIRED_KEYS);

  const kept = new Set(keep.map((row) => row.kid));
  const retired = await db
    .select({ kid: signingKeys.kid })
    .from(signingKeys)
    .where(eq(signingKeys.status, "retired"));

  const stale = retired.map((row) => row.kid).filter((kid) => !kept.has(kid));
  if (stale.length === 0) return 0;

  await db.delete(signingKeys).where(inArray(signingKeys.kid, stale));
  return stale.length;
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