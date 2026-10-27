import { TOTP, Secret } from "otpauth";
import { and, eq, inArray, isNull, lt, or } from "drizzle-orm";
import type { Db } from "../db/client";
import { mfaFactors } from "../db/schema";
import { decryptSecret, encryptSecret } from "../lib/aes";
import { uuid } from "../lib/crypto";
import { nowSeconds } from "../lib/time";

/** 允许前后各一个 30 秒窗口 —— 容忍轻微时钟偏移。 */
const TOTP_WINDOW = 1;
const TOTP_PERIOD = 30;
const TOTP_DIGITS = 6;

export type EnrolledTotp = {
  factorId: string;
  secret: string;
  uri: string;
};

export async function createTotpFactor(
  db: Db,
  params: { userId: string; accountName: string; issuer: string },
): Promise<EnrolledTotp> {
  const secret = new Secret({ size: 20 });
  const totp = new TOTP({
    issuer: params.issuer,
    label: params.accountName,
    algorithm: "SHA1",
    digits: TOTP_DIGITS,
    period: TOTP_PERIOD,
    secret,
  });

  const factorId = uuid();
  // 未验证的因子先不落库 —— 用户必须提交首个验证码后才创建。
  // 这里只把 secret 交给调用方加密暂存，见 MFA 流程。
  return { factorId, secret: secret.base32, uri: totp.toString() };
}

export async function persistTotpFactor(
  db: Db,
  params: { factorId: string; userId: string; secret: string; masterKey: string },
): Promise<void> {
  const encrypted = await encryptSecret(params.masterKey, params.secret);
  await db.insert(mfaFactors).values({
    id: params.factorId,
    userId: params.userId,
    factorType: "totp",
    secretCiphertext: encrypted.ciphertext,
    iv: encrypted.iv,
    keyVersion: encrypted.keyVersion,
    status: "active",
    verifiedAt: null,
    createdAt: nowSeconds(),
  });
}

export type VerifyResult =
  | { ok: true; factorId: string }
  | { ok: false; reason: "no_factor" | "invalid_code" | "replayed" | "decrypt_failed" };

/**
 * 验证 TOTP。同一时间步只接受一次 ——
 * ±1 窗口意味着 90 秒有效期，不防重放就是可重放。
 */
export async function verifyTotp(
  db: Db,
  params: { userId: string; code: string; masterKey: string },
): Promise<VerifyResult> {
  const rows = await db
    .select()
    .from(mfaFactors)
    .where(
      and(
        eq(mfaFactors.userId, params.userId),
        eq(mfaFactors.factorType, "totp"),
        // 启用确认阶段因子还是 pending，登录验证阶段是 active。
        // 两种都要能验证，否则永远无法完成首次绑定。
        inArray(mfaFactors.status, ["pending", "active"]),
      ),
    )
    .limit(1);

  const factor = rows[0];
  if (!factor || !factor.secretCiphertext || !factor.iv) return { ok: false, reason: "no_factor" };

  let secretBase32: string;
  try {
    secretBase32 = await decryptSecret(params.masterKey, {
      ciphertext: factor.secretCiphertext,
      iv: factor.iv,
      keyVersion: factor.keyVersion,
    });
  } catch {
    return { ok: false, reason: "decrypt_failed" };
  }

  const totp = new TOTP({
    algorithm: "SHA1",
    digits: TOTP_DIGITS,
    period: TOTP_PERIOD,
    secret: Secret.fromBase32(secretBase32),
  });

  const delta = totp.validate({ token: params.code, window: TOTP_WINDOW });
  if (delta === null) return { ok: false, reason: "invalid_code" };

  const currentStep = Math.floor(nowSeconds() / TOTP_PERIOD);
  const matchedStep = currentStep + delta;

  // 原子占用：只有 last_used_step 为空或小于本次步长时才更新成功。
  // 以受影响行数判定，避免两个并发请求用同一个码通过。
  const updated = await db
    .update(mfaFactors)
    .set({ lastUsedStep: matchedStep, verifiedAt: factor.verifiedAt ?? nowSeconds() })
    .where(
      and(
        eq(mfaFactors.id, factor.id),
        or(isNull(mfaFactors.lastUsedStep), lt(mfaFactors.lastUsedStep, matchedStep)),
      ),
    )
    .returning({ id: mfaFactors.id });

  if (updated.length === 0) return { ok: false, reason: "replayed" };
  return { ok: true, factorId: factor.id };
}

export async function hasTotpFactor(db: Db, userId: string): Promise<boolean> {
  const rows = await db
    .select({ id: mfaFactors.id })
    .from(mfaFactors)
    .where(
      and(
        eq(mfaFactors.userId, userId),
        eq(mfaFactors.factorType, "totp"),
        eq(mfaFactors.status, "active"),
      ),
    )
    .limit(1);
  return rows.length > 0;
}