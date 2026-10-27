import { and, eq, isNull } from "drizzle-orm";
import type { Db } from "../db/client";
import { mfaFactors, mfaRecoveryCodes, passkeys } from "../db/schema";
import { randomHex, sha256Hex, uuid } from "../lib/crypto";
import { nowSeconds } from "../lib/time";

export const RECOVERY_CODE_COUNT = 10;

export type GeneratedCodes = { codes: string[] };

/**
 * 生成恢复码。明文只返回这一次，D1 只存 SHA-256。
 * 用户手机丢了、Passkey 设备丢了，这是唯一的自助出路。
 */
export async function generateRecoveryCodes(db: Db, userId: string): Promise<GeneratedCodes> {
  // 重新生成时作废旧码，避免越攒越多。
  await db.delete(mfaRecoveryCodes).where(eq(mfaRecoveryCodes.userId, userId));

  const now = nowSeconds();
  const codes: string[] = [];

  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const code = formatCode(randomHex(10));
    codes.push(code);
    await db.insert(mfaRecoveryCodes).values({
      id: uuid(),
      userId,
      codeHash: await sha256Hex(normalizeCode(code)),
      usedAt: null,
      createdAt: now,
    });
  }

  return { codes };
}

export type RecoveryResult =
  | { ok: true; userId: string }
  | { ok: false; reason: "invalid" | "none_left" };

/**
 * 使用恢复码：原子占用，单次有效。
 * 用掉之后必须由调用方吊销全部会话 —— 恢复码等同于"凭证丢失后的接管"。
 */
export async function consumeRecoveryCode(
  db: Db,
  params: { userId: string; code: string },
): Promise<RecoveryResult> {
  const codeHash = await sha256Hex(normalizeCode(params.code));

  const updated = await db
    .update(mfaRecoveryCodes)
    .set({ usedAt: nowSeconds() })
    .where(
      and(
        eq(mfaRecoveryCodes.userId, params.userId),
        eq(mfaRecoveryCodes.codeHash, codeHash),
        isNull(mfaRecoveryCodes.usedAt),
      ),
    )
    .returning({ id: mfaRecoveryCodes.id });

  if (updated.length === 0) return { ok: false, reason: "invalid" };
  return { ok: true, userId: params.userId };
}

export async function remainingRecoveryCodes(db: Db, userId: string): Promise<number> {
  const rows = await db
    .select({ id: mfaRecoveryCodes.id })
    .from(mfaRecoveryCodes)
    .where(and(eq(mfaRecoveryCodes.userId, userId), isNull(mfaRecoveryCodes.usedAt)));
  return rows.length;
}

/**
 * 超管重置 MFA：
 * 因子标记为 revoked（不物理删，保留审计可追溯），
 * 同时吊销该用户全部会话与令牌 —— 不踢会话的话，
 * "重置 MFA"对已经登录的会话毫无意义。
 */
export function revokeMfaStatements(db: Db, userId: string) {
  const now = nowSeconds();
  return [
    db
      .update(mfaFactors)
      .set({ status: "revoked", revokedAt: now })
      .where(and(eq(mfaFactors.userId, userId), eq(mfaFactors.status, "active"))),
    db
      .update(passkeys)
      .set({ revokedAt: now })
      .where(and(eq(passkeys.userId, userId), isNull(passkeys.revokedAt))),
    db.delete(mfaRecoveryCodes).where(eq(mfaRecoveryCodes.userId, userId)),
  ] as const;
}

/** 用户输入的恢复码统一去掉分隔符与大小写差异。 */
function normalizeCode(code: string): string {
  return code.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
}

/** 展示为 xxxxx-xxxxx 形式，便于抄写。 */
function formatCode(hex: string): string {
  const clean = hex.toLowerCase().slice(0, 10);
  return `${clean.slice(0, 5)}-${clean.slice(5, 10)}`;
}
