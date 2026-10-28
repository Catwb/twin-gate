import { and, eq, isNull, ne } from "drizzle-orm";
import { SessionStatus, TTL, type Role } from "@sso/shared";
import type { Db } from "../db/client";
import { accessTokens, authorizationCodes, sessions } from "../db/schema";
import { randomHex, sha256Hex, uuid } from "../lib/crypto";
import { nowSeconds } from "../lib/time";

export type IssuedSession = {
  sessionId: string;
  token: string;
  expiresAt: number;
};

export type SessionLookup =
  | { valid: true; sessionId: string; userId: string; role: Role; status: string }
  | { valid: false; reason: "missing" | "expired" | "revoked" | "mfa_pending" };

function sessionExpiry(status: string): number {
  const ttl = status === SessionStatus.MfaPending ? TTL.mfaPending : TTL.session;
  return nowSeconds() + ttl;
}

export async function createSession(
  db: Db,
  params: {
    userId: string;
    status: string;
    userAgent?: string | null;
    ip?: string | null;
    sessionId?: string;
  },
): Promise<IssuedSession> {
  const token = randomHex(32);
  const tokenHash = await sha256Hex(token);
  const sessionId = params.sessionId ?? uuid();
  const now = nowSeconds();
  const expiresAt = sessionExpiry(params.status);

  await db.insert(sessions).values({
    id: sessionId,
    tokenHash,
    userId: params.userId,
    status: params.status,
    expiresAt,
    createdAt: now,
    lastUsedAt: now,
    userAgent: params.userAgent ?? null,
    ip: params.ip ?? null,
  });

  return { sessionId, token, expiresAt };
}

/**
 * MFA 升级与改密必须轮换 token（防会话固定），但保留同一个 id，
 * 这样下游与审计里的会话标识不中断。
 */
export async function rotateSessionToken(
  db: Db,
  sessionId: string,
  status: string,
): Promise<IssuedSession> {
  const token = randomHex(32);
  const tokenHash = await sha256Hex(token);
  const expiresAt = sessionExpiry(status);

  await db
    .update(sessions)
    .set({ tokenHash, status, expiresAt, lastUsedAt: nowSeconds() })
    .where(eq(sessions.id, sessionId));

  return { sessionId, token, expiresAt };
}

export async function lookupSession(
  db: Db,
  token: string,
  roleOf: (userId: string) => Promise<Role | null>,
): Promise<SessionLookup> {
  const tokenHash = await sha256Hex(token);
  const rows = await db.select().from(sessions).where(eq(sessions.tokenHash, tokenHash)).limit(1);
  const row = rows[0];
  if (!row) return { valid: false, reason: "missing" };
  if (row.revokedAt !== null) return { valid: false, reason: "revoked" };
  if (row.expiresAt <= nowSeconds()) return { valid: false, reason: "expired" };
  // 显式拒绝 mfa_pending —— 硬约束，不能靠调用方自觉。
  if (row.status === SessionStatus.MfaPending) return { valid: false, reason: "mfa_pending" };

  const role = await roleOf(row.userId);
  if (!role) return { valid: false, reason: "missing" };

  return { valid: true, sessionId: row.id, userId: row.userId, role, status: row.status };
}

/**
 * 校验某个 mfa_pending 会话确实属于指定用户。
 *
 * 第二因子端点从 payload 里同时收 userId 与 sessionId，两者来自不同地方，
 * 不校验绑定关系的话，任何持有自己待验证会话的人都能拿别人的 userId
 * 去猜验证码 —— 验证码成了可离线爆破的预言机。
 */
export async function isPendingSessionOfUser(
  db: Db,
  params: { sessionId: string; userId: string },
): Promise<boolean> {
  const rows = await db
    .select({ userId: sessions.userId, status: sessions.status, revokedAt: sessions.revokedAt, expiresAt: sessions.expiresAt })
    .from(sessions)
    .where(eq(sessions.id, params.sessionId))
    .limit(1);

  const row = rows[0];
  if (!row) return false;
  if (row.revokedAt !== null) return false;
  if (row.expiresAt <= nowSeconds()) return false;
  if (row.status !== SessionStatus.MfaPending) return false;
  return row.userId === params.userId;
}

export async function touchSession(db: Db, sessionId: string): Promise<void> {
  await db.update(sessions).set({ lastUsedAt: nowSeconds() }).where(eq(sessions.id, sessionId));
}

/**
 * 构造吊销语句组。调用方必须交给 db.batch() 以单事务执行，
 * 禁止先查后写、禁止分成多次调用。
 */
export function revokeAllStatements(
  db: Db,
  params: { userId: string; reason: string; keepSessionId?: string },
) {
  const now = nowSeconds();
  const sessionWhere = params.keepSessionId
    ? and(eq(sessions.userId, params.userId), isNull(sessions.revokedAt), ne(sessions.id, params.keepSessionId))
    : and(eq(sessions.userId, params.userId), isNull(sessions.revokedAt));

  return [
    db
      .update(sessions)
      .set({ revokedAt: now, revokeReason: params.reason })
      .where(sessionWhere),
    db
      .update(accessTokens)
      .set({ revokedAt: now })
      .where(and(eq(accessTokens.userId, params.userId), isNull(accessTokens.revokedAt))),
    db
      .update(authorizationCodes)
      .set({ usedAt: now })
      .where(and(eq(authorizationCodes.userId, params.userId), isNull(authorizationCodes.usedAt))),
  ] as const;
}

/** 吊销单个会话，以及由它签出的全部访问令牌。同样必须走 batch。 */
export function revokeOneSessionStatements(db: Db, sessionId: string, reason: string) {
  const now = nowSeconds();
  return [
    db
      .update(sessions)
      .set({ revokedAt: now, revokeReason: reason })
      .where(and(eq(sessions.id, sessionId), isNull(sessions.revokedAt))),
    db
      .update(accessTokens)
      .set({ revokedAt: now })
      .where(and(eq(accessTokens.sessionId, sessionId), isNull(accessTokens.revokedAt))),
  ] as const;
}
