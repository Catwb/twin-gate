import { and, desc, eq, gt, isNull } from "drizzle-orm";
import type { Db } from "../db/client";
import { sessions } from "../db/schema";
import { nowSeconds } from "../lib/time";

/**
 * 列出当前活动会话（用于"哪些设备还登着"）。
 * 只返回管理必需字段，不含 token_hash。
 */
export async function listActiveSessions(db: Db, limit: number, offset: number) {
  const now = nowSeconds();
  return db
    .select({
      id: sessions.id,
      userId: sessions.userId,
      status: sessions.status,
      createdAt: sessions.createdAt,
      lastUsedAt: sessions.lastUsedAt,
      expiresAt: sessions.expiresAt,
      userAgent: sessions.userAgent,
      ip: sessions.ip,
    })
    .from(sessions)
    .where(and(isNull(sessions.revokedAt), gt(sessions.expiresAt, now)))
    .orderBy(desc(sessions.lastUsedAt))
    .limit(limit)
    .offset(offset);
}

export async function listSessionsOfUser(db: Db, userId: string, limit: number) {
  const now = nowSeconds();
  return db
    .select({
      id: sessions.id,
      status: sessions.status,
      lastUsedAt: sessions.lastUsedAt,
      userAgent: sessions.userAgent,
      ip: sessions.ip,
    })
    .from(sessions)
    .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt), gt(sessions.expiresAt, now)))
    .orderBy(desc(sessions.lastUsedAt))
    .limit(limit);
}
