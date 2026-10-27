import { and, eq, gt, isNull } from "drizzle-orm";
import type { Role } from "@sso/shared";
import type { Db } from "../db/client";
import { invitations } from "../db/schema";
import { randomHex, sha256Hex, uuid } from "../lib/crypto";
import { nowSeconds } from "../lib/time";

export type CreatedInvitation = {
  id: string;
  /** 明文仅此一次返回，D1 只存哈希。 */
  code: string;
  expiresAt: number;
};

export async function createInvitation(
  db: Db,
  params: { email?: string | null; role: Role; createdBy: string; ttlSeconds: number },
): Promise<CreatedInvitation> {
  const code = randomHex(16);
  const codeHash = await sha256Hex(code);
  const id = uuid();
  const now = nowSeconds();
  const expiresAt = now + params.ttlSeconds;

  await db.insert(invitations).values({
    id,
    codeHash,
    email: params.email ? params.email.toLowerCase() : null,
    role: params.role,
    createdBy: params.createdBy,
    createdAt: now,
    expiresAt,
  });

  return { id, code, expiresAt };
}

/**
 * 原子占用：以受影响行数 == 1 判定成功。
 * 严禁先 SELECT 再 UPDATE —— 那是经典的竞态漏洞。
 */
export async function consumeInvitation(
  db: Db,
  code: string,
): Promise<{ ok: true; invitation: typeof invitations.$inferSelect } | { ok: false }> {
  const codeHash = await sha256Hex(code);
  const now = nowSeconds();

  const updated = await db
    .update(invitations)
    .set({ usedAt: now })
    .where(
      and(
        eq(invitations.codeHash, codeHash),
        isNull(invitations.usedAt),
        isNull(invitations.revokedAt),
        gt(invitations.expiresAt, now),
      ),
    )
    .returning();

  const row = updated[0];
  if (!row) return { ok: false };
  return { ok: true, invitation: row };
}

export async function listInvitations(db: Db, limit: number, offset: number) {
  return db
    .select({
      id: invitations.id,
      email: invitations.email,
      role: invitations.role,
      createdAt: invitations.createdAt,
      expiresAt: invitations.expiresAt,
      usedAt: invitations.usedAt,
      revokedAt: invitations.revokedAt,
    })
    .from(invitations)
    .orderBy(invitations.createdAt)
    .limit(limit)
    .offset(offset);
}

export async function revokeInvitation(db: Db, id: string): Promise<void> {
  await db.update(invitations).set({ revokedAt: nowSeconds() }).where(eq(invitations.id, id));
}
