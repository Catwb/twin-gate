import { uuid } from "../lib/crypto";
import { nowSeconds } from "../lib/time";
import type { Db } from "../db/client";
import { auditLogs } from "../db/schema";

export type AuditEvent = {
  action: string;
  actorUserId?: string | null;
  target?: string | null;
  ip?: string | null;
  meta?: Record<string, unknown>;
};

/**
 * 审计写入失败绝不能阻断认证。
 * 调用方应当用 ctx.waitUntil 包裹，接受 best-effort 语义。
 */
export async function appendAudit(db: Db, event: AuditEvent): Promise<void> {
  await db.insert(auditLogs).values({
    id: uuid(),
    actorUserId: event.actorUserId ?? null,
    action: event.action,
    target: event.target ?? null,
    ip: event.ip ?? null,
    meta: event.meta ? JSON.stringify(event.meta) : null,
    createdAt: nowSeconds(),
  });
}

/** 审计失败不抛出，只记录。 */
export async function safeAudit(db: Db, event: AuditEvent): Promise<void> {
  try {
    await appendAudit(db, event);
  } catch {
    // 明确接受丢失：审计是 best-effort，不得影响登录等主流程。
  }
}
