import { and, lt, sql } from "drizzle-orm";
import { CRON_DELETE_BATCH } from "@sso/shared";
import type { Db } from "./db/client";
import {
  accessTokens,
  auditLogs,
  authorizationCodes,
  invitations,
  oidcStates,
  passwordResets,
  rateLimits,
  sessions,
} from "./db/schema";
import { nowSeconds } from "./lib/time";

/**
 * 免费版 Cron 单次 CPU 上限 10 ms，绝不能一条 SQL 扫全表。
 * 策略：每个表每轮最多删 CRON_DELETE_BATCH 行，靠 15 分钟的触发频率慢慢消化。
 */
export type CleanupReport = Record<string, number>;

export async function runCleanup(db: Db): Promise<CleanupReport> {
  const now = nowSeconds();
  const report: CleanupReport = {};

  // sessions / access_tokens 是真正的高增长表，优先清理。
  report.sessions = await deleteBatch(
    db,
    sql`DELETE FROM ${sessions} WHERE id IN (
      SELECT id FROM ${sessions} WHERE expires_at < ${now} OR (revoked_at IS NOT NULL AND revoked_at < ${now - 7 * 24 * 3600})
      LIMIT ${CRON_DELETE_BATCH}
    )`,
  );

  report.accessTokens = await deleteBatch(
    db,
    sql`DELETE FROM ${accessTokens} WHERE token_hash IN (
      SELECT token_hash FROM ${accessTokens} WHERE expires_at < ${now} OR revoked_at < ${now - 7 * 24 * 3600}
      LIMIT ${CRON_DELETE_BATCH}
    )`,
  );

  report.authorizationCodes = await deleteBatch(
    db,
    sql`DELETE FROM ${authorizationCodes} WHERE code_hash IN (
      SELECT code_hash FROM ${authorizationCodes} WHERE expires_at < ${now} LIMIT ${CRON_DELETE_BATCH}
    )`,
  );

  report.oidcStates = await deleteBatch(
    db,
    sql`DELETE FROM ${oidcStates} WHERE state_hash IN (
      SELECT state_hash FROM ${oidcStates} WHERE expires_at < ${now} LIMIT ${CRON_DELETE_BATCH}
    )`,
  );

  report.passwordResets = await deleteBatch(
    db,
    sql`DELETE FROM ${passwordResets} WHERE id IN (
      SELECT id FROM ${passwordResets} WHERE expires_at < ${now} LIMIT ${CRON_DELETE_BATCH}
    )`,
  );

  report.invitations = await deleteBatch(
    db,
    sql`DELETE FROM ${invitations} WHERE id IN (
      SELECT id FROM ${invitations}
      WHERE expires_at < ${now - 30 * 24 * 3600} OR used_at < ${now - 30 * 24 * 3600}
      LIMIT ${CRON_DELETE_BATCH}
    )`,
  );

  report.rateLimits = await deleteBatch(
    db,
    sql`DELETE FROM ${rateLimits} WHERE bucket_key IN (
      SELECT bucket_key FROM ${rateLimits} WHERE window_start < ${now - 3600} LIMIT ${CRON_DELETE_BATCH}
    )`,
  );

  // 审计保留 60 天（免费版 D1 单库 500 MB）。
  report.auditLogs = await deleteBatch(
    db,
    sql`DELETE FROM ${auditLogs} WHERE id IN (
      SELECT id FROM ${auditLogs} WHERE created_at < ${now - 60 * 24 * 3600} LIMIT ${CRON_DELETE_BATCH}
    )`,
  );

  return report;
}

async function deleteBatch(db: Db, statement: ReturnType<typeof sql>): Promise<number> {
  const result = await db.run(statement);
  const changes = (result as { meta?: { changes?: number } }).meta?.changes;
  return typeof changes === "number" ? changes : 0;
}

export { and, lt };
