import { and, eq, lte, sql } from "drizzle-orm";
import { LOCKOUT, TTL } from "@sso/shared";
import type { Db } from "../db/client";
import { rateLimits } from "../db/schema";
import { nowSeconds } from "../lib/time";

export type RateLimitResult = {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
};

/**
 * 固定窗口计数器。桶键形如：
 *   login:account:<email>      登录失败按账号
 *   login:ip:<ip>              登录失败按 IP
 *   invite:ip:<ip>             邀请码接受
 *   reset:ip:<ip>              密码重置
 */
export async function consume(
  db: Db,
  bucketKey: string,
  limit: number,
  windowSeconds: number,
): Promise<RateLimitResult> {
  const now = nowSeconds();
  const windowStart = Math.floor(now / windowSeconds) * windowSeconds;

  const row = await db
    .insert(rateLimits)
    .values({ bucketKey, windowStart, count: 1 })
    .onConflictDoUpdate({
      target: rateLimits.bucketKey,
      set: {
        count: sql`CASE WHEN ${rateLimits.windowStart} = ${windowStart} THEN ${rateLimits.count} + 1 ELSE 1 END`,
        windowStart,
      },
    })
    .returning({ count: rateLimits.count, windowStart: rateLimits.windowStart });

  const current = row[0];
  const count = current?.count ?? 1;
  const retryAfterSeconds = Math.max(0, windowStart + windowSeconds - now);

  return { allowed: count <= limit, remaining: Math.max(0, limit - count), retryAfterSeconds };
}

export async function peek(db: Db, bucketKey: string, windowSeconds: number): Promise<number> {
  const now = nowSeconds();
  const windowStart = Math.floor(now / windowSeconds) * windowSeconds;
  const rows = await db
    .select({ count: rateLimits.count })
    .from(rateLimits)
    .where(and(eq(rateLimits.bucketKey, bucketKey), eq(rateLimits.windowStart, windowStart)))
    .limit(1);
  return rows[0]?.count ?? 0;
}

export async function reset(db: Db, bucketKey: string): Promise<void> {
  await db.delete(rateLimits).where(eq(rateLimits.bucketKey, bucketKey));
}

export const buckets = {
  loginAccount: (email: string) => `login:account:${email.toLowerCase()}`,
  loginIp: (ip: string) => `login:ip:${ip}`,
  inviteIp: (ip: string) => `invite:ip:${ip}`,
  resetIp: (ip: string) => `reset:ip:${ip}`,
  passkeyIp: (ip: string) => `passkey:ip:${ip}`,
} as const;

/** 登录失败计数：账号维度 15 分钟 10 次，IP 维度 1 小时 20 次。 */
export async function checkLoginAllowed(db: Db, email: string, ip: string): Promise<boolean> {
  const accountFailures = await peek(db, buckets.loginAccount(email), LOCKOUT.perAccountSeconds);
  if (accountFailures >= LOCKOUT.perAccountFailures) return false;
  const ipFailures = await peek(db, buckets.loginIp(ip), LOCKOUT.perIpSeconds);
  if (ipFailures >= LOCKOUT.perIpFailures) return false;
  return true;
}

export async function recordLoginFailure(db: Db, email: string, ip: string): Promise<void> {
  await consume(db, buckets.loginAccount(email), LOCKOUT.perAccountFailures, LOCKOUT.perAccountSeconds);
  await consume(db, buckets.loginIp(ip), LOCKOUT.perIpFailures, LOCKOUT.perIpSeconds);
}

export async function clearLoginFailures(db: Db, email: string): Promise<void> {
  await reset(db, buckets.loginAccount(email));
}

export { TTL };
