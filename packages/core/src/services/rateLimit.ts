import { and, eq, lte, sql } from "drizzle-orm";
import { INVITE_LIMIT, LOCKOUT, SECOND_FACTOR, TTL } from "@sso/shared";
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
 *   mfa:account:<userId>       第二因子失败（TOTP 与恢复码共用）
 *   passkey:ip:<ip>            Passkey 认证失败
 *   invite:ip:<ip>             邀请码接受
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
  mfaAccount: (userId: string) => `mfa:account:${userId}`,
  passkeyIp: (ip: string) => `passkey:ip:${ip}`,
  inviteIp: (ip: string) => `invite:ip:${ip}`,
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

// ------------------------------------------------------------ 第二因子

/**
 * 第二因子验证前的准入检查。
 *
 * 密码已经泄露时，第二因子是唯一防线；能无限次尝试的防线不是防线。
 * TOTP 与恢复码共享同一个账号桶 —— 否则攻击者只要换一种验证方式就能重置计数。
 */
export async function checkSecondFactorAllowed(db: Db, userId: string): Promise<boolean> {
  const failures = await peek(db, buckets.mfaAccount(userId), SECOND_FACTOR.perAccountSeconds);
  return failures < SECOND_FACTOR.perAccountFailures;
}

export async function recordSecondFactorFailure(db: Db, userId: string): Promise<void> {
  await consume(
    db,
    buckets.mfaAccount(userId),
    SECOND_FACTOR.perAccountFailures,
    SECOND_FACTOR.perAccountSeconds,
  );
}

export async function clearSecondFactorFailures(db: Db, userId: string): Promise<void> {
  await reset(db, buckets.mfaAccount(userId));
}

/** Passkey 认证前还没有身份上下文，只能按 IP 计。 */
export async function checkPasskeyIpAllowed(db: Db, ip: string): Promise<boolean> {
  const failures = await peek(db, buckets.passkeyIp(ip), SECOND_FACTOR.perIpSeconds);
  return failures < SECOND_FACTOR.perIpFailures;
}

export async function recordPasskeyIpFailure(db: Db, ip: string): Promise<void> {
  await consume(db, buckets.passkeyIp(ip), SECOND_FACTOR.perIpFailures, SECOND_FACTOR.perIpSeconds);
}

export async function clearPasskeyIpFailures(db: Db, ip: string): Promise<void> {
  await reset(db, buckets.passkeyIp(ip));
}

/**
 * 邀请码接受是匿名可访问的。邀请码本身 128 位熵不可暴力破解，
 * 但每次尝试都要算一次 SHA-256 并查库 —— 不限流就是免费的 D1 与 CPU 消耗。
 */
export async function checkInviteIpAllowed(db: Db, ip: string): Promise<boolean> {
  const failures = await peek(db, buckets.inviteIp(ip), INVITE_LIMIT.perIpSeconds);
  return failures < INVITE_LIMIT.perIpFailures;
}

export async function recordInviteIpFailure(db: Db, ip: string): Promise<void> {
  await consume(db, buckets.inviteIp(ip), INVITE_LIMIT.perIpFailures, INVITE_LIMIT.perIpSeconds);
}

export { TTL };
