import { and, eq, sql } from "drizzle-orm";
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
 * 固定窗口计数器，**单条 SQL 原子完成**。
 *
 * 这是全项目唯一的限流原语。所有「准入判定」都必须走它，
 * 不许再出现「先 peek 查一次、失败后再 consume 记一次」的写法 ——
 * 两步之间隔着 D1 读、HMAC 和另一次 D1 写，K 个并发请求会在首个写落库前
 * 全部读到旧计数而通过判定，阈值被并发数放大。
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

/** 只读查询当前窗口计数。**不得用于准入判定**，只用于展示与清理决策。 */
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

// ------------------------------------------------------------ 登录

export type LoginGate = {
  /** IP 维度超限：直接拒绝，不再验密。这是真正挡爆破的那道。 */
  ipBlocked: boolean;
  /** 账号维度超限：**只作信号，不阻断**。 */
  accountLocked: boolean;
};

/**
 * 登录准入。
 *
 * 关键设计：**账号桶不阻断登录**。
 *
 * 旧实现是「账号桶超限 → 验密之前直接 429」，于是任何人对任意已知邮箱
 * 每 15 分钟提交 10 次错误口令，就能让受害者连正确密码都进不去，
 * 而且全项目没有任何解除锁定的途径（clearLoginFailures 只在验密成功后调用，
 * 而锁定状态下永远到不了那一步）。
 *
 * 现在改成：
 *   - IP 桶 → 原子占位，超限即拒（同一来源的爆破仍然被挡住）
 *   - 账号桶 → 原子占位后只当信号，正确密码依然放行
 *
 * 代价：分布式多 IP 的慢速爆破不再被账号维度拦住。
 * 这是有意的取舍 —— 能锁死唯一超管的「防护」比不做防护更危险。
 */
export async function tryLogin(db: Db, email: string, ip: string): Promise<LoginGate> {
  const byIp = await consume(db, buckets.loginIp(ip), LOCKOUT.perIpFailures, LOCKOUT.perIpSeconds);
  const account = await consume(
    db,
    buckets.loginAccount(email),
    LOCKOUT.perAccountFailures,
    LOCKOUT.perAccountSeconds,
  );
  return { ipBlocked: !byIp.allowed, accountLocked: !account.allowed };
}

export async function clearLoginFailures(db: Db, email: string): Promise<void> {
  await reset(db, buckets.loginAccount(email));
}

// ------------------------------------------------------------ 第二因子

/**
 * 第二因子准入：同样原子占位。
 * TOTP 与恢复码共用同一个账号桶 —— 换验证方式不能重置计数。
 */
export async function trySecondFactor(db: Db, userId: string): Promise<boolean> {
  const result = await consume(
    db,
    buckets.mfaAccount(userId),
    SECOND_FACTOR.perAccountFailures,
    SECOND_FACTOR.perAccountSeconds,
  );
  return result.allowed;
}

export async function clearSecondFactorFailures(db: Db, userId: string): Promise<void> {
  await reset(db, buckets.mfaAccount(userId));
}

/** Passkey 认证前还没有身份上下文，只能按 IP 计。 */
export async function tryPasskeyIp(db: Db, ip: string): Promise<boolean> {
  const result = await consume(
    db,
    buckets.passkeyIp(ip),
    SECOND_FACTOR.perIpFailures,
    SECOND_FACTOR.perIpSeconds,
  );
  return result.allowed;
}

export async function clearPasskeyIpFailures(db: Db, ip: string): Promise<void> {
  await reset(db, buckets.passkeyIp(ip));
}

// ------------------------------------------------------------ 邀请码

/**
 * 邀请码接受是匿名可访问的。邀请码本身 128 位熵不可暴力破解，
 * 但每次尝试都要算一次 SHA-256 并查库 —— 不限流就是免费的 D1 与 CPU 消耗。
 */
export async function tryInviteIp(db: Db, ip: string): Promise<boolean> {
  const result = await consume(db, buckets.inviteIp(ip), INVITE_LIMIT.perIpFailures, INVITE_LIMIT.perIpSeconds);
  return result.allowed;
}

/** 邀请码用对之后清掉该 IP 的失败计数。 */
export async function clearInviteIpFailures(db: Db, ip: string): Promise<void> {
  await reset(db, buckets.inviteIp(ip));
}

export { TTL };
