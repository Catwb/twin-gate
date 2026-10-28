import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransport,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { and, eq, gt, isNull, lt } from "drizzle-orm";
import { TTL } from "@sso/shared";
import type { Db } from "../db/client";
import { mfaFactors, passkeyChallenges, passkeys } from "../db/schema";
import { uuid } from "../lib/crypto";
import { nowSeconds } from "../lib/time";

export type PasskeyRecord = typeof passkeys.$inferSelect;

export async function listPasskeys(db: Db, userId: string) {
  return db
    .select({
      id: passkeys.id,
      credentialId: passkeys.credentialId,
      deviceType: passkeys.deviceType,
      backedUp: passkeys.backedUp,
      createdAt: passkeys.createdAt,
      revokedAt: passkeys.revokedAt,
    })
    .from(passkeys)
    .where(and(eq(passkeys.userId, userId), isNull(passkeys.revokedAt)));
}

/**
 * 按 credential_id 全局反查。
 *
 * 这是全项目唯一一处不带 tenant / user 上下文的查询 ——
 * 认证时用户尚未识别，只能先凭凭证找到人。
 * 命中后调用方必须立刻校验凭证归属，不可跳过。
 */
export async function findPasskeyByCredential(db: Db, credentialId: string): Promise<PasskeyRecord | null> {
  const rows = await db
    .select()
    .from(passkeys)
    .where(and(eq(passkeys.credentialId, credentialId), isNull(passkeys.revokedAt)))
    .limit(1);
  return rows[0] ?? null;
}

export async function saveChallenge(
  db: Db,
  params: { userId: string | null; challenge: string; type: "register" | "login" },
): Promise<string> {
  const id = uuid();
  const now = nowSeconds();
  await db.insert(passkeyChallenges).values({
    id,
    userId: params.userId,
    challenge: params.challenge,
    type: params.type,
    expiresAt: now + TTL.webauthnChallenge,
    createdAt: now,
  });
  return id;
}

export async function consumeChallenge(
  db: Db,
  params: { challenge: string; type: "register" | "login" },
): Promise<boolean> {
  const now = nowSeconds();
  const updated = await db
    .update(passkeyChallenges)
    .set({ consumedAt: now })
    .where(
      and(
        eq(passkeyChallenges.challenge, params.challenge),
        eq(passkeyChallenges.type, params.type),
        isNull(passkeyChallenges.consumedAt),
        gt(passkeyChallenges.expiresAt, now),
      ),
    )
    .returning({ id: passkeyChallenges.id });
  return updated.length > 0;
}

/** 每次 Passkey 请求前清掉该用户的过期 challenge，防止表无限增长。 */
export async function lazyCleanupChallenges(db: Db, userId: string): Promise<void> {
  const now = nowSeconds();
  await db
    .delete(passkeyChallenges)
    .where(and(eq(passkeyChallenges.userId, userId), lt(passkeyChallenges.expiresAt, now)));
}

/**
 * 免用户名登录时 user_id 是 NULL，按 user_id 过滤的清理永远碰不到这些行。
 * 这条按 expires_at 全局清，量级由 cron 的批次上限兜住。
 */
export async function lazyCleanupExpiredChallenges(db: Db): Promise<void> {
  await db.delete(passkeyChallenges).where(lt(passkeyChallenges.expiresAt, nowSeconds()));
}

export type RegistrationOptions = Awaited<ReturnType<typeof generateRegistrationOptions>>;

export async function buildRegistrationOptions(
  db: Db,
  params: { userId: string; email: string; rpId: string; rpName: string },
): Promise<RegistrationOptions> {
  await lazyCleanupChallenges(db, params.userId);

  const existing = await listPasskeys(db, params.userId);
  const options = await generateRegistrationOptions({
    rpID: params.rpId,
    // rpName 是显示在系统弹窗里的名字，不能是 URL。
    // 调用方传进来的可能是 ISSUER（https://...），这里兜底成域名或固定名。
    rpName: normalizeRpName(params.rpName),
    userID: encodeUserId(params.userId),
    userName: params.email,
    attestationType: "none",
    // 必须可发现凭证，否则无法做无用户名登录。
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
    },
    excludeCredentials: existing.map((item) => ({
      id: item.credentialId,
      transports: undefined,
    })),
  });

  await saveChallenge(db, { userId: params.userId, challenge: options.challenge, type: "register" });
  return options;
}

export type VerifiedRegistration =
  | { ok: true; credentialId: string }
  | { ok: false; reason: "invalid_challenge" | "verification_failed"; detail?: string };

export async function completeRegistration(
  db: Db,
  params: {
    userId: string;
    response: RegistrationResponseJSON;
    expectedChallenge: string;
    expectedOrigin: string;
    rpId: string;
  },
): Promise<VerifiedRegistration> {
  const challengeOk = await consumeChallenge(db, { challenge: params.expectedChallenge, type: "register" });
  if (!challengeOk) return { ok: false, reason: "invalid_challenge" };

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: params.response,
      expectedChallenge: params.expectedChallenge,
      expectedOrigin: params.expectedOrigin,
      expectedRPID: params.rpId,
      requireUserVerification: true,
    });
  } catch (error) {
    // 把原始错误带出去 —— 之前只返回 verification_failed，
    // 线上排查时完全看不出是 rpID 不匹配、origin 不匹配还是 attestation 解析失败。
    const detail = error instanceof Error ? error.message : String(error);
    console.error("[passkey] 注册验证失败:", detail);
    return { ok: false, reason: "verification_failed", detail };
  }

  if (!verification.verified || !verification.registrationInfo) {
    return { ok: false, reason: "verification_failed" };
  }

  const { credential } = verification.registrationInfo;
  const now = nowSeconds();

  await db.insert(passkeys).values({
    id: uuid(),
    userId: params.userId,
    credentialId: credential.id,
    publicKey: base64urlFromBytes(new Uint8Array(credential.publicKey)),
    counter: credential.counter,
    deviceType: verification.registrationInfo.credentialDeviceType,
    backedUp: verification.registrationInfo.credentialBackedUp ? 1 : 0,
    transports: credential.transports ? JSON.stringify(credential.transports) : null,
    createdAt: now,
  });

  return { ok: true, credentialId: credential.id };
}

export type VerifiedAuthentication =
  | { ok: true; userId: string }
  | {
      ok: false;
      reason: "not_found" | "invalid_challenge" | "verification_failed" | "counter_regression";
      detail?: string;
    };

export async function completeAuthentication(
  db: Db,
  params: {
    response: AuthenticationResponseJSON;
    expectedChallenge: string;
    expectedOrigin: string;
    rpId: string;
  },
): Promise<VerifiedAuthentication> {
  const record = await findPasskeyByCredential(db, params.response.id);
  if (!record) return { ok: false, reason: "not_found" };

  const challengeOk = await consumeChallenge(db, { challenge: params.expectedChallenge, type: "login" });
  if (!challengeOk) return { ok: false, reason: "invalid_challenge" };

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: params.response,
      expectedChallenge: params.expectedChallenge,
      expectedOrigin: params.expectedOrigin,
      expectedRPID: params.rpId,
      requireUserVerification: true,
      credential: {
        id: record.credentialId,
        publicKey: bytesFromBase64url(record.publicKey),
        counter: record.counter,
        transports: record.transports
          ? (JSON.parse(record.transports) as AuthenticatorTransport[])
          : undefined,
      },
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    console.error("[passkey] 认证验证失败:", detail);
    return { ok: false, reason: "verification_failed", detail };
  }

  if (!verification.verified) return { ok: false, reason: "verification_failed" };

  // counter 更新是克隆检测的基础：不更新就等于放弃这层防护。
  const newCounter = verification.authenticationInfo.newCounter;
  await db
    .update(passkeys)
    .set({ counter: newCounter })
    .where(eq(passkeys.id, record.id));

  return { ok: true, userId: record.userId };
}

/**
 * rpName 会直接显示在系统的通行密钥弹窗里（"X 想要创建通行密钥"）。
 * 传 URL 过去用户会看到一串网址，很难辨认。
 */
function normalizeRpName(raw: string): string {
  const value = raw.trim();
  if (!value) return "SSO";
  // 是 URL 就取域名
  if (/^https?:\/\//i.test(value)) {
    try {
      return new URL(value).hostname;
    } catch {
      return "SSO";
    }
  }
  return value;
}

// ---- 编解码 ----

/** 显式分配 ArrayBuffer，避免 Uint8Array<ArrayBufferLike> 与 WebAuthn 类型不匹配。 */
function encodeUserId(userId: string): Uint8Array<ArrayBuffer> {
  const encoded = new TextEncoder().encode(userId);
  const buffer = new ArrayBuffer(encoded.byteLength);
  const bytes = new Uint8Array(buffer);
  bytes.set(encoded);
  return bytes;
}

function base64urlFromBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function bytesFromBase64url(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export async function hasPasskey(db: Db, userId: string): Promise<boolean> {
  const rows = await db
    .select({ id: passkeys.id })
    .from(passkeys)
    .where(and(eq(passkeys.userId, userId), isNull(passkeys.revokedAt)))
    .limit(1);
  return rows.length > 0;
}

export { mfaFactors };