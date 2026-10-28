import { Hono } from "hono";
import { z } from "zod";
import { Role, SessionStatus } from "@sso/shared";
import type { Env } from "../types";
import { getDb } from "../db/client";
import { safeAudit } from "../services/audit";
import { createSession, revokeAllStatements, rotateSessionToken } from "../services/session";
import { findUserById, markLogin } from "../services/users";
import { createTotpFactor, hasTotpFactor, persistTotpFactor, verifyTotp } from "../services/totp";
import {
  buildRegistrationOptions,
  completeAuthentication,
  completeRegistration,
  hasPasskey,
  listPasskeys,
} from "../services/passkey";
import {
  consumeRecoveryCode,
  generateRecoveryCodes,
  remainingRecoveryCodes,
  revokeMfaStatements,
} from "../services/recovery";
import { buildAuthenticationOptionsForUser } from "../services/passkeyAuth";
import { deriveRpId, normalizeOrigin } from "../lib/webauthn-config";
import { uuid } from "../lib/crypto";

type Variables = { db: ReturnType<typeof getDb> };

export const mfaRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

const callerSchema = z.object({
  userId: z.string().min(1),
  role: z.enum([Role.SuperAdmin, Role.Admin, Role.User]),
});

const envelopeSchema = z.object({
  caller: callerSchema.nullable().optional(),
  payload: z.unknown(),
});

function payloadOf(body: unknown): unknown {
  const parsed = envelopeSchema.safeParse(body);
  return parsed.success ? parsed.data.payload : null;
}

function callerOf(body: unknown) {
  const parsed = envelopeSchema.safeParse(body);
  return parsed.success ? parsed.data.caller ?? null : null;
}

// ---------------------------------------------------------------- 状态

mfaRoutes.post("/mfa/status", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const parsed = z.object({ userId: z.string().min(1) }).safeParse(payloadOf(body));
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const [totp, passkey, remaining] = await Promise.all([
    hasTotpFactor(db, parsed.data.userId),
    hasPasskey(db, parsed.data.userId),
    remainingRecoveryCodes(db, parsed.data.userId),
  ]);

  const user = await findUserById(db, parsed.data.userId);
  return c.json({
    ok: true,
    totp,
    passkey,
    recoveryCodesRemaining: remaining,
    mustChangePassword: user?.mustChangePassword === 1,
    role: user?.role ?? null,
  });
});

// ---------------------------------------------------------------- TOTP 启用

mfaRoutes.post("/mfa/totp/begin", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const caller = callerOf(body);
  if (!caller) return c.json({ ok: false, code: "unauthorized" }, 401);

  const user = await findUserById(db, caller.userId);
  if (!user) return c.json({ ok: false, code: "unauthorized" }, 401);

  const enrolled = await createTotpFactor(db, {
    userId: user.id,
    accountName: user.email,
    issuer: c.env.ISSUER ?? "SSO",
  });

  // secret 未知化前先加密暂存到一个待验证因子中。
  // 这里用 pending 状态，未提交验证码前不计入 hasTotpFactor。
  await persistTotpFactorPending(db, {
    factorId: enrolled.factorId,
    userId: user.id,
    secret: enrolled.secret,
    masterKey: c.env.TOTP_MASTER_KEY,
  });

  return c.json({
    ok: true,
    factorId: enrolled.factorId,
    // 二维码在浏览器端渲染，不落存储、不落日志。
    otpauthUri: enrolled.uri,
  });
});

mfaRoutes.post("/mfa/totp/confirm", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const caller = callerOf(body);
  if (!caller) return c.json({ ok: false, code: "unauthorized" }, 401);

  // factorId 可选：启用流程天然只有一个待确认因子，
  // 但保留它以便将来支持多因子时精确定位。
  const parsed = z
    .object({ factorId: z.string().min(1).optional(), code: z.string().min(6).max(10) })
    .safeParse(payloadOf(body));
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const result = await verifyTotp(db, {
    userId: caller.userId,
    code: parsed.data.code,
    masterKey: c.env.TOTP_MASTER_KEY,
  });

  if (!result.ok) {
    const message =
      result.reason === "replayed"
        ? "该验证码已使用过"
        : result.reason === "no_factor"
          ? "没有待确认的验证器"
          : "验证码不正确";
    return c.json({ ok: false, code: result.reason, message }, 400);
  }

  await activateTotpFactor(db, caller.userId);
  const recovery = await generateRecoveryCodes(db, caller.userId);

  await safeAudit(db, {
    action: "mfa_totp_enabled",
    actorUserId: caller.userId,
    ip: c.req.header("x-caller-ip") ?? null,
  });

  // 恢复码只在启用时返回这一次。
  return c.json({ ok: true, recoveryCodes: recovery.codes });
});

// ---------------------------------------------------------------- TOTP 登录验证

mfaRoutes.post("/mfa/verify-totp", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const parsed = z
    .object({
      userId: z.string().min(1),
      code: z.string().min(6).max(10),
      sessionId: z.string().min(1),
      userAgent: z.string().max(200).optional(),
      ip: z.string().max(64).optional(),
    })
    .safeParse(payloadOf(body));
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const result = await verifyTotp(db, {
    userId: parsed.data.userId,
    code: parsed.data.code,
    masterKey: c.env.TOTP_MASTER_KEY,
  });

  if (!result.ok) {
    await safeAudit(db, {
      action: "mfa_verify_failed",
      actorUserId: parsed.data.userId,
      ip: parsed.data.ip ?? null,
      meta: { method: "totp", reason: result.reason },
    });
    return c.json({ ok: false, code: result.reason }, 401);
  }

  const user = await findUserById(db, parsed.data.userId);
  if (!user) return c.json({ ok: false, code: "unauthorized" }, 401);

  // MFA 升级必须轮换 token（防会话固定），但保留同一个 sessionId，
  // 这样审计与下游的会话标识不中断。
  const upgraded = await rotateSessionToken(db, parsed.data.sessionId, SessionStatus.Active);

  await markLogin(db, user.id);
  await safeAudit(db, { action: "mfa_verified", actorUserId: user.id, ip: parsed.data.ip ?? null, meta: { method: "totp" } });

  return c.json({
    ok: true,
    token: upgraded.token,
    expiresAt: upgraded.expiresAt,
    role: user.role,
    mustChangePassword: user.mustChangePassword === 1,
  });
});

mfaRoutes.post("/mfa/recovery/regenerate", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const caller = callerOf(body);
  if (!caller) return c.json({ ok: false, code: "unauthorized" }, 401);

  // 只有已启用 MFA 的账号才需要恢复码。
  const hasTotp = await hasTotpFactor(db, caller.userId);
  const hasPk = await hasPasskey(db, caller.userId);
  if (!hasTotp && !hasPk) return c.json({ ok: false, code: "no_mfa" }, 400);

  const generated = await generateRecoveryCodes(db, caller.userId);
  await safeAudit(db, {
    action: "mfa_recovery_regenerated",
    actorUserId: caller.userId,
    ip: c.req.header("x-caller-ip") ?? null,
  });

  return c.json({ ok: true, codes: generated.codes });
});

// ---------------------------------------------------------------- 恢复码

mfaRoutes.post("/mfa/verify-recovery", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const parsed = z
    .object({
      userId: z.string().min(1),
      code: z.string().min(4).max(32),
      sessionId: z.string().min(1),
    })
    .safeParse(payloadOf(body));
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const result = await consumeRecoveryCode(db, { userId: parsed.data.userId, code: parsed.data.code });
  if (!result.ok) return c.json({ ok: false, code: "invalid_recovery_code" }, 401);

  const user = await findUserById(db, parsed.data.userId);
  if (!user) return c.json({ ok: false, code: "unauthorized" }, 401);

  // 恢复码被使用 = 凭证可能已丢失，必须吊销其余会话。
  await db.batch([
    ...revokeAllStatements(db, { userId: user.id, reason: "recovery_code_used", keepSessionId: parsed.data.sessionId }),
  ]);

  const upgraded = await rotateSessionToken(db, parsed.data.sessionId, SessionStatus.Active);

  await markLogin(db, user.id);
  await safeAudit(db, {
    action: "mfa_recovery_used",
    actorUserId: user.id,
    ip: c.req.header("x-caller-ip") ?? null,
  });

  const remaining = await remainingRecoveryCodes(db, user.id);
  return c.json({
    ok: true,
    token: upgraded.token,
    expiresAt: upgraded.expiresAt,
    role: user.role,
    remaining,
  });
});

// ---------------------------------------------------------------- Passkey

// ---------------------------------------------------------------- 诊断

/**
 * 暴露 WebAuthn 的生效配置，用于排查 Passkey 绑定失败。
 * 只返回 origin 与 rpId —— 都是公开信息，不含任何 secret。
 */
mfaRoutes.post("/passkey/config", async (c) => {
  const origin = normalizeOrigin(c.env.ISSUER ?? "");
  const rpId = c.env.RP_ID?.trim() || deriveRpId(origin) || "localhost";
  const configuredRaw = { issuer: c.env.ISSUER ?? null, rpIdRaw: c.env.RP_ID ?? null };

  return c.json({
    ok: true,
    origin,
    rpId,
    configuredRaw,
    hints: [
      "浏览器地址栏的域名必须与 rpId 完全一致（或为其子域）",
      "expectedOrigin 必须等于浏览器报告的 origin（含协议与端口，不带路径）",
    ],
  });
});

/**
 * 生成 Passkey 注册选项，同时把预期挑战返回给前端。
 */
mfaRoutes.post("/passkey/register-options", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const caller = callerOf(body);
  if (!caller) return c.json({ ok: false, code: "unauthorized" }, 401);

  const user = await findUserById(db, caller.userId);
  if (!user) return c.json({ ok: false, code: "unauthorized" }, 401);

  const options = await buildRegistrationOptions(db, {
    userId: user.id,
    email: user.email,
    rpId: c.env.RP_ID?.trim() || deriveRpId(normalizeOrigin(c.env.ISSUER ?? "")) || "localhost",
    rpName: c.env.ISSUER ?? "SSO",
  });

  return c.json({ ok: true, options });
});

mfaRoutes.post("/passkey/register-verify", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const caller = callerOf(body);
  if (!caller) return c.json({ ok: false, code: "unauthorized" }, 401);

  const parsed = z
    .object({ response: z.unknown(), challenge: z.string().min(1) })
    .safeParse(payloadOf(body));
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const result = await completeRegistration(db, {
    userId: caller.userId,
    response: parsed.data.response as never,
    expectedChallenge: parsed.data.challenge,
    expectedOrigin: normalizeOrigin(c.env.ISSUER ?? ""),
    rpId: c.env.RP_ID?.trim() || deriveRpId(normalizeOrigin(c.env.ISSUER ?? "")) || "localhost",
  });

  if (!result.ok) {
    // detail 只在服务端日志与本次响应里出现，方便定位 rpID / origin 不匹配。
    return c.json({ ok: false, code: result.reason, detail: result.detail ?? null }, 400);
  }

  await safeAudit(db, {
    action: "passkey_registered",
    actorUserId: caller.userId,
    ip: c.req.header("x-caller-ip") ?? null,
  });

  return c.json({ ok: true, credentialId: result.credentialId });
});

mfaRoutes.post("/passkey/login-options", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const parsed = z
    .object({ userId: z.string().min(1).optional() })
    .safeParse(payloadOf(body) ?? {});
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const options = await buildAuthenticationOptionsForUser(db, {
    userId: parsed.data.userId ?? null,
    rpId: c.env.RP_ID?.trim() || deriveRpId(normalizeOrigin(c.env.ISSUER ?? "")) || "localhost",
  });

  return c.json({ ok: true, options });
});

mfaRoutes.post("/passkey/login-verify", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const parsed = z
    .object({
      response: z.unknown(),
      challenge: z.string().min(1),
      sessionId: z.string().optional(),
      userAgent: z.string().max(200).optional(),
      ip: z.string().max(64).optional(),
    })
    .safeParse(payloadOf(body));
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const result = await completeAuthentication(db, {
    response: parsed.data.response as never,
    expectedChallenge: parsed.data.challenge,
    expectedOrigin: normalizeOrigin(c.env.ISSUER ?? ""),
    rpId: c.env.RP_ID?.trim() || deriveRpId(normalizeOrigin(c.env.ISSUER ?? "")) || "localhost",
  });

  if (!result.ok) {
    await safeAudit(db, {
      action: "mfa_verify_failed",
      ip: parsed.data.ip ?? null,
      meta: { method: "passkey", reason: result.reason },
    });
    return c.json({ ok: false, code: result.reason, detail: result.detail ?? null }, 401);
  }

  const user = await findUserById(db, result.userId);
  if (!user || user.status !== "active") return c.json({ ok: false, code: "unauthorized" }, 401);

  const issued = await createSession(db, {
    userId: user.id,
    status: SessionStatus.Active,
    sessionId: parsed.data.sessionId,
    userAgent: parsed.data.userAgent ?? null,
    ip: parsed.data.ip ?? null,
  });

  await markLogin(db, user.id);
  await safeAudit(db, { action: "login_succeeded", actorUserId: user.id, ip: parsed.data.ip ?? null, meta: { method: "passkey" } });

  return c.json({
    ok: true,
    token: issued.token,
    expiresAt: issued.expiresAt,
    role: user.role,
    mustChangePassword: user.mustChangePassword === 1,
  });
});

// ---------------------------------------------------------------- 列表与重置

mfaRoutes.post("/mfa/factors", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const parsed = z.object({ userId: z.string().min(1) }).safeParse(payloadOf(body));
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const [passkeys, totp] = await Promise.all([
    listPasskeys(db, parsed.data.userId),
    hasTotpFactor(db, parsed.data.userId),
  ]);

  return c.json({ ok: true, passkeys, totp, recoveryCodesRemaining: await remainingRecoveryCodes(db, parsed.data.userId) });
});

mfaRoutes.post("/mfa/reset", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const caller = callerOf(body);
  if (caller?.role !== Role.SuperAdmin) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z.object({ userId: z.string().min(1) }).safeParse(payloadOf(body));
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  // 因子标记 revoked + 吊销全部会话与令牌，一次事务完成。
  await db.batch([
    ...revokeMfaStatements(db, parsed.data.userId),
    ...revokeAllStatements(db, { userId: parsed.data.userId, reason: "mfa_reset_by_admin" }),
  ]);

  await safeAudit(db, {
    action: "mfa_reset_by_admin",
    actorUserId: caller.userId,
    target: parsed.data.userId,
    ip: c.req.header("x-caller-ip") ?? null,
  });

  return c.json({ ok: true });
});

// ---------------------------------------------------------------- 内部辅助

async function persistTotpFactorPending(
  db: ReturnType<typeof getDb>,
  params: { factorId: string; userId: string; secret: string; masterKey: string },
): Promise<void> {
  const { encryptSecret } = await import("../lib/aes");
  const { mfaFactors } = await import("../db/schema");
  const encrypted = await encryptSecret(params.masterKey, params.secret);
  await db.insert(mfaFactors).values({
    id: params.factorId,
    userId: params.userId,
    factorType: "totp",
    secretCiphertext: encrypted.ciphertext,
    iv: encrypted.iv,
    keyVersion: encrypted.keyVersion,
    status: "pending",
    verifiedAt: null,
    createdAt: Math.floor(Date.now() / 1000),
  });
}

async function activateTotpFactor(db: ReturnType<typeof getDb>, userId: string): Promise<void> {
  const { mfaFactors } = await import("../db/schema");
  const { and, eq } = await import("drizzle-orm");
  await db
    .update(mfaFactors)
    .set({ status: "active", verifiedAt: Math.floor(Date.now() / 1000) })
    .where(and(eq(mfaFactors.userId, userId), eq(mfaFactors.factorType, "totp"), eq(mfaFactors.status, "pending")));
}

export { uuid, hasTotpFactor };