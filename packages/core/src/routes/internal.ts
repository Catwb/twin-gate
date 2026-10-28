import { Hono } from "hono";
import { eq } from "drizzle-orm";
import { z } from "zod";
import { PAGE_SIZE, Role, SessionStatus, TTL } from "@sso/shared";
import type { Env } from "../types";
import { getDb } from "../db/client";
import { safeAudit } from "../services/audit";
import { checkPasswordPolicy, dummyVerify, makePasswordHash, verifyPassword } from "../services/password";
import { buckets, checkLoginAllowed, clearLoginFailures, consume, recordLoginFailure } from "../services/rateLimit";
import {
  createSession,
  lookupSession,
  revokeAllStatements,
  revokeOneSessionStatements,
  touchSession,
} from "../services/session";
import {
  activeSuperAdminCount,
  findUserByEmail,
  findUserById,
  insertUser,
  listUsers,
  markLogin,
  roleOf,
  setUserRole,
  setUserStatus,
} from "../services/users";
import { consumeInvitation, createInvitation, listInvitations, revokeInvitation } from "../services/invitations";
import { uuid } from "../lib/crypto";

/**
 * Core 只暴露具名方法。
 * 全项目禁止出现任何形如 { sql, params } 的透传接口 —— 那会让双 Worker 隔离归零。
 */
export const internalRoutes = new Hono<{ Bindings: Env; Variables: { db: ReturnType<typeof getDb> } }>();

const emailSchema = z.string().email().max(254);
const passwordSchema = z.string().min(1).max(256);
const callerSchema = z.object({
  userId: z.string().min(1),
  role: z.enum([Role.SuperAdmin, Role.Admin, Role.User]),
});
const envelopeSchema = z.object({
  caller: callerSchema.nullable().optional(),
  payload: z.unknown(),
});

function parseEnvelope<T extends z.ZodTypeAny>(schema: T) {
  return (body: unknown): z.infer<T> | null => {
    const env = envelopeSchema.safeParse(body);
    if (!env.success) return null;
    const inner = schema.safeParse(env.data.payload);
    if (!inner.success) return null;
    return inner.data;
  };
}

/** 仅管理员以上可调用的接口，统一在这里校验角色。 */
function requireAdmin(role: string | null): boolean {
  return role === Role.SuperAdmin || role === Role.Admin;
}

internalRoutes.get("/health", (c) => c.json({ ok: true }));

/** 从 envelope 里取 payload，供内联 zod 校验使用。 */
function parsedEnvelopePayload(body: unknown): unknown {
  const env = envelopeSchema.safeParse(body);
  return env.success ? env.data.payload : null;
}

internalRoutes.post("/auth/login", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const parsed = parseEnvelope(z.object({ email: emailSchema, password: passwordSchema }))(body);
  if (!parsed) return c.json({ ok: false, code: "bad_request" }, 400);

  const email = parsed.email.toLowerCase();
  const ip = (c.req.header("x-caller-ip") ?? "0.0.0.0").slice(0, 64);

  if (!(await checkLoginAllowed(db, email, ip))) {
    await safeAudit(db, { action: "login_locked", target: email, ip });
    return c.json({ ok: false, code: "locked" }, 429);
  }

  const user = await findUserByEmail(db, email);
  if (!user) {
    // 用户不存在时也走一次完整 HMAC，保持耗时一致，防止用户名枚举。
    await dummyVerify(c.env.SESSION_PEPPER, parsed.password);
    await recordLoginFailure(db, email, ip);
    await safeAudit(db, { action: "login_failed", target: email, ip, meta: { reason: "no_user" } });
    return c.json({ ok: false, code: "invalid_credentials" }, 401);
  }

  const passwordOk = await verifyPassword(c.env.SESSION_PEPPER, parsed.password, user.passwordHash);
  if (!passwordOk) {
    await recordLoginFailure(db, email, ip);
    await safeAudit(db, { action: "login_failed", target: email, ip, meta: { reason: "bad_password" } });
    return c.json({ ok: false, code: "invalid_credentials" }, 401);
  }

  await clearLoginFailures(db, email);

  const hasMfa = await hasActiveMfaFactor(db, user.id);
  const status = hasMfa ? SessionStatus.MfaPending : SessionStatus.Active;
  const issued = await createSession(db, {
    userId: user.id,
    status,
    userAgent: (c.req.header("x-caller-ua") ?? "").slice(0, 200) || null,
    ip,
  });

  await safeAudit(db, {
    action: status === SessionStatus.Active ? "login_succeeded" : "login_mfa_pending",
    actorUserId: user.id,
    ip,
  });

  if (status === SessionStatus.Active) await markLogin(db, user.id);

  return c.json({
    ok: true,
    sessionId: issued.sessionId,
    token: issued.token,
    expiresAt: issued.expiresAt,
    status,
    role: user.role,
    mustChangePassword: user.mustChangePassword === 1,
  });
});

internalRoutes.post("/session/lookup", async (c) => {
  const db = c.get("db");
  const parsed = parseEnvelope(z.object({ token: z.string().min(1).max(200) }))(
    await c.req.json().catch(() => null),
  );
  if (!parsed) return c.json({ ok: false, code: "bad_request" }, 400);

  const result = await lookupSession(db, parsed.token, async (userId) => {
    const user = await findUserById(db, userId);
    return user ? (user.role as Role) : null;
  });

  if (!result.valid) return c.json({ ok: true, valid: false, reason: result.reason });
  return c.json({ ok: true, valid: true, sessionId: result.sessionId, userId: result.userId, role: result.role });
});

/**
 * 仅供 MFA 升级流程使用：返回 mfa_pending 状态的会话。
 * 与 /session/lookup 的区别是它不拒绝 mfa_pending ——
 * 但正因为如此，调用方（Gateway）只能用它来推进 MFA，不能用于鉴权。
 */
internalRoutes.post("/session/lookup-pending", async (c) => {
  const db = c.get("db");
  const parsed = parseEnvelope(z.object({ token: z.string().min(1).max(200) }))(
    await c.req.json().catch(() => null),
  );
  if (!parsed) return c.json({ ok: false, code: "bad_request" }, 400);

  const { sessions } = await import("../db/schema");
  const { sha256Hex } = await import("../lib/crypto");
  const { nowSeconds } = await import("../lib/time");

  const tokenHash = await sha256Hex(parsed.token);
  const rows = await db.select().from(sessions).where(eq(sessions.tokenHash, tokenHash)).limit(1);
  const row = rows[0];

  if (!row) return c.json({ ok: true, valid: false });
  if (row.revokedAt !== null) return c.json({ ok: true, valid: false });
  if (row.expiresAt <= nowSeconds()) return c.json({ ok: true, valid: false });
  if (row.status !== SessionStatus.MfaPending) return c.json({ ok: true, valid: false });

  return c.json({ ok: true, valid: true, sessionId: row.id, userId: row.userId, status: row.status });
});

internalRoutes.post("/session/revoke", async (c) => {
  const db = c.get("db");
  const parsed = parseEnvelope(z.object({ sessionId: z.string().min(1), reason: z.string().max(64) }))(
    await c.req.json().catch(() => null),
  );
  if (!parsed) return c.json({ ok: false, code: "bad_request" }, 400);

  await db.batch([...revokeOneSessionStatements(db, parsed.sessionId, parsed.reason)]);
  return c.json({ ok: true });
});

internalRoutes.post("/session/touch", async (c) => {
  const db = c.get("db");
  const parsed = parseEnvelope(z.object({ sessionId: z.string().min(1) }))(
    await c.req.json().catch(() => null),
  );
  if (!parsed) return c.json({ ok: false, code: "bad_request" }, 400);
  await touchSession(db, parsed.sessionId);
  return c.json({ ok: true });
});

internalRoutes.post("/user/revoke-all", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  const parsed = z
    .object({ userId: z.string().min(1), reason: z.string().max(64) })
    .safeParse(env.data.payload);
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  await db.batch([...revokeAllStatements(db, { userId: parsed.data.userId, reason: parsed.data.reason })]);
  return c.json({ ok: true });
});

internalRoutes.post("/user/list", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (!requireAdmin(env.data.caller?.role ?? null)) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z
    .object({ limit: z.number().int().min(1).max(PAGE_SIZE).default(PAGE_SIZE), offset: z.number().int().min(0).default(0) })
    .safeParse(env.data.payload ?? {});
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const rows = await listUsers(db, parsed.data.limit, parsed.data.offset);
  return c.json({ ok: true, users: rows });
});

internalRoutes.post("/user/create", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (!requireAdmin(env.data.caller?.role ?? null)) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z
    .object({
      email: emailSchema,
      password: passwordSchema,
      role: z.enum([Role.SuperAdmin, Role.Admin, Role.User]),
      mustChangePassword: z.boolean().default(true),
    })
    .safeParse(env.data.payload);
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const policy = checkPasswordPolicy(parsed.data.password);
  if (!policy.ok) return c.json({ ok: false, code: "weak_password", message: policy.reason }, 400);

  const existing = await findUserByEmail(db, parsed.data.email);
  if (existing) return c.json({ ok: false, code: "email_taken" }, 409);

  const passwordHash = await makePasswordHash(c.env.SESSION_PEPPER, parsed.data.password);
  const id = uuid();
  await insertUser(db, {
    id,
    email: parsed.data.email,
    passwordHash,
    role: parsed.data.role,
    mustChangePassword: parsed.data.mustChangePassword,
  });
  await safeAudit(db, {
    action: "user_created",
    actorUserId: env.data.caller?.userId ?? null,
    target: parsed.data.email,
  });
  return c.json({ ok: true, userId: id });
});

internalRoutes.post("/user/change-password", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const parsed = z
    .object({
      userId: z.string().min(1),
      currentPassword: z.string().min(1).max(256),
      newPassword: z.string().min(1).max(256),
    })
    .safeParse(parsedEnvelopePayload(body));
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const policy = checkPasswordPolicy(parsed.data.newPassword);
  if (!policy.ok) return c.json({ ok: false, code: "weak_password", message: policy.reason }, 400);

  if (parsed.data.currentPassword === parsed.data.newPassword) {
    return c.json({ ok: false, code: "same_password", message: "新密码不能与当前密码相同" }, 400);
  }

  const user = await findUserById(db, parsed.data.userId);
  if (!user) return c.json({ ok: false, code: "unauthorized" }, 401);

  const ok = await verifyPassword(c.env.SESSION_PEPPER, parsed.data.currentPassword, user.passwordHash);
  if (!ok) return c.json({ ok: false, code: "invalid_credentials" }, 401);

  const passwordHash = await makePasswordHash(c.env.SESSION_PEPPER, parsed.data.newPassword);
  await db
    .update((await import("../db/schema")).users)
    .set({ passwordHash, mustChangePassword: 0 })
    .where(eq((await import("../db/schema")).users.id, user.id));

  // 改密后吊销其它会话（保留当前这条由 Gateway 侧决定）
  await db.batch([...revokeAllStatements(db, { userId: user.id, reason: "password_changed" })]);

  await safeAudit(db, {
    action: "password_changed",
    actorUserId: user.id,
    ip: c.req.header("x-caller-ip") ?? null,
  });

  return c.json({ ok: true });
});
internalRoutes.post("/user/set-status", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (!requireAdmin(env.data.caller?.role ?? null)) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z
    .object({ userId: z.string().min(1), status: z.enum(["active", "disabled"]) })
    .safeParse(env.data.payload);
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  await setUserStatus(db, parsed.data.userId, parsed.data.status);
  if (parsed.data.status === "disabled") {
    await db.batch([...revokeAllStatements(db, { userId: parsed.data.userId, reason: "disabled" })]);
  }
  await safeAudit(db, {
    action: "user_status_changed",
    actorUserId: env.data.caller?.userId ?? null,
    target: parsed.data.userId,
    meta: { status: parsed.data.status },
  });
  return c.json({ ok: true });
});

internalRoutes.post("/user/set-role", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (env.data.caller?.role !== Role.SuperAdmin) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z
    .object({ userId: z.string().min(1), role: z.enum([Role.SuperAdmin, Role.Admin, Role.User]) })
    .safeParse(env.data.payload);
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  // 降级最后一个超管会让系统失去管理入口，直接拒绝。
  if (parsed.data.role !== Role.SuperAdmin) {
    const current = await findUserById(db, parsed.data.userId);
    if (current?.role === Role.SuperAdmin) {
      const count = await activeSuperAdminCount(db);
      if (count <= 1) return c.json({ ok: false, code: "last_super_admin" }, 409);
    }
  }

  await setUserRole(db, parsed.data.userId, parsed.data.role);
  await safeAudit(db, {
    action: "user_role_changed",
    actorUserId: env.data.caller?.userId ?? null,
    target: parsed.data.userId,
    meta: { role: parsed.data.role },
  });
  return c.json({ ok: true });
});

internalRoutes.post("/invite/create", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (!requireAdmin(env.data.caller?.role ?? null)) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z
    .object({
      email: emailSchema.optional().nullable(),
      role: z.enum([Role.Admin, Role.User]).default(Role.User),
    })
    .safeParse(env.data.payload ?? {});
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const created = await createInvitation(db, {
    email: parsed.data.email ?? null,
    role: parsed.data.role,
    createdBy: env.data.caller!.userId,
    ttlSeconds: TTL.invitation,
  });
  await safeAudit(db, {
    action: "invite_created",
    actorUserId: env.data.caller?.userId ?? null,
    target: created.id,
    meta: { role: parsed.data.role, email: parsed.data.email ?? null },
  });
  // 明文邀请码只在此响应里出现一次。
  return c.json({ ok: true, id: created.id, code: created.code, expiresAt: created.expiresAt });
});

internalRoutes.post("/invite/list", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (!requireAdmin(env.data.caller?.role ?? null)) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z
    .object({ limit: z.number().int().min(1).max(PAGE_SIZE).default(PAGE_SIZE), offset: z.number().int().min(0).default(0) })
    .safeParse(env.data.payload ?? {});
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  return c.json({ ok: true, invitations: await listInvitations(db, parsed.data.limit, parsed.data.offset) });
});

internalRoutes.post("/invite/revoke", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (!requireAdmin(env.data.caller?.role ?? null)) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z.object({ id: z.string().min(1) }).safeParse(env.data.payload);
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  await revokeInvitation(db, parsed.data.id);
  await safeAudit(db, {
    action: "invite_revoked",
    actorUserId: env.data.caller?.userId ?? null,
    target: parsed.data.id,
  });
  return c.json({ ok: true });
});

internalRoutes.post("/invite/accept", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const parsed = z
    .object({ code: z.string().min(1).max(200), email: emailSchema, password: passwordSchema })
    .safeParse(env.data.payload);
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const policy = checkPasswordPolicy(parsed.data.password);
  if (!policy.ok) return c.json({ ok: false, code: "weak_password", message: policy.reason }, 400);

  const consumed = await consumeInvitation(db, parsed.data.code);
  if (!consumed.ok) return c.json({ ok: false, code: "invalid_invite" }, 400);

  // 邀请码若绑定了邮箱，必须一致。
  if (consumed.invitation.email && consumed.invitation.email !== parsed.data.email.toLowerCase()) {
    return c.json({ ok: false, code: "invalid_invite" }, 400);
  }

  const existing = await findUserByEmail(db, parsed.data.email);
  if (existing) return c.json({ ok: false, code: "email_taken" }, 409);

  const passwordHash = await makePasswordHash(c.env.SESSION_PEPPER, parsed.data.password);
  const id = uuid();
  await insertUser(db, {
    id,
    email: parsed.data.email,
    passwordHash,
    role: consumed.invitation.role as Role,
    mustChangePassword: false,
  });
  await safeAudit(db, { action: "invite_accepted", actorUserId: id, target: parsed.data.email });

  return c.json({ ok: true, userId: id });
});

internalRoutes.post("/audit/list", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (!requireAdmin(env.data.caller?.role ?? null)) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z
    .object({ limit: z.number().int().min(1).max(PAGE_SIZE).default(PAGE_SIZE), offset: z.number().int().min(0).default(0) })
    .safeParse(env.data.payload ?? {});
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const { auditLogs } = await import("../db/schema");
  const rows = await db
    .select()
    .from(auditLogs)
    .orderBy(auditLogs.createdAt)
    .limit(parsed.data.limit)
    .offset(parsed.data.offset);
  return c.json({ ok: true, logs: rows });
});

async function hasActiveMfaFactor(db: ReturnType<typeof getDb>, userId: string): Promise<boolean> {
  const { mfaFactors } = await import("../db/schema");
  const { and, eq, isNull } = await import("drizzle-orm");
  const rows = await db
    .select({ id: mfaFactors.id })
    .from(mfaFactors)
    .where(and(eq(mfaFactors.userId, userId), eq(mfaFactors.status, "active"), isNull(mfaFactors.revokedAt)))
    .limit(1);
  return rows.length > 0;
}