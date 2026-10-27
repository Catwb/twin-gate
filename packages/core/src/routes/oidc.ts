import { Hono } from "hono";
import { z } from "zod";
import { Role, TTL } from "@sso/shared";
import type { Env } from "../types";
import { getDb } from "../db/client";
import { safeAudit } from "../services/audit";
import {
  consumeAuthorizationCode,
  consumeState,
  findApp,
  introspect,
  isPkceMethodAllowed,
  isRedirectUriAllowed,
  issueAccessToken,
  issueAuthorizationCode,
  parsePostLogoutRedirectUris,
  revokeToken,
  saveState,
  verifyClientSecret,
  verifyPkce,
} from "../services/oidc";
import {
  createApp,
  deleteApp,
  listApps,
  rotateClientSecret,
  updateApp,
} from "../services/apps";
import { activeKey, buildJwks, listSigningKeys, parseKeySet, syncSigningKeys } from "../services/signingKeys";
import { signJwt } from "../lib/jwt";
import { findUserById } from "../services/users";
import { listActiveSessions, listSessionsOfUser } from "../services/sessions-list";
import { PAGE_SIZE } from "@sso/shared";

type Variables = { db: ReturnType<typeof getDb> };

export const oidcRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

const callerSchema = z.object({
  userId: z.string().min(1),
  role: z.enum([Role.SuperAdmin, Role.Admin, Role.User]),
});

const envelopeSchema = z.object({
  caller: callerSchema.nullable().optional(),
  payload: z.unknown(),
});

function requireAdmin(role: string | null | undefined): boolean {
  return role === Role.SuperAdmin || role === Role.Admin;
}

// ---------------------------------------------------------------- JWKS

oidcRoutes.post("/jwks/build", async (c) => {
  const db = c.get("db");
  const jwks = await buildJwks(db, c.env.SIGNING_KEYS_JSON);
  // 分钟级缓存，不做小时级。
  c.header("cache-control", "public, max-age=300");
  return c.json(jwks);
});

oidcRoutes.post("/jwks/sync", async (c) => {
  const db = c.get("db");
  if (!c.env.SIGNING_KEYS_JSON) return c.json({ ok: false, code: "missing_signing_keys" }, 500);
  const set = parseKeySet(c.env.SIGNING_KEYS_JSON);
  await syncSigningKeys(db, set);
  return c.json({ ok: true, kid: activeKey(set).kid });
});

oidcRoutes.post("/keys/list", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (!requireAdmin(env.data.caller?.role)) return c.json({ ok: false, code: "forbidden" }, 403);

  const keys = await listSigningKeys(db);
  return c.json({ ok: true, keys });
});

// ---------------------------------------------------------------- clients

oidcRoutes.post("/client/list", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (!requireAdmin(env.data.caller?.role)) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z
    .object({ limit: z.number().int().min(1).max(PAGE_SIZE).default(PAGE_SIZE), offset: z.number().int().min(0).default(0) })
    .safeParse(env.data.payload ?? {});
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  return c.json({ ok: true, apps: await listApps(db, parsed.data.limit, parsed.data.offset) });
});

oidcRoutes.post("/client/create", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (env.data.caller?.role !== Role.SuperAdmin) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z
    .object({
      name: z.string().min(1).max(100),
      redirectUris: z.array(z.string().url()).min(1),
      postLogoutRedirectUris: z.array(z.string().url()).optional(),
    })
    .safeParse(env.data.payload);
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const created = await createApp(db, {
    name: parsed.data.name,
    redirectUris: parsed.data.redirectUris,
    ...(parsed.data.postLogoutRedirectUris ? { postLogoutRedirectUris: parsed.data.postLogoutRedirectUris } : {}),
  });

  await safeAudit(db, {
    action: "client_created",
    actorUserId: env.data.caller.userId,
    target: created.clientId,
    meta: { name: parsed.data.name },
  });

  // 明文 secret 只此一次返回。
  return c.json({ ok: true, clientId: created.clientId, clientSecret: created.clientSecret });
});

oidcRoutes.post("/client/update", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (env.data.caller?.role !== Role.SuperAdmin) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z
    .object({
      clientId: z.string().min(1),
      name: z.string().min(1).max(100).optional(),
      redirectUris: z.array(z.string().url()).min(1).optional(),
      postLogoutRedirectUris: z.array(z.string().url()).optional(),
    })
    .safeParse(env.data.payload);
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  await updateApp(db, parsed.data.clientId, {
    ...(parsed.data.name !== undefined ? { name: parsed.data.name } : {}),
    ...(parsed.data.redirectUris !== undefined ? { redirectUris: parsed.data.redirectUris } : {}),
    ...(parsed.data.postLogoutRedirectUris !== undefined
      ? { postLogoutRedirectUris: parsed.data.postLogoutRedirectUris }
      : {}),
  });
  return c.json({ ok: true });
});

oidcRoutes.post("/client/rotate-secret", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (env.data.caller?.role !== Role.SuperAdmin) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z.object({ clientId: z.string().min(1) }).safeParse(env.data.payload);
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const clientSecret = await rotateClientSecret(db, parsed.data.clientId);
  await safeAudit(db, {
    action: "client_secret_rotated",
    actorUserId: env.data.caller.userId,
    target: parsed.data.clientId,
  });
  return c.json({ ok: true, clientSecret });
});

oidcRoutes.post("/client/delete", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (env.data.caller?.role !== Role.SuperAdmin) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z.object({ clientId: z.string().min(1) }).safeParse(env.data.payload);
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  await deleteApp(db, parsed.data.clientId);
  await safeAudit(db, {
    action: "client_deleted",
    actorUserId: env.data.caller.userId,
    target: parsed.data.clientId,
  });
  return c.json({ ok: true });
});

// ---------------------------------------------------------------- authorize

const authorizeSchema = z.object({
  clientId: z.string().min(1),
  redirectUri: z.string().url(),
  state: z.string().min(1).max(512),
  nonce: z.string().max(512).optional().nullable(),
  codeChallenge: z.string().min(43).max(128),
  codeChallengeMethod: z.string().min(1),
  scope: z.string().min(1).max(200),
  userId: z.string().min(1),
});

oidcRoutes.post("/authorize/prepare", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const parsed = authorizeSchema.safeParse(env.data.payload);
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const app = await findApp(db, parsed.data.clientId);
  if (!app) return c.json({ ok: false, code: "unknown_client" }, 400);
  if (!isRedirectUriAllowed(app, parsed.data.redirectUri)) {
    return c.json({ ok: false, code: "invalid_redirect_uri" }, 400);
  }
  if (!isPkceMethodAllowed(parsed.data.codeChallengeMethod)) {
    return c.json({ ok: false, code: "pkce_method_not_allowed" }, 400);
  }

  await saveState(db, {
    state: parsed.data.state,
    nonce: parsed.data.nonce ?? null,
    redirectUri: parsed.data.redirectUri,
  });

  const issued = await issueAuthorizationCode(db, {
    clientId: parsed.data.clientId,
    userId: parsed.data.userId,
    redirectUri: parsed.data.redirectUri,
    codeChallenge: parsed.data.codeChallenge,
    codeChallengeMethod: parsed.data.codeChallengeMethod,
    nonce: parsed.data.nonce ?? null,
    scope: parsed.data.scope,
  });

  await safeAudit(db, {
    action: "authorization_code_issued",
    actorUserId: parsed.data.userId,
    target: parsed.data.clientId,
    meta: { scope: parsed.data.scope },
  });

  return c.json({ ok: true, code: issued.code, expiresAt: issued.expiresAt, state: parsed.data.state });
});

// ---------------------------------------------------------------- token

oidcRoutes.post("/token/exchange", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const parsed = z
    .object({
      clientId: z.string().min(1),
      clientSecret: z.string().min(1),
      code: z.string().min(1),
      redirectUri: z.string().url(),
      codeVerifier: z.string().min(43).max(128),
    })
    .safeParse((body as { payload?: unknown } | null)?.payload);
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const app = await verifyClientSecret(db, parsed.data.clientId, parsed.data.clientSecret);
  if (!app) return c.json({ ok: false, code: "invalid_client" }, 401);

  const codeRow = await consumeAuthorizationCode(db, parsed.data.code);
  if (!codeRow) return c.json({ ok: false, code: "invalid_grant" }, 400);

  if (codeRow.clientId !== app.clientId) return c.json({ ok: false, code: "invalid_grant" }, 400);
  if (codeRow.redirectUri !== parsed.data.redirectUri) return c.json({ ok: false, code: "invalid_grant" }, 400);
  if (!(await verifyPkce(codeRow.codeChallenge, parsed.data.codeVerifier))) {
    return c.json({ ok: false, code: "invalid_grant" }, 400);
  }

  const user = await findUserById(db, codeRow.userId);
  if (!user || user.status !== "active") return c.json({ ok: false, code: "invalid_grant" }, 400);

  const { sessions } = await import("../db/schema");
  const { and, eq, isNull } = await import("drizzle-orm");
  const sessionRows = await db
    .select({ id: sessions.id })
    .from(sessions)
    .where(and(eq(sessions.userId, user.id), isNull(sessions.revokedAt), eq(sessions.status, "active")))
    .limit(1);
  const sessionId = sessionRows[0]?.id ?? "";

  const accessToken = await issueAccessToken(db, {
    userId: user.id,
    clientId: app.clientId,
    sessionId,
    scope: codeRow.scope,
  });

  if (!c.env.SIGNING_KEYS_JSON) return c.json({ ok: false, code: "missing_signing_keys" }, 500);
  const key = activeKey(parseKeySet(c.env.SIGNING_KEYS_JSON));
  const now = Math.floor(Date.now() / 1000);

  const idToken = await signJwt(
    {
      iss: c.env.ISSUER ?? "",
      sub: user.id,
      aud: app.clientId,
      exp: now + TTL.accessToken,
      iat: now,
      // sid 现在用不上，但将来补 Back-channel Logout 时它是唯一能把
      // "哪个会话结束"告诉下游的东西。加它成本为零。
      sid: sessionId,
      ...(codeRow.nonce ? { nonce: codeRow.nonce } : {}),
      email: user.email,
      role: user.role,
    },
    key,
  );

  await safeAudit(db, {
    action: "token_issued",
    actorUserId: user.id,
    target: app.clientId,
    meta: { scope: codeRow.scope },
  });

  return c.json({
    ok: true,
    accessToken: accessToken.token,
    expiresIn: TTL.accessToken,
    idToken,
    tokenType: "Bearer",
    scope: codeRow.scope,
  });
});

// ---------------------------------------------------------------- introspection / revocation

oidcRoutes.post("/introspect", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const parsed = z
    .object({ clientId: z.string().min(1), clientSecret: z.string().min(1), token: z.string().min(1).max(512) })
    .safeParse((body as { payload?: unknown } | null)?.payload);
  if (!parsed.success) return c.json({ active: false });

  const app = await verifyClientSecret(db, parsed.data.clientId, parsed.data.clientSecret);
  if (!app) return c.json({ active: false });

  return c.json(await introspect(db, parsed.data.token));
});

oidcRoutes.post("/revoke", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const parsed = z
    .object({ clientId: z.string().min(1), clientSecret: z.string().min(1), token: z.string().min(1).max(512) })
    .safeParse((body as { payload?: unknown } | null)?.payload);
  // 无论 token 是否存在、客户端是否有效，都返回成功，避免被用来探测。
  if (!parsed.success) return c.json({ ok: true });

  const app = await verifyClientSecret(db, parsed.data.clientId, parsed.data.clientSecret);
  if (!app) return c.json({ ok: true });

  await revokeToken(db, parsed.data.token);
  return c.json({ ok: true });
});

// ---------------------------------------------------------------- userinfo

oidcRoutes.post("/userinfo", async (c) => {
  const db = c.get("db");
  const parsed = z
    .object({ token: z.string().min(1).max(512) })
    .safeParse((await c.req.json().catch(() => null) as { payload?: unknown } | null)?.payload);
  if (!parsed.success) return c.json({ ok: false, code: "invalid_token" }, 401);

  const result = await introspect(db, parsed.data.token);
  if (!result.active) return c.json({ ok: false, code: "invalid_token" }, 401);

  const user = await findUserById(db, result.sub);
  if (!user) return c.json({ ok: false, code: "invalid_token" }, 401);

  return c.json({
    ok: true,
    userinfo: {
      sub: user.id,
      email: user.email,
      role: user.role,
      scope: result.scope,
    },
  });
});

// ---------------------------------------------------------------- logout hint

oidcRoutes.post("/logout/validate", async (c) => {
  const db = c.get("db");
  const parsed = z
    .object({ clientId: z.string().min(1), postLogoutRedirectUri: z.string().url().optional().nullable() })
    .safeParse((await c.req.json().catch(() => null) as { payload?: unknown } | null)?.payload);
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const app = await findApp(db, parsed.data.clientId);
  if (!app) return c.json({ ok: false, code: "unknown_client" }, 400);

  if (!parsed.data.postLogoutRedirectUri) return c.json({ ok: true, redirect: null });
  const allowed = parsePostLogoutRedirectUris(app);
  if (!allowed.includes(parsed.data.postLogoutRedirectUri)) {
    return c.json({ ok: false, code: "invalid_post_logout_redirect_uri" }, 400);
  }
  return c.json({ ok: true, redirect: parsed.data.postLogoutRedirectUri });
});

// ---------------------------------------------------------------- sessions / users (admin)

oidcRoutes.post("/session/list", async (c) => {
  const db = c.get("db");
  const body = await c.req.json().catch(() => null);
  const env = envelopeSchema.safeParse(body);
  if (!env.success) return c.json({ ok: false, code: "bad_request" }, 400);
  if (!requireAdmin(env.data.caller?.role)) return c.json({ ok: false, code: "forbidden" }, 403);

  const parsed = z
    .object({
      limit: z.number().int().min(1).max(PAGE_SIZE).default(PAGE_SIZE),
      offset: z.number().int().min(0).default(0),
      userId: z.string().min(1).optional(),
    })
    .safeParse(env.data.payload ?? {});
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const sessions = parsed.data.userId
    ? await listSessionsOfUser(db, parsed.data.userId, parsed.data.limit)
    : await listActiveSessions(db, parsed.data.limit, parsed.data.offset);

  return c.json({ ok: true, sessions });
});

oidcRoutes.post("/state/consume", async (c) => {
  const db = c.get("db");
  const parsed = z
    .object({ state: z.string().min(1).max(512) })
    .safeParse((await c.req.json().catch(() => null) as { payload?: unknown } | null)?.payload);
  if (!parsed.success) return c.json({ ok: false, code: "bad_request" }, 400);

  const row = await consumeState(db, parsed.data.state);
  if (!row) return c.json({ ok: false, code: "invalid_state" }, 400);
  return c.json({ ok: true, nonce: row.nonce, redirectUri: row.redirectUri });
});