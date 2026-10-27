import { and, eq, gt, isNull, lt } from "drizzle-orm";
import { TTL } from "@sso/shared";
import type { Db } from "../db/client";
import { accessTokens, apps, authorizationCodes, oidcStates } from "../db/schema";
import { randomHex, sha256Hex } from "../lib/crypto";
import { nowSeconds } from "../lib/time";

export type AppRecord = typeof apps.$inferSelect;

export async function findApp(db: Db, clientId: string): Promise<AppRecord | null> {
  const rows = await db.select().from(apps).where(eq(apps.clientId, clientId)).limit(1);
  return rows[0] ?? null;
}

export async function verifyClientSecret(
  db: Db,
  clientId: string,
  clientSecret: string,
): Promise<AppRecord | null> {
  const app = await findApp(db, clientId);
  if (!app) return null;
  const hash = await sha256Hex(clientSecret);
  if (hash !== app.clientSecretHash) return null;
  return app;
}

export function parseRedirectUris(app: AppRecord): string[] {
  try {
    const parsed = JSON.parse(app.redirectUris) as unknown;
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

export function parsePostLogoutRedirectUris(app: AppRecord): string[] {
  try {
    const parsed = JSON.parse(app.postLogoutRedirectUris) as unknown;
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

/** redirect_uri 必须精确匹配客户端注册值，否则就是开放重定向。 */
export function isRedirectUriAllowed(app: AppRecord, redirectUri: string): boolean {
  return parseRedirectUris(app).includes(redirectUri);
}

/** 只接受 S256。plain 一律拒绝。 */
export function isPkceMethodAllowed(method: string): boolean {
  return method === "S256";
}

export type IssuedCode = { code: string; expiresAt: number };

export async function issueAuthorizationCode(
  db: Db,
  params: {
    clientId: string;
    userId: string;
    redirectUri: string;
    codeChallenge: string;
    codeChallengeMethod: string;
    nonce: string | null;
    scope: string;
  },
): Promise<IssuedCode> {
  const code = randomHex(32);
  const codeHash = await sha256Hex(code);
  const now = nowSeconds();
  const expiresAt = now + TTL.authorizationCode;

  await db.insert(authorizationCodes).values({
    codeHash,
    clientId: params.clientId,
    userId: params.userId,
    redirectUri: params.redirectUri,
    codeChallenge: params.codeChallenge,
    codeChallengeMethod: params.codeChallengeMethod,
    nonce: params.nonce,
    scope: params.scope,
    expiresAt,
    createdAt: now,
  });

  return { code, expiresAt };
}

/**
 * 授权码单次使用：条件更新，以受影响行数判定成功。
 * 严禁先查后写 —— 那会产生重放窗口。
 */
export async function consumeAuthorizationCode(
  db: Db,
  code: string,
): Promise<typeof authorizationCodes.$inferSelect | null> {
  const codeHash = await sha256Hex(code);
  const now = nowSeconds();

  const updated = await db
    .update(authorizationCodes)
    .set({ usedAt: now })
    .where(
      and(
        eq(authorizationCodes.codeHash, codeHash),
        isNull(authorizationCodes.usedAt),
        gt(authorizationCodes.expiresAt, now),
      ),
    )
    .returning();

  return updated[0] ?? null;
}

/** PKCE 校验：S256(code_verifier) 必须等于存储的 code_challenge。 */
export async function verifyPkce(
  codeChallenge: string,
  codeVerifier: string,
): Promise<boolean> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  const computed = base64url(new Uint8Array(digest));
  return computed === codeChallenge;
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export type IssuedAccessToken = { token: string; expiresAt: number };

/** 访问令牌是不透明串 —— 这是"可即时吊销"的前提，绝不能用 JWT 替代。 */
export async function issueAccessToken(
  db: Db,
  params: { userId: string; clientId: string; sessionId: string; scope: string },
): Promise<IssuedAccessToken> {
  const token = randomHex(32);
  const tokenHash = await sha256Hex(token);
  const now = nowSeconds();
  const expiresAt = now + TTL.accessToken;

  await db.insert(accessTokens).values({
    tokenHash,
    userId: params.userId,
    clientId: params.clientId,
    sessionId: params.sessionId,
    scope: params.scope,
    expiresAt,
    createdAt: now,
  });

  return { token, expiresAt };
}

export type IntrospectionResult =
  | {
      active: true;
      scope: string;
      client_id: string;
      sub: string;
      exp: number;
      iat: number;
      token_type: "Bearer";
    }
  | { active: false };

/**
 * 内省必须查 D1 实时状态。
 * 任何"无效"情形都返回完全相同的 { active: false }，不泄露原因。
 */
export async function introspect(db: Db, token: string): Promise<IntrospectionResult> {
  const tokenHash = await sha256Hex(token);
  const now = nowSeconds();

  const rows = await db
    .select()
    .from(accessTokens)
    .where(eq(accessTokens.tokenHash, tokenHash))
    .limit(1);

  const row = rows[0];
  if (!row) return { active: false };
  if (row.revokedAt !== null) return { active: false };
  if (row.expiresAt <= now) return { active: false };

  // 令牌签发它的会话若已吊销，令牌也必须视为无效。
  const { sessions } = await import("../db/schema");
  const sessionRows = await db
    .select({ revokedAt: sessions.revokedAt, expiresAt: sessions.expiresAt })
    .from(sessions)
    .where(eq(sessions.id, row.sessionId))
    .limit(1);
  const session = sessionRows[0];
  if (!session || session.revokedAt !== null || session.expiresAt <= now) return { active: false };

  return {
    active: true,
    scope: row.scope,
    client_id: row.clientId,
    sub: row.userId,
    exp: row.expiresAt,
    iat: row.createdAt,
    token_type: "Bearer",
  };
}

/** 撤销令牌。不存在也返回成功，避免被用来探测。 */
export async function revokeToken(db: Db, token: string): Promise<void> {
  const tokenHash = await sha256Hex(token);
  await db
    .update(accessTokens)
    .set({ revokedAt: nowSeconds() })
    .where(and(eq(accessTokens.tokenHash, tokenHash), isNull(accessTokens.revokedAt)));
}

export type StateRecord = typeof oidcStates.$inferSelect;

export async function saveState(
  db: Db,
  params: { state: string; nonce: string | null; redirectUri: string },
): Promise<void> {
  const stateHash = await sha256Hex(params.state);
  const now = nowSeconds();
  await db.insert(oidcStates).values({
    stateHash,
    nonce: params.nonce,
    redirectUri: params.redirectUri,
    expiresAt: now + 600,
    createdAt: now,
  });
}

export async function consumeState(db: Db, state: string): Promise<StateRecord | null> {
  const stateHash = await sha256Hex(state);
  const now = nowSeconds();
  const rows = await db
    .select()
    .from(oidcStates)
    .where(and(eq(oidcStates.stateHash, stateHash), gt(oidcStates.expiresAt, now)))
    .limit(1);
  const row = rows[0];
  if (!row) return null;
  await db.delete(oidcStates).where(eq(oidcStates.stateHash, stateHash));
  return row;
}

export { lt };
