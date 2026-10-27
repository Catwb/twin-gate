import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

/**
 * 时间统一用 INTEGER（Unix 秒），比较与索引都最省。
 * 十六进制/哈希统一用 TEXT。
 */

export const users = sqliteTable(
  "users",
  {
    id: text("id").primaryKey(),
    email: text("email").notNull(),
    /** HMAC-SHA256(SESSION_PEPPER, 明文密码)。绝不存明文，也绝不存可逆密文。 */
    passwordHash: text("password_hash").notNull(),
    role: text("role").notNull(),
    status: text("status").notNull().default("active"),
    mustChangePassword: integer("must_change_password").notNull().default(0),
    mfaResetAt: integer("mfa_reset_at"),
    lastLoginAt: integer("last_login_at"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [uniqueIndex("idx_users_email").on(t.email)],
);

export const sessions = sqliteTable(
  "sessions",
  {
    /** 稳定 UUID。MFA 升级与改密会轮换 token，但 id 不变，下游关联不断。 */
    id: text("id").primaryKey(),
    tokenHash: text("token_hash").notNull(),
    userId: text("user_id").notNull(),
    status: text("status").notNull(),
    expiresAt: integer("expires_at").notNull(),
    createdAt: integer("created_at").notNull(),
    revokedAt: integer("revoked_at"),
    revokeReason: text("revoke_reason"),
    lastUsedAt: integer("last_used_at"),
    userAgent: text("user_agent"),
    ip: text("ip"),
  },
  (t) => [
    uniqueIndex("idx_sessions_token").on(t.tokenHash),
    index("idx_sessions_user").on(t.userId),
    index("idx_sessions_expires").on(t.expiresAt),
  ],
);

export const accessTokens = sqliteTable(
  "access_tokens",
  {
    tokenHash: text("token_hash").primaryKey(),
    userId: text("user_id").notNull(),
    clientId: text("client_id").notNull(),
    /** 关联签发它的 SSO 会话：会话被吊销时，其签出的令牌一并失效。 */
    sessionId: text("session_id").notNull(),
    scope: text("scope").notNull(),
    expiresAt: integer("expires_at").notNull(),
    revokedAt: integer("revoked_at"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [
    index("idx_access_tokens_session").on(t.sessionId),
    index("idx_access_tokens_user").on(t.userId),
    index("idx_access_tokens_expires").on(t.expiresAt),
  ],
);

export const invitations = sqliteTable(
  "invitations",
  {
    id: text("id").primaryKey(),
    codeHash: text("code_hash").notNull(),
    email: text("email"),
    role: text("role").notNull(),
    createdBy: text("created_by").notNull(),
    createdAt: integer("created_at").notNull(),
    expiresAt: integer("expires_at").notNull(),
    usedAt: integer("used_at"),
    revokedAt: integer("revoked_at"),
  },
  (t) => [uniqueIndex("idx_invitations_code").on(t.codeHash)],
);

export const passwordResets = sqliteTable(
  "password_resets",
  {
    id: text("id").primaryKey(),
    tokenHash: text("token_hash").notNull(),
    userId: text("user_id").notNull(),
    expiresAt: integer("expires_at").notNull(),
    usedAt: integer("used_at"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [
    uniqueIndex("idx_password_resets_token").on(t.tokenHash),
    index("idx_password_resets_user").on(t.userId),
  ],
);

export const rateLimits = sqliteTable("rate_limits", {
  bucketKey: text("bucket_key").primaryKey(),
  windowStart: integer("window_start").notNull(),
  count: integer("count").notNull().default(0),
});

export const apps = sqliteTable(
  "apps",
  {
    clientId: text("client_id").primaryKey(),
    clientSecretHash: text("client_secret_hash").notNull(),
    name: text("name").notNull(),
    /** JSON 数组字符串 */
    redirectUris: text("redirect_uris").notNull(),
    postLogoutRedirectUris: text("post_logout_redirect_uris").notNull().default("[]"),
    createdAt: integer("created_at").notNull(),
  },
);

export const authorizationCodes = sqliteTable(
  "authorization_codes",
  {
    codeHash: text("code_hash").primaryKey(),
    clientId: text("client_id").notNull(),
    userId: text("user_id").notNull(),
    redirectUri: text("redirect_uri").notNull(),
    codeChallenge: text("code_challenge").notNull(),
    codeChallengeMethod: text("code_challenge_method").notNull(),
    nonce: text("nonce"),
    scope: text("scope").notNull(),
    expiresAt: integer("expires_at").notNull(),
    usedAt: integer("used_at"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [
    index("idx_authorization_codes_expires").on(t.expiresAt),
    index("idx_authorization_codes_user").on(t.userId),
  ],
);

export const oidcStates = sqliteTable(
  "oidc_states",
  {
    stateHash: text("state_hash").primaryKey(),
    nonce: text("nonce"),
    redirectUri: text("redirect_uri").notNull(),
    expiresAt: integer("expires_at").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_oidc_states_expires").on(t.expiresAt)],
);

export const signingKeys = sqliteTable(
  "signing_keys",
  {
    kid: text("kid").primaryKey(),
    alg: text("alg").notNull(),
    /** 只存公钥 JWK。私钥只在 SESSION 之外的 secret 里，绝不进 D1。 */
    publicJwk: text("public_jwk").notNull(),
    status: text("status").notNull(),
    createdAt: integer("created_at").notNull(),
    retiredAt: integer("retired_at"),
  },
);

export const passkeys = sqliteTable(
  "passkeys",
  {
    id: text("id").primaryKey(),
    userId: text("user_id").notNull(),
    /** 全局唯一。登录时先按它反查用户（此时还没有身份上下文）。 */
    credentialId: text("credential_id").notNull(),
    publicKey: text("public_key").notNull(),
    counter: integer("counter").notNull().default(0),
    deviceType: text("device_type"),
    backedUp: integer("backed_up").notNull().default(0),
    /** JSON 数组字符串 */
    transports: text("transports"),
    createdAt: integer("created_at").notNull(),
    revokedAt: integer("revoked_at"),
  },
  (t) => [
    uniqueIndex("idx_passkeys_credential").on(t.credentialId),
    index("idx_passkeys_user").on(t.userId),
  ],
);

export const passkeyChallenges = sqliteTable(
  "passkey_challenges",
  {
    id: text("id").primaryKey(),
    userId: text("user_id"),
    challenge: text("challenge").notNull(),
    type: text("type").notNull(),
    expiresAt: integer("expires_at").notNull(),
    consumedAt: integer("consumed_at"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [
    uniqueIndex("idx_passkey_challenges_challenge").on(t.challenge),
    index("idx_passkey_challenges_user").on(t.userId),
    index("idx_passkey_challenges_expires").on(t.expiresAt),
  ],
);

export const mfaFactors = sqliteTable(
  "mfa_factors",
  {
    id: text("id").primaryKey(),
    userId: text("user_id").notNull(),
    factorType: text("factor_type").notNull(),
    /** AES-GCM 密文 */
    secretCiphertext: text("secret_ciphertext"),
    iv: text("iv"),
    keyVersion: integer("key_version").notNull().default(1),
    /** 已使用的时间步，防同一验证码重放 */
    lastUsedStep: integer("last_used_step"),
    status: text("status").notNull().default("active"),
    verifiedAt: integer("verified_at"),
    createdAt: integer("created_at").notNull(),
    revokedAt: integer("revoked_at"),
  },
  (t) => [index("idx_mfa_factors_user").on(t.userId)],
);

export const mfaRecoveryCodes = sqliteTable(
  "mfa_recovery_codes",
  {
    id: text("id").primaryKey(),
    userId: text("user_id").notNull(),
    codeHash: text("code_hash").notNull(),
    usedAt: integer("used_at"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [
    uniqueIndex("idx_recovery_codes_hash").on(t.codeHash),
    index("idx_recovery_codes_user").on(t.userId),
  ],
);

export const auditLogs = sqliteTable(
  "audit_logs",
  {
    id: text("id").primaryKey(),
    actorUserId: text("actor_user_id"),
    action: text("action").notNull(),
    target: text("target"),
    ip: text("ip"),
    /** JSON 字符串，不含任何明文密码或完整令牌 */
    meta: text("meta"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_audit_logs_created").on(t.createdAt)],
);