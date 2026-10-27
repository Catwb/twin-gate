-- 0001_init.sql — 认证主库初始结构
-- 所有时间列为 INTEGER（Unix 秒）。所有令牌只存 SHA-256 哈希。

CREATE TABLE users (
  id                    TEXT PRIMARY KEY,
  email                 TEXT NOT NULL,
  password_hash         TEXT NOT NULL,
  role                  TEXT NOT NULL,
  status                TEXT NOT NULL DEFAULT 'active',
  must_change_password  INTEGER NOT NULL DEFAULT 0,
  mfa_reset_at          INTEGER,
  last_login_at         INTEGER,
  created_at            INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_users_email ON users(email);

CREATE TABLE sessions (
  id             TEXT PRIMARY KEY,
  token_hash     TEXT NOT NULL,
  user_id        TEXT NOT NULL,
  status         TEXT NOT NULL,
  expires_at     INTEGER NOT NULL,
  created_at     INTEGER NOT NULL,
  revoked_at     INTEGER,
  revoke_reason  TEXT,
  last_used_at   INTEGER,
  user_agent     TEXT,
  ip             TEXT
);
CREATE UNIQUE INDEX idx_sessions_token ON sessions(token_hash);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE access_tokens (
  token_hash  TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  client_id   TEXT NOT NULL,
  session_id  TEXT NOT NULL,
  scope       TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  revoked_at  INTEGER,
  created_at  INTEGER NOT NULL
);
CREATE INDEX idx_access_tokens_session ON access_tokens(session_id);
CREATE INDEX idx_access_tokens_user ON access_tokens(user_id);
CREATE INDEX idx_access_tokens_expires ON access_tokens(expires_at);

CREATE TABLE invitations (
  id          TEXT PRIMARY KEY,
  code_hash   TEXT NOT NULL,
  email       TEXT,
  role        TEXT NOT NULL,
  created_by  TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  revoked_at  INTEGER
);
CREATE UNIQUE INDEX idx_invitations_code ON invitations(code_hash);

CREATE TABLE password_resets (
  id          TEXT PRIMARY KEY,
  token_hash  TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  created_at  INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_password_resets_token ON password_resets(token_hash);
CREATE INDEX idx_password_resets_user ON password_resets(user_id);

CREATE TABLE rate_limits (
  bucket_key    TEXT PRIMARY KEY,
  window_start  INTEGER NOT NULL,
  count         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE apps (
  client_id                   TEXT PRIMARY KEY,
  client_secret_hash          TEXT NOT NULL,
  name                        TEXT NOT NULL,
  redirect_uris               TEXT NOT NULL,
  post_logout_redirect_uris   TEXT NOT NULL DEFAULT '[]',
  created_at                  INTEGER NOT NULL
);

CREATE TABLE authorization_codes (
  code_hash              TEXT PRIMARY KEY,
  client_id              TEXT NOT NULL,
  user_id                TEXT NOT NULL,
  redirect_uri           TEXT NOT NULL,
  code_challenge         TEXT NOT NULL,
  code_challenge_method  TEXT NOT NULL,
  nonce                  TEXT,
  scope                  TEXT NOT NULL,
  expires_at             INTEGER NOT NULL,
  used_at                INTEGER,
  created_at             INTEGER NOT NULL
);
CREATE INDEX idx_authorization_codes_expires ON authorization_codes(expires_at);
CREATE INDEX idx_authorization_codes_user ON authorization_codes(user_id);

CREATE TABLE oidc_states (
  state_hash    TEXT PRIMARY KEY,
  nonce         TEXT,
  redirect_uri  TEXT NOT NULL,
  expires_at    INTEGER NOT NULL,
  created_at    INTEGER NOT NULL
);
CREATE INDEX idx_oidc_states_expires ON oidc_states(expires_at);

CREATE TABLE signing_keys (
  kid          TEXT PRIMARY KEY,
  alg          TEXT NOT NULL,
  public_jwk   TEXT NOT NULL,
  status       TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  retired_at   INTEGER
);

CREATE TABLE passkeys (
  id             TEXT PRIMARY KEY,
  user_id        TEXT NOT NULL,
  credential_id  TEXT NOT NULL,
  public_key     TEXT NOT NULL,
  counter        INTEGER NOT NULL DEFAULT 0,
  device_type    TEXT,
  backed_up      INTEGER NOT NULL DEFAULT 0,
  transports     TEXT,
  created_at     INTEGER NOT NULL,
  revoked_at     INTEGER
);
CREATE UNIQUE INDEX idx_passkeys_credential ON passkeys(credential_id);
CREATE INDEX idx_passkeys_user ON passkeys(user_id);

CREATE TABLE mfa_factors (
  id                 TEXT PRIMARY KEY,
  user_id            TEXT NOT NULL,
  factor_type        TEXT NOT NULL,
  secret_ciphertext  TEXT,
  iv                 TEXT,
  key_version        INTEGER NOT NULL DEFAULT 1,
  last_used_step     INTEGER,
  status             TEXT NOT NULL DEFAULT 'active',
  verified_at        INTEGER,
  created_at         INTEGER NOT NULL,
  revoked_at         INTEGER
);
CREATE INDEX idx_mfa_factors_user ON mfa_factors(user_id);

CREATE TABLE mfa_recovery_codes (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  code_hash   TEXT NOT NULL,
  used_at     INTEGER,
  created_at  INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_recovery_codes_hash ON mfa_recovery_codes(code_hash);
CREATE INDEX idx_recovery_codes_user ON mfa_recovery_codes(user_id);

CREATE TABLE audit_logs (
  id             TEXT PRIMARY KEY,
  actor_user_id  TEXT,
  action         TEXT NOT NULL,
  target         TEXT,
  ip             TEXT,
  meta           TEXT,
  created_at     INTEGER NOT NULL
);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);
