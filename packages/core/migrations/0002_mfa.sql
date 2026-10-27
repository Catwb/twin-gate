-- 0002_mfa.sql — 阶段三：Passkey challenge 暂存表
-- TOTP 因子复用已有的 mfa_factors 表，此迁移只补 challenge 表。

CREATE TABLE passkey_challenges (
  id           TEXT PRIMARY KEY,
  user_id      TEXT,
  challenge    TEXT NOT NULL,
  type         TEXT NOT NULL,
  expires_at   INTEGER NOT NULL,
  consumed_at  INTEGER,
  created_at   INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_passkey_challenges_challenge ON passkey_challenges(challenge);
CREATE INDEX idx_passkey_challenges_user ON passkey_challenges(user_id);
CREATE INDEX idx_passkey_challenges_expires ON passkey_challenges(expires_at);
