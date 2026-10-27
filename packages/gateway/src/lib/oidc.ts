/**
 * OIDC 协议层的常量与校验工具。
 * 这里是 issuer / RP 相关的唯一来源，别处不得硬编码。
 */

export const SUPPORTED_SCOPES = ["openid", "profile", "email"] as const;

export function isValidScope(scope: string): boolean {
  const requested = scope.split(/\s+/).filter(Boolean);
  if (requested.length === 0) return false;
  // openid 是 OIDC 的必需 scope，缺了就不是 OIDC 请求。
  if (!requested.includes("openid")) return false;
  return requested.every((item) => (SUPPORTED_SCOPES as readonly string[]).includes(item));
}

export function normalizeScope(scope: string): string {
  const requested = scope.split(/\s+/).filter(Boolean);
  const unique = Array.from(new Set(requested));
  return unique.join(" ");
}

export function discoveryDocument(issuer: string): Record<string, unknown> {
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    jwks_uri: `${issuer}/oauth/jwks.json`,
    end_session_endpoint: `${issuer}/oauth/logout`,
    introspection_endpoint: `${issuer}/oauth/introspect`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["EdDSA"],
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: [...SUPPORTED_SCOPES],
    claims_supported: ["sub", "iss", "aud", "exp", "iat", "nonce", "sid", "email", "role"],
  };
}

/** 授权码流程的状态参数长度限制，防止超长输入撑爆 D1。 */
export const MAX_STATE_LENGTH = 512;
export const MAX_NONCE_LENGTH = 512;
export const MIN_CODE_CHALLENGE_LENGTH = 43;
