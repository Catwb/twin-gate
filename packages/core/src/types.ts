export interface Env {
  DB: D1Database;
  /** 由 wrangler secret 注入。Gateway 与 Core 必须完全一致。 */
  GATEWAY_TOKEN: string;
  /** HMAC-SHA256 的 pepper。泄露 = 全部密码可被离线爆破。 */
  SESSION_PEPPER: string;
  /** TOTP secret 的 AES-GCM 主密钥。必须与 SESSION_PEPPER 分开。 */
  TOTP_MASTER_KEY: string;
  /** EdDSA 私钥材料（JSON 数组）。第一项为当前签名密钥。 */
  SIGNING_KEYS_JSON?: string;
  /** OIDC issuer，必须与 Gateway 一致。 */
  ISSUER?: string;
  /** WebAuthn RP ID，通常是域名（不含协议）。 */
  RP_ID?: string;
}
