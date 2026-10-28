/**
 * WebAuthn 配置的规范化与诊断。
 *
 * 两个值最容易配错，且错误现象不明显：
 *   - expectedOrigin 必须是页面 origin（协议 + host + 端口），不带结尾斜杠、不带路径
 *   - rpId 必须是 host（不带协议、不带端口、不带斜杠）
 *
 * 配错的典型表现：点"绑定"后浏览器报 SecurityError（rpId 不匹配），
 * 或者提交后服务端返回 verification_failed（origin 不匹配）。
 */

/** 从 ISSUER 得到 WebAuthn 期望的 origin。 */
export function normalizeOrigin(issuer: string): string {
  const trimmed = issuer.trim();
  if (!trimmed) return "";
  try {
    const url = new URL(trimmed);
    // origin 天然不带路径、不带结尾斜杠
    return url.origin;
  } catch {
    // 配置本身不是合法 URL，原样返回让上层的校验报出更明确的错
    return trimmed.replace(/\/+$/, "");
  }
}

/** 从 ORIGIN 或 ISSUER 推导出 rpId。 */
export function deriveRpId(origin: string): string {
  try {
    return new URL(origin).hostname;
  } catch {
    return origin;
  }
}

export type WebAuthnConfigDiagnosis =
  | { ok: true; origin: string; rpId: string }
  | { ok: false; error: string };

/** 启动时校验配置，配错就早失败，不要等到用户点绑定才报错。 */
export function diagnoseWebAuthnConfig(issuer: string, configuredRpId?: string): WebAuthnConfigDiagnosis {
  const origin = normalizeOrigin(issuer);
  if (!origin) return { ok: false, error: "ISSUER 未配置" };

  let host: string;
  try {
    host = new URL(origin).hostname;
  } catch {
    return { ok: false, error: `ISSUER 不是合法 URL：${issuer}` };
  }

  const rpId = configuredRpId?.trim() || host;

  // rpId 必须是 host 或 host 的后缀（父域）
  if (host !== rpId && !host.endsWith(`.${rpId}`)) {
    return {
      ok: false,
      error: `RP_ID (${rpId}) 不是 ISSUER 域名 (${host}) 的后缀，Passkey 会全部失败`,
    };
  }

  return { ok: true, origin, rpId };
}
