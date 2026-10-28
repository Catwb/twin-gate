/**
 * CSP 只有一份。静态页（_headers）与 SSR 页（中间件）必须引用同一个字符串，
 * 否则迟早改一处忘一处。
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "font-src 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "object-src 'none'",
].join("; ");

export function securityHeaders(): Record<string, string> {
  return {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    // 注意：不要加 interest-cohort=()。
    // 那是 FLoC 的指令，Google 已用 Topics API 取代 FLoC，
    // Chrome 不再识别它，反而会在控制台报：
    //   "Origin trial controlled feature not enabled: 'interest-cohort'"
    // 只保留确实是本项目会用到、且需要显式禁用的能力。
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  };
}
