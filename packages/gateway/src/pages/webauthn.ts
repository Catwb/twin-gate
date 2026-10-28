/// <reference lib="dom" />

/** 登录页与安全页共用的 WebAuthn / 请求工具。 */

export type JsonResult<T = unknown> = {
  ok: boolean;
  redirect?: string;
  message?: string;
  /** 服务端错误码，用于给出可操作提示 */
  code?: string | null;
  data?: T;
};

export async function postJson<T = unknown>(url: string, body: unknown): Promise<JsonResult<T>> {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      // CSRF：跨源请求无法在无预检情况下携带自定义头
      "x-requested-with": "sso-gateway",
    },
    body: JSON.stringify(body),
  });
  return (await response.json().catch(() => ({ ok: false }))) as JsonResult<T>;
}

export function base64urlToBuffer(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return buffer;
}

export function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** 从 clientDataJSON 里取出 challenge —— 服务端要用它精确匹配暂存的 challenge。 */
export function decodeChallenge(clientDataJSON: string): string | null {
  try {
    const padded = clientDataJSON.replace(/-/g, "+").replace(/_/g, "/");
    const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
    const parsed = JSON.parse(atob(padded + pad)) as { challenge?: string };
    return parsed.challenge ?? null;
  } catch {
    return null;
  }
}

export function setHint(id: string, text: string): void {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

/**
 * 把浏览器抛出的 DOMException 翻译成可操作提示。
 *
 * 登录页与安全页共用 —— 之前只有安全页有一份，
 * 登录页的 Passkey 失败一律显示"验证被取消"，包括真正的网络故障。
 */
export function describeWebAuthnException(name: string, message: string): string {
  switch (name) {
    case "NotAllowedError":
      return "已取消或超时。请确认已用指纹/面容/PIN 完成验证";
    case "SecurityError":
      return "安全错误：当前域名与 RP_ID 不匹配。请用配置的正式域名访问（不能是 IP 或别的域名）";
    case "InvalidStateError":
      return "该设备已绑定过此账号的 Passkey。可换一台设备，或先在系统设置里删除旧凭证";
    case "NotSupportedError":
      return "此浏览器或设备不支持所需的验证方式";
    case "AbortError":
      return "操作被中断，请重试";
    case "NotReadableError":
      return "系统凭证管理器无法响应。请检查：① 手机已设置屏幕锁（PIN/密码，仅有指纹不够）② Chrome 的密码管理器已启用 ③ 不是在工作资料或无痕模式下操作";
    case "UnknownError":
      return "系统返回未知错误。可尝试换一种验证方式（如改用验证器 App 的 TOTP）";
    default:
      return `Passkey 失败：${name}${message ? " - " + message : ""}`.trim();
  }
}