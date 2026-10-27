/// <reference lib="dom" />

/** 登录页与安全页共用的 WebAuthn / 请求工具。 */

export type JsonResult<T = unknown> = {
  ok: boolean;
  redirect?: string;
  message?: string;
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
