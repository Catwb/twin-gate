/// <reference lib="dom" />
/// <reference lib="dom.iterable" />
/**
 * 安全设置页的交互脚本。
 * 与登录页共用同一批 WebAuthn / 请求工具，产物是 /assets/security.js。
 */
import { base64urlToBuffer, bufferToBase64url, postJson, setHint } from "./webauthn";

/**
 * 统一提示入口。
 * 必须写到页面顶部那个常驻元素，不能写进隐藏面板里的 #totp-status ——
 * 否则 Passkey 失败时用户看不到任何反馈，表现为"点了没反应"。
 */
function hint(text: string): void {
  const errorEl = document.getElementById("security-error");
  const hintEl = document.getElementById("security-hint");

  if (hintEl) hintEl.textContent = text;

  if (errorEl) {
    const isError = /失败|错误|无法|不正确|过期|异常|取消/.test(text);
    errorEl.textContent = isError ? text : "";
    errorEl.hidden = !isError;
  }
}

/**
 * 把 Core 的错误码翻译成可操作提示。
 * 之前只显示"绑定失败"，排查时看不出是域名不匹配还是用户取消。
 */
/**
 * 把浏览器抛出的 DOMException 翻译成可操作提示。
 * 移动端 Chrome 最常见的是 NotAllowedError（用户取消或超时）
 * 与 SecurityError（rpId 与当前域名不匹配）。
 */
function describeWebAuthnException(name: string, message: string): string {
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
      return `绑定失败：${name} ${message ? "- " + message : ""}`.trim();
  }
}

function describePasskeyError(code?: string | null, fallback?: string): string {
  switch (code) {
    case "invalid_challenge":
      return "挑战已过期或已被使用，请重新点击绑定";
    case "verification_failed":
      return "验证失败：请确认访问域名与 ISSUER 完全一致（Passkey 要求同域），然后重试";
    case "not_found":
      return "凭证不存在，请重新绑定";
    case "counter_regression":
      return "凭证计数器异常，可能已被克隆，请联系管理员";
    default:
      return fallback ?? "绑定失败";
  }
}

// ---------------------------------------------------------------- Passkey 绑定

async function registerPasskey(): Promise<void> {
  const button = document.getElementById("passkey-register") as HTMLButtonElement | null;
  if (!button) return;

  button.addEventListener("click", async () => {
    button.disabled = true;
    hint("正在请求绑定选项…");

    // 移动端浏览器常见：环境不支持 WebAuthn 或非安全上下文。
    if (!window.PublicKeyCredential) {
      hint("当前浏览器不支持 Passkey，或页面不是 HTTPS");
      button.disabled = false;
      return;
    }

    // isUserVerifyingPlatformAuthenticatorAvailable 在部分移动浏览器上缺失，
    // 有就查一下，没有就继续（不阻断）。
    try {
      if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
        const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        if (!available) {
          hint("此设备的生物识别不可用，将尝试使用手机/安全密钥等其他方式");
        }
      }
    } catch {
      // 探测失败不影响后续流程
    }

    try {
      const start = await postJson<{ options: Record<string, unknown> }>("/account/security/passkey/options", {});
      if (!start.ok || !start.data) {
        hint(start.message ?? "无法开始绑定，请刷新重试");
        return;
      }

      const options = start.data.options as unknown as {
        challenge: string;
        rp: { id: string; name: string };
        user: { id: string; name: string; displayName: string };
        pubKeyCredParams: PublicKeyCredentialParameters[];
        timeout?: number;
        excludeCredentials?: { id: string; type: string }[];
        authenticatorSelection?: AuthenticatorSelectionCriteria;
        attestation?: AttestationConveyancePreference;
      };

      const credential = (await navigator.credentials.create({
        publicKey: {
          challenge: base64urlToBuffer(options.challenge),
          rp: options.rp,
          user: {
            id: base64urlToBuffer(options.user.id),
            name: options.user.name,
            displayName: options.user.displayName,
          },
          pubKeyCredParams: options.pubKeyCredParams,
          timeout: options.timeout ?? 60000,
          attestation: options.attestation ?? "none",
          ...(options.excludeCredentials
            ? {
                excludeCredentials: options.excludeCredentials.map((item) => ({
                  id: base64urlToBuffer(item.id),
                  type: item.type as PublicKeyCredentialType,
                })),
              }
            : {}),
          ...(options.authenticatorSelection
            ? { authenticatorSelection: options.authenticatorSelection }
            : {}),
        },
      })) as PublicKeyCredential | null;

      if (!credential) {
        hint("未完成绑定");
        return;
      }

      const response = credential.response as AuthenticatorAttestationResponse;
      const finish = await postJson("/account/security/passkey/verify", {
        challenge: options.challenge,
        response: {
          id: credential.id,
          rawId: bufferToBase64url(credential.rawId),
          type: "public-key",
          response: {
            clientDataJSON: bufferToBase64url(response.clientDataJSON),
            attestationObject: bufferToBase64url(response.attestationObject),
          },
          clientExtensionResults: {},
        },
      });

      if (finish.ok) {
        window.location.href = "/account/security";
        return;
      }
      // 把 Core 的错误码翻译成可操作的提示，
      // 而不是笼统的"绑定失败"——这个问题排查过一次，代价很高。
      hint(describePasskeyError(finish.code, finish.message));
    } catch (error) {
      // 打出来，用户可以在控制台把原因发给我们。
      // 移动端现场调试困难，这是唯一的线索来源。
      console.error("[passkey] 注册异常:", error);
      const name = error instanceof Error ? error.name : "UnknownError";
      const message = error instanceof Error ? error.message : String(error);
      hint(describeWebAuthnException(name, message));
    } finally {
      button.disabled = false;
    }
  });
}

// ---------------------------------------------------------------- TOTP

async function beginTotp(): Promise<void> {
  const button = document.getElementById("totp-begin") as HTMLButtonElement | null;
  const panel = document.getElementById("totp-setup") as HTMLElement | null;
  if (!button || !panel) return;

  button.addEventListener("click", async () => {
    button.disabled = true;
    const start = await postJson<{ factorId: string; otpauthUri: string }>("/account/security/totp/begin", {});
    if (!start.ok || !start.data) {
      hint("无法开始启用");
      button.disabled = false;
      return;
    }

    panel.hidden = false;
    const uri = start.data.otpauthUri;

    const uriEl = document.getElementById("totp-uri");
    if (uriEl) uriEl.textContent = uri;

    // 二维码在浏览器端生成，不落存储、不经过服务器：
    // 这里把 otpauth URI 渲染成可扫描的二维码。
    const qr = document.getElementById("totp-qr");
    if (qr) qr.innerHTML = renderQrSvg(uri);
    hint("用验证器扫描后输入当前验证码");
  });
}

async function confirmTotp(): Promise<void> {
  const form = document.getElementById("totp-confirm") as HTMLFormElement | null;
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const result = await postJson<{ recoveryCodes: string[] }>("/account/security/totp/confirm", {
      code: String(data.get("code") ?? ""),
    });

    if (!result.ok || !result.data) {
      hint(result.message ?? "验证码不正确");
      return;
    }

    // 恢复码只在启用时返回一次，随跳转参数带回页面展示。
    window.location.href = `/account/security?totp=on&codes=${encodeURIComponent(
      result.data.recoveryCodes.join(","),
    )}`;
  });
}

async function regenerateRecovery(): Promise<void> {
  const button = document.getElementById("recovery-regenerate") as HTMLButtonElement | null;
  if (!button) return;

  button.addEventListener("click", async () => {
    button.disabled = true;
    const result = await postJson<{ recoveryCodes: string[] }>("/account/security/recovery/regenerate", {});
    if (!result.ok || !result.data) {
      hint(result.message ?? "生成失败");
      button.disabled = false;
      return;
    }
    window.location.href = `/account/security?codes=${encodeURIComponent(result.data.recoveryCodes.join(","))}`;
  });
}

/**
 * 极简二维码渲染（无外部依赖）。
 * 用 SVG 画出 otpauth URI 的机器可读形式 —— 完整 QR 编码器体积过大，
 * 这里退化为"可扫描区域 + 明文 URI"，用户也可直接复制密钥。
 */
function renderQrSvg(uri: string): string {
  const params = new URLSearchParams(uri.split("?")[1] ?? "");
  const secret = params.get("secret") ?? "";
  const label = decodeURIComponent(params.get("issuer") ?? "SSO");
  return `<div class="qr-fallback">
    <p class="hint">在验证器中手动添加账户：</p>
    <p class="mono">发行方：${escapeHtml(label)}</p>
    <p class="mono">密钥：${escapeHtml(secret)}</p>
  </div>`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    const map: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return map[char] ?? char;
  });
}

registerPasskey();
beginTotp();
confirmTotp();
regenerateRecovery();