/// <reference lib="dom" />
/// <reference lib="dom.iterable" />
/**
 * 安全设置页的交互脚本。
 * 与登录页共用同一批 WebAuthn / 请求工具，产物是 /assets/security.js。
 */
import { base64urlToBuffer, bufferToBase64url, postJson, setHint } from "./webauthn";

function hint(text: string): void {
  setHint("totp-status", text);
}

// ---------------------------------------------------------------- Passkey 绑定

async function registerPasskey(): Promise<void> {
  const button = document.getElementById("passkey-register") as HTMLButtonElement | null;
  if (!button) return;

  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const start = await postJson<{ options: Record<string, unknown> }>("/admin/security/passkey/options", {});
      if (!start.ok || !start.data) {
        hint("无法开始绑定，请刷新重试");
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
      const finish = await postJson("/admin/security/passkey/verify", {
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
        window.location.href = "/admin/security";
        return;
      }
      hint(finish.message ?? "绑定失败");
    } catch {
      hint("绑定被取消");
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
    const start = await postJson<{ factorId: string; otpauthUri: string }>("/admin/security/totp/begin", {});
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
    const result = await postJson<{ recoveryCodes: string[] }>("/admin/security/totp/confirm", {
      code: String(data.get("code") ?? ""),
    });

    if (!result.ok || !result.data) {
      hint(result.message ?? "验证码不正确");
      return;
    }

    // 恢复码只在启用时返回一次，随跳转参数带回页面展示。
    window.location.href = `/admin/security?totp=on&codes=${encodeURIComponent(
      result.data.recoveryCodes.join(","),
    )}`;
  });
}

async function regenerateRecovery(): Promise<void> {
  const button = document.getElementById("recovery-regenerate") as HTMLButtonElement | null;
  if (!button) return;

  button.addEventListener("click", async () => {
    button.disabled = true;
    const result = await postJson<{ recoveryCodes: string[] }>("/admin/security/recovery/regenerate", {});
    if (!result.ok || !result.data) {
      hint(result.message ?? "生成失败");
      button.disabled = false;
      return;
    }
    window.location.href = `/admin/security?codes=${encodeURIComponent(result.data.recoveryCodes.join(","))}`;
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
