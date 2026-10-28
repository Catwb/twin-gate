/// <reference lib="dom" />
/// <reference lib="dom.iterable" />
/**
 * 登录页 / MFA 页的客户端脚本。
 * 由 esbuild 打包成 /assets/app.js（固定文件名，不带 hash）。
 */
import { base64urlToBuffer, bufferToBase64url, postJson, setHint } from "./webauthn";

function hint(text: string): void {
  setHint("login-hint", text);
  setHint("mfa-hint", text);
}

async function loginWithPassword(): Promise<void> {
  const form = document.getElementById("login-form") as HTMLFormElement | null;
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = form.querySelector("button[type=submit]") as HTMLButtonElement | null;
    if (submit) submit.disabled = true;

    const formData = new FormData(form);
    const result = await postJson("/auth/login", {
      email: String(formData.get("email") ?? ""),
      password: String(formData.get("password") ?? ""),
    });

    if (submit) submit.disabled = false;

    if (result.ok && result.redirect) {
      window.location.href = result.redirect;
      return;
    }
    hint(result.message ?? "登录失败");
  });
}

async function loginWithPasskey(): Promise<void> {
  const button = document.getElementById("passkey-login") as HTMLButtonElement | null;
  if (!button) return;

  if (!window.PublicKeyCredential) {
    button.disabled = true;
    hint("当前浏览器不支持 Passkey");
    return;
  }

  button.addEventListener("click", async () => {
    button.disabled = true;
    hint("正在等待设备确认…");
    try {
      const start = await postJson<{ challenge: string; rpId: string; timeout: number; userVerification: string; allowCredentials?: { id: string; type: string }[] }>(
        "/auth/passkey/options",
        {},
      );
      if (!start.ok || !start.data) {
        hint(start.message ?? "无法开始 Passkey 登录");
        return;
      }

      const options = start.data;
      const assertion = (await navigator.credentials.get({
        publicKey: {
          challenge: base64urlToBuffer(options.challenge),
          rpId: options.rpId,
          timeout: options.timeout,
          userVerification: options.userVerification as UserVerificationRequirement,
          ...(options.allowCredentials
            ? {
                allowCredentials: options.allowCredentials.map((cred) => ({
                  id: base64urlToBuffer(cred.id),
                  type: cred.type as PublicKeyCredentialType,
                })),
              }
            : {}),
        },
      })) as PublicKeyCredential | null;

      if (!assertion) {
        hint("未完成验证");
        return;
      }

      const response = assertion.response as AuthenticatorAssertionResponse;
      const finish = await postJson("/auth/passkey/verify", {
        id: bufferToBase64url(assertion.rawId),
        clientDataJSON: bufferToBase64url(response.clientDataJSON),
        authenticatorData: bufferToBase64url(response.authenticatorData),
        signature: bufferToBase64url(response.signature),
        userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
      });

      if (finish.ok && finish.redirect) {
        window.location.href = finish.redirect;
        return;
      }
      hint(finish.message ?? "Passkey 验证失败");
    } catch {
      hint("Passkey 验证被取消");
    } finally {
      button.disabled = false;
    }
  });
}

/**
 * 恢复码表单的展开/收起。
 *
 * 默认收起是为了让 TOTP 主路径保持简洁，
 * 但按钮本身始终可见 —— 设备丢失时用户能一眼看到出路。
 */
function setupRecoveryToggle(): void {
  const toggle = document.getElementById("recovery-toggle") as HTMLButtonElement | null;
  const form = document.getElementById("recovery-form") as HTMLFormElement | null;
  if (!toggle || !form) return;

  toggle.addEventListener("click", () => {
    const willShow = form.hidden;
    form.hidden = !willShow;
    toggle.textContent = willShow ? "收起恢复码" : "使用恢复码";

    if (willShow) {
      const input = form.querySelector("input[name=code]") as HTMLInputElement | null;
      input?.focus();
    }
  });
}

loginWithPassword();
loginWithPasskey();
setupRecoveryToggle();