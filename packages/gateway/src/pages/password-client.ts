/// <reference lib="dom" />
/// <reference lib="dom.iterable" />
/**
 * 改密页脚本。产物为 /assets/password.js。
 */
import { postJson } from "./webauthn";

function setMessage(text: string, isError: boolean): void {
  const hintEl = document.getElementById("password-hint");
  const errorEl = document.getElementById("password-error");
  if (hintEl) hintEl.textContent = isError ? "" : text;
  if (errorEl) {
    errorEl.textContent = isError ? text : "";
    errorEl.hidden = !isError;
  }
}

const form = document.getElementById("password-form") as HTMLFormElement | null;

form?.addEventListener("submit", async (event) => {
  event.preventDefault();

  const data = new FormData(form);
  const currentPassword = String(data.get("currentPassword") ?? "");
  const newPassword = String(data.get("newPassword") ?? "");
  const confirmPassword = String(data.get("confirmPassword") ?? "");

  if (newPassword !== confirmPassword) {
    setMessage("两次输入的新密码不一致", true);
    return;
  }
  if (newPassword.length < 12) {
    setMessage("新密码至少 12 位", true);
    return;
  }

  const submit = form.querySelector("button[type=submit]") as HTMLButtonElement | null;
  if (submit) submit.disabled = true;
  setMessage("正在保存…", false);

  try {
    const result = await postJson<{ redirect?: string }>("/admin/account/password", {
      currentPassword,
      newPassword,
    });

    if (result.ok && result.data?.redirect) {
      window.location.href = result.data.redirect;
      return;
    }
    setMessage(result.message ?? "修改失败", true);
  } catch {
    setMessage("网络异常，请重试", true);
  } finally {
    if (submit) submit.disabled = false;
  }
});
