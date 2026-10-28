/// <reference lib="dom" />
/// <reference lib="dom.iterable" />
/**
 * 注册页脚本。产物是 /assets/register.js。
 *
 * 与登录页同一套 postJson：走 JSON + 自定义头（CSRF），
 * 不依赖表单编码，和后端 /auth/invite/accept 的读法一致。
 */
import { postJson, setHint } from "./webauthn";

function setupRegister(): void {
  const form = document.getElementById("register-form") as HTMLFormElement | null;
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = form.querySelector("button[type=submit]") as HTMLButtonElement | null;
    if (submit) submit.disabled = true;

    const formData = new FormData(form);
    const result = await postJson("/auth/invite/accept", {
      code: String(formData.get("code") ?? "").trim(),
      email: String(formData.get("email") ?? "").trim(),
      password: String(formData.get("password") ?? ""),
    });

    if (submit) submit.disabled = false;

    if (result.ok) {
      setHint("register-hint", "账号已创建，正在跳转到登录页…");
      window.location.href = result.redirect ?? "/login";
      return;
    }
    setHint("register-hint", result.message ?? "注册失败");
  });
}

setupRegister();
