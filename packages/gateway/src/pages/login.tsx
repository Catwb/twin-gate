/** @jsxImportSource hono/jsx */
import { Layout, Field, Alert } from "../components/Layout";

export function LoginPage(props: { loginTitle?: string; error?: string | null }) {
  return (
    <Layout title="登录" script>
      <section class="card">
        <h1 class="card-title">{props.loginTitle ?? "登录"}</h1>
        <Alert kind="error" message={props.error ?? null} />
        <form id="login-form" method="post" action="/auth/login" class="form">
          <Field label="邮箱" name="email" type="email" autocomplete="username" />
          <Field label="密码" name="password" type="password" autocomplete="current-password" />
          <button class="btn btn-primary" type="submit">登录</button>
        </form>
        <div class="divider"><span>或</span></div>
        <button class="btn btn-secondary" id="passkey-login" type="button">使用 Passkey 登录</button>
        <p class="hint" id="login-hint"></p>
      </section>
    </Layout>
  );
}