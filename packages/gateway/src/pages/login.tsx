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

        {/* 邀请注册入口。
            登录页是预渲染的静态页，读不到 INVITE_ENABLED，
            所以这里不做条件渲染 —— 开关状态由 /register 页自己判断并说明。 */}
        <div class="divider"><span>首次使用</span></div>
        <a class="btn btn-secondary" href="/register">用邀请码注册</a>
      </section>
    </Layout>
  );
}