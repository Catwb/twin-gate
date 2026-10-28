/** @jsxImportSource hono/jsx */
import { Layout, Field, Alert } from "../components/Layout";

/**
 * 邀请码接受页。
 *
 * 这个页面**必须 SSR**：邀请开关是部署期变量（INVITE_ENABLED），
 * 预渲染成静态页就拿不到它。登录页本身仍是静态的，只放一个指向这里的链接。
 */
export function RegisterPage(props: { enabled: boolean; error?: string | null }) {
  return (
    <Layout title="使用邀请码注册" script>
      <section class="card">
        <h1 class="card-title">使用邀请码注册</h1>
        <Alert kind="error" message={props.error ?? null} />

        {props.enabled ? (
          <>
            <p class="hint">
              邀请码由管理员在后台生成，一次性使用。请向管理员索取，不要张贴到公开渠道。
            </p>
            <form id="register-form" method="post" action="/auth/invite/accept" class="form">
              <Field label="邀请码" name="code" type="text" autocomplete="off" />
              <Field label="邮箱" name="email" type="email" autocomplete="username" />
              <Field label="密码" name="password" type="password" autocomplete="new-password" />
              <button class="btn btn-primary" type="submit">创建账号</button>
            </form>
            <p class="hint" id="register-hint"></p>
            <div class="divider"><span>或</span></div>
            <a class="btn btn-secondary" href="/login">返回登录</a>
          </>
        ) : (
          <>
            <p class="alert alert-error">
              当前实例未开放邀请注册。请联系管理员在部署配置中打开 INVITE_ENABLED。
            </p>
            <a class="btn btn-secondary" href="/login">返回登录</a>
          </>
        )}
      </section>
    </Layout>
  );
}
