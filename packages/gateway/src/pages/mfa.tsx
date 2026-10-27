/** @jsxImportSource hono/jsx */
import { Layout, Field, Alert } from "../components/Layout";

export function MfaPage(props: { error?: string | null }) {
  return (
    <Layout title="二次验证" script>
      <section class="card">
        <h1 class="card-title">二次验证</h1>
        <Alert kind="error" message={props.error ?? null} />
        <form id="totp-form" method="post" action="/auth/mfa" class="form">
          <Field label="验证码" name="code" type="text" autocomplete="one-time-code" />
          <button class="btn btn-primary" type="submit">验证</button>
        </form>
        <div class="divider"><span>或</span></div>
        <button class="btn btn-secondary" id="passkey-verify" type="button">使用 Passkey</button>
        <p class="hint" id="mfa-hint"></p>
      </section>
    </Layout>
  );
}