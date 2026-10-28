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

        {/* 恢复码入口。
            设备丢失、验证器不在身边时，这是唯一的自助出路，
            所以入口必须始终可见 —— 不能藏在"更多选项"里。 */}
        <div class="divider"><span>或</span></div>

        <button class="btn btn-secondary" id="recovery-toggle" type="button">
          使用恢复码
        </button>

        <form id="recovery-form" method="post" action="/auth/mfa/recovery" class="form" hidden>
          <label class="field">
            <span class="field-label">恢复码（10 个一次性码之一）</span>
            <input
              class="input"
              name="code"
              type="text"
              autocomplete="off"
              spellcheck={false}
              placeholder="xxxxx-xxxxx"
              required
            />
          </label>
          <button class="btn btn-primary" type="submit">用恢复码登录</button>
          <p class="hint">
            每个恢复码只能使用一次。用完后请到「安全」页面重新生成。
          </p>
        </form>

        <p class="hint" id="mfa-hint"></p>
      </section>
    </Layout>
  );
}
