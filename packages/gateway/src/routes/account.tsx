/** @jsxImportSource hono/jsx */
import { Hono } from "hono";
import { callCore } from "../core/callCore";
import { requireAuth } from "../middleware/session";
import { Layout } from "../components/Layout";
import type { AppContext } from "../types";

export const accountRoutes = new Hono<AppContext>();

accountRoutes.use("*", requireAuth);

/**
 * 改密页。
 *
 * 这个页面必须放在超管 MFA 门禁之外：
 * 种子超管 mustChangePassword=1，登录后会被重定向到这里，
 * 如果被门禁挡住就会形成死循环（要改密 → 要求先绑 MFA → 绑完又要改密）。
 */
accountRoutes.get("/account/password", async (c) => {
  const caller = c.get("caller")!;
  const status = await callCore<{ mustChangePassword: boolean }>(c.env, {
    method: "POST",
    path: "/mfa/status",
    payload: { userId: caller.userId },
  });

  const forced = status.ok ? status.data.mustChangePassword : false;

  // 不使用 AdminLayout：避免进入侧栏导航，改密完成后再跳转。
  // 样式表仍由 Layout 统一引入，模板内不得自行引用 CSS。
  return c.html(
    <Layout title="修改密码" variant="centered" scripts={["/assets/password.js"]}>
      <section class="card">
        <h1 class="card-title">{forced ? "请先修改密码" : "修改密码"}</h1>
        {forced ? (
          <p class="hint">首次登录需要设置自己的密码。完成后会自动跳转到管理后台。</p>
        ) : null}
        <p class="alert alert-error" id="password-error" hidden />
        <p class="hint" id="password-hint" />

        <form id="password-form" class="form">
          <label class="field">
            <span class="field-label">当前密码</span>
            <input
              class="input"
              type="password"
              name="currentPassword"
              autocomplete="current-password"
              required
            />
          </label>
          <label class="field">
            <span class="field-label">新密码（至少 12 位）</span>
            <input
              class="input"
              type="password"
              name="newPassword"
              autocomplete="new-password"
              minlength={12}
              required
            />
          </label>
          <label class="field">
            <span class="field-label">确认新密码</span>
            <input
              class="input"
              type="password"
              name="confirmPassword"
              autocomplete="new-password"
              minlength={12}
              required
            />
          </label>
          <button class="btn btn-primary" type="submit">保存</button>
        </form>
      </section>
    </Layout>,
  );
});
