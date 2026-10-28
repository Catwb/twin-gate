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

/**
 * 提交改密。
 *
 * 注意：这个端点在 MFA 门禁之外，因为它服务于"首次登录必须改密"流程，
 * 而此时用户可能还没绑定任何第二因子。
 */
accountRoutes.post("/account/password", async (c) => {
  const caller = c.get("caller")!;
  const body = (await c.req.json().catch(() => null)) as {
    currentPassword?: string;
    newPassword?: string;
  } | null;

  if (!body?.currentPassword || !body?.newPassword) {
    return c.json({ ok: false, code: "bad_request", message: "请求无效" }, 400);
  }

  const result = await callCore(c.env, {
    method: "POST",
    path: "/user/change-password",
    caller,
    payload: {
      userId: caller.userId,
      currentPassword: body.currentPassword,
      newPassword: body.newPassword,
    },
    ip: c.req.header("cf-connecting-ip") ?? undefined,
  });

  if (!result.ok) {
    const messages: Record<string, string> = {
      invalid_credentials: "当前密码不正确",
      weak_password: "新密码不满足要求（至少 12 位）",
      same_password: "新密码不能与当前密码相同",
      bad_request: "请求无效",
    };
    return c.json(
      {
        ok: false,
        code: result.code,
        message: messages[result.code] ?? "修改失败",
      },
      400,
    );
  }

  return c.json({ ok: true, redirect: "/admin" });
});
