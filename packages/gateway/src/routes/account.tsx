/** @jsxImportSource hono/jsx */
import { Hono } from "hono";
import { TTL } from "@sso/shared";
import { callCore } from "../core/callCore";
import { requireAuth, setSessionCookie } from "../middleware/session";
import { AdminLayout } from "../components/AdminLayout";
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
/**
 * 账户首页：普通用户的落地页。
 *
 * 之前 user 角色登录后被送到 /admin，而 /admin/users 要求 Role.Admin，
 * 直接撞「无权限」。这里给普通用户一个自己的落脚点。
 */
accountRoutes.get("/", async (c) => {
  const caller = c.get("caller")!;

  const status = await callCore<{
    totp: boolean;
    passkey: boolean;
    recoveryCodesRemaining: number;
    mustChangePassword: boolean;
    role: string | null;
  }>(c.env, {
    method: "POST",
    path: "/mfa/status",
    payload: { userId: caller.userId },
  });

  const info = status.ok
    ? status.data
    : { totp: false, passkey: false, recoveryCodesRemaining: 0, mustChangePassword: false, role: null };

  const hasMfa = info.totp || info.passkey;
  const isAdmin = caller.role === "admin" || caller.role === "super_admin";

  return c.html(
    <AdminLayout title="我的账户" current="/account" role={caller.role}>
      {info.mustChangePassword ? (
        <p class="alert alert-error">
          你的密码仍是初始密码，请尽快<a href="/account/password">修改</a>。
        </p>
      ) : null}

      <h2 class="section-title">账户</h2>
      <table class="table">
        <tbody>
          <tr>
            <th>密码</th>
            <td><a class="btn btn-secondary btn-sm" href="/account/password">修改密码</a></td>
          </tr>
          <tr>
            <th>二次验证</th>
            <td>
              <span class="badge">{hasMfa ? "已启用" : "未启用"}</span>
              <a class="btn btn-secondary btn-sm" href="/account/security">管理</a>
            </td>
          </tr>
          <tr>
            <th>恢复码</th>
            <td>
              <span class="badge">剩余 {info.recoveryCodesRemaining}</span>
              {info.recoveryCodesRemaining <= 2 && hasMfa ? (
                <span class="hint">建议重新生成</span>
              ) : null}
            </td>
          </tr>
          {isAdmin ? (
            <tr>
              <th>管理后台</th>
              <td><a class="btn btn-secondary btn-sm" href="/admin">进入</a></td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </AdminLayout>,
  );
});

accountRoutes.get("/password", async (c) => {
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
accountRoutes.post("/password", async (c) => {
  const caller = c.get("caller")!;
  const body = (await c.req.json().catch(() => null)) as {
    currentPassword?: string;
    newPassword?: string;
  } | null;

  if (!body?.currentPassword || !body?.newPassword) {
    return c.json({ ok: false, code: "bad_request", message: "请求无效" }, 400);
  }

  const result = await callCore<{ ok: boolean; token?: string; expiresAt?: number }>(c.env, {
    method: "POST",
    path: "/user/change-password",
    caller,
    payload: {
      userId: caller.userId,
      currentPassword: body.currentPassword,
      newPassword: body.newPassword,
      // 传当前会话 id，Core 会保留它并轮换 token
      sessionId: c.get("sessionId") ?? undefined,
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

  // Core 改密后轮换了当前会话的 token，必须写回 Cookie，
  // 否则浏览器还拿着已失效的旧 token，跳转后立刻被踢回登录页。
  const rotatedToken = result.data?.token;
  if (rotatedToken) {
    setSessionCookie(c, rotatedToken, TTL.session);
  }

  // 与其它端点保持一致：业务数据放在 data 里。
  // 前端统一读 result.data，之前放顶层导致"改密成功却提示失败"。
  // 按角色分流：普通用户进 /admin 会撞 requireRole(Role.Admin)。
  // 与 auth.tsx 登录后的规则保持一致。
  const redirect = caller.role === "user" ? "/account" : "/admin";
  return c.json({ ok: true, data: { redirect } });
});