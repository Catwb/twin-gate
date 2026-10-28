/** @jsxImportSource hono/jsx */
import { Hono } from "hono";
import { PAGE_SIZE, Role } from "@sso/shared";
import { callCore } from "../core/callCore";
import { requireAuth, requireRole } from "../middleware/session";
import { mfaGate } from "../middleware/mfaGate";
import { AdminLayout, Pager } from "../components/AdminLayout";
import type { AppContext } from "../types";

export const adminRoutes = new Hono<AppContext>();

// 管理路由组整体挂 requireAuth —— 组内不存在任何可匿名访问的端点。
adminRoutes.use("*", requireAuth);
// 超管未绑定 MFA 前不得进入，只能去 /admin/security。
adminRoutes.use("*", mfaGate);

adminRoutes.get("/", (c) => c.redirect("/admin/users", 302));

adminRoutes.get("/users", requireRole(Role.Admin), async (c) => {
  const offset = Math.max(0, Number(c.req.query("offset") ?? 0) || 0);
  const isSuperAdmin = c.get("caller")?.role === Role.SuperAdmin;
  // 操作后的反馈：所有 POST 都以 ?done= / ?error= 跳回这里
  const done = c.req.query("done");
  const errorMessage = c.req.query("error");
  const result = await callCore<{ ok: boolean; users: UserRow[] }>(c.env, {
    method: "POST",
    path: "/user/list",
    caller: c.get("caller"),
    payload: { limit: PAGE_SIZE, offset },
  });

  const users = result.ok ? result.data.users : [];
  return c.html(
    <AdminLayout title="用户" current="/admin/users">
      {errorMessage ? <p class="alert alert-error">{errorMessage}</p> : null}
      {done ? <p class="alert alert-info">{done}</p> : null}

      <table class="table">
        <thead>
          <tr>
            <th>邮箱</th>
            <th>角色</th>
            <th>状态</th>
            <th>最后登录</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {users.length === 0 ? (
            <tr>
              <td colspan={5} class="hint">还没有用户。</td>
            </tr>
          ) : null}
          {users.map((user) => (
            <tr>
              <td>{user.email}</td>
              <td><span class="badge">{user.role}</span></td>
              <td><span class="badge">{user.status}</span></td>
              <td class="mono">{formatTime(user.lastLoginAt)}</td>
              <td class="actions">
                <form method="post" action="/admin/users/set-status" class="inline-form">
                  <input type="hidden" name="userId" value={user.id} />
                  <input type="hidden" name="status" value={user.status === "active" ? "disabled" : "active"} />
                  <button class="btn btn-secondary btn-sm" type="submit">
                    {user.status === "active" ? "禁用" : "启用"}
                  </button>
                </form>
                <form method="post" action="/admin/users/revoke-sessions" class="inline-form">
                  <input type="hidden" name="userId" value={user.id} />
                  <button class="btn btn-secondary btn-sm" type="submit">踢下线</button>
                </form>
                {isSuperAdmin ? (
                  <form method="post" action="/admin/users/reset-mfa" class="inline-form">
                    <input type="hidden" name="userId" value={user.id} />
                    <button class="btn btn-danger btn-sm" type="submit">重置 MFA</button>
                  </form>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pager base="/admin/users" offset={offset} pageSize={PAGE_SIZE} hasNext={users.length === PAGE_SIZE} />
    </AdminLayout>,
  );
});

adminRoutes.get("/invites", requireRole(Role.Admin), async (c) => {
  const offset = Math.max(0, Number(c.req.query("offset") ?? 0) || 0);
  const createdCode = c.req.query("created");
  const done = c.req.query("done");
  const errorMessage = c.req.query("error");
  const result = await callCore<{ ok: boolean; invitations: InvitationRow[] }>(c.env, {
    method: "POST",
    path: "/invite/list",
    caller: c.get("caller"),
    payload: { limit: PAGE_SIZE, offset },
  });

  const invitations = result.ok ? result.data.invitations : [];
  return c.html(
    <AdminLayout title="邀请" current="/admin/invites">
      <p class="hint">
        邀请默认关闭（INVITE_ENABLED=false）。开启后生成的邀请码只显示一次，请立即复制并线下转达。
      </p>

      {errorMessage ? <p class="alert alert-error">{errorMessage}</p> : null}
      {done ? <p class="alert alert-info">{done}</p> : null}

      {createdCode ? (
        <div class="alert alert-info">
          <strong>邀请码（只显示这一次，请立即复制）</strong>
          <p class="mono secret-box">{createdCode}</p>
          <p class="hint">接受地址：/login → 注册（需管理员开启邀请开关）</p>
        </div>
      ) : null}

      <h2 class="section-title">生成邀请码</h2>
      <form method="post" action="/admin/invites/create" class="form form-wide">
        <label class="field">
          <span class="field-label">限定邮箱（可选，留空则任何持码者可用）</span>
          <input class="input" type="email" name="email" autocomplete="off" />
        </label>
        <label class="field">
          <span class="field-label">初始角色</span>
          <select class="input" name="role">
            <option value="user">user</option>
            <option value="admin">admin</option>
          </select>
        </label>
        <button class="btn btn-primary" type="submit">生成</button>
      </form>
      <table class="table">
        <thead>
          <tr>
            <th>邮箱</th>
            <th>角色</th>
            <th>状态</th>
            <th>过期时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {invitations.map((invitation) => (
            <tr>
              <td>{invitation.email ?? "任意"}</td>
              <td><span class="badge">{invitation.role}</span></td>
              <td><span class="badge">{invitationState(invitation)}</span></td>
              <td class="mono">{formatTime(invitation.expiresAt)}</td>
              <td class="actions">
                {invitation.usedAt || invitation.revokedAt ? null : (
                  <form method="post" action="/admin/invites/revoke" class="inline-form">
                    <input type="hidden" name="id" value={invitation.id} />
                    <button class="btn btn-danger btn-sm" type="submit">撤销</button>
                  </form>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pager base="/admin/invites" offset={offset} pageSize={PAGE_SIZE} hasNext={invitations.length === PAGE_SIZE} />
    </AdminLayout>,
  );
});

adminRoutes.get("/audit", requireRole(Role.Admin), async (c) => {
  const offset = Math.max(0, Number(c.req.query("offset") ?? 0) || 0);
  const result = await callCore<{ ok: boolean; logs: AuditRow[] }>(c.env, {
    method: "POST",
    path: "/audit/list",
    caller: c.get("caller"),
    payload: { limit: PAGE_SIZE, offset },
  });

  const logs = result.ok ? result.data.logs : [];
  return c.html(
    <AdminLayout title="审计" current="/admin/audit">
      <table class="table">
        <thead>
          <tr>
            <th>时间</th>
            <th>动作</th>
            <th>对象</th>
            <th>IP</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log) => (
            <tr>
              <td class="mono">{formatTime(log.createdAt)}</td>
              <td>{log.action}</td>
              <td class="mono">{log.target ?? "-"}</td>
              <td class="mono">{log.ip ?? "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pager base="/admin/audit" offset={offset} pageSize={PAGE_SIZE} hasNext={logs.length === PAGE_SIZE} />
    </AdminLayout>,
  );
});

type UserRow = {
  id: string;
  email: string;
  role: string;
  status: string;
  lastLoginAt: number | null;
  createdAt: number;
};

type InvitationRow = {
  id: string;
  email: string | null;
  role: string;
  createdAt: number;
  expiresAt: number;
  usedAt: number | null;
  revokedAt: number | null;
};

type AuditRow = {
  id: string;
  action: string;
  target: string | null;
  ip: string | null;
  createdAt: number;
};

function invitationState(invitation: InvitationRow): string {
  if (invitation.revokedAt) return "已撤销";
  if (invitation.usedAt) return "已使用";
  if (invitation.expiresAt * 1000 < Date.now()) return "已过期";
  return "有效";
}

function formatTime(value: number | null): string {
  if (!value) return "-";
  const date = new Date(value * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

// ---------------------------------------------------------------- 用户操作

/** 重置他人 MFA：吊销因子与会话，强制重新绑定。 */
adminRoutes.post("/users/reset-mfa", requireRole(Role.SuperAdmin), async (c) => {
  const form = await c.req.formData();
  const userId = String(form.get("userId") ?? "");

  const result = await callCore(c.env, {
    method: "POST",
    path: "/mfa/reset",
    caller: c.get("caller"),
    payload: { userId },
    ip: c.req.header("cf-connecting-ip") ?? undefined,
  });

  if (!result.ok) {
    return c.redirect("/admin/users?error=" + encodeURIComponent("重置失败"), 303);
  }
  return c.redirect("/admin/users?done=" + encodeURIComponent("已重置该用户的 MFA"), 303);
});

/** 启用 / 禁用账号。禁用会连带吊销其全部会话。 */
adminRoutes.post("/users/set-status", requireRole(Role.Admin), async (c) => {
  const form = await c.req.formData();
  const userId = String(form.get("userId") ?? "");
  const status = String(form.get("status") ?? "");

  if (status !== "active" && status !== "disabled") {
    return c.redirect("/admin/users?error=" + encodeURIComponent("无效状态"), 303);
  }

  const result = await callCore(c.env, {
    method: "POST",
    path: "/user/set-status",
    caller: c.get("caller"),
    payload: { userId, status },
  });

  if (!result.ok) {
    return c.redirect("/admin/users?error=" + encodeURIComponent("操作失败，请确认权限"), 303);
  }
  return c.redirect("/admin/users?done=" + encodeURIComponent(status === "disabled" ? "已禁用" : "已启用"), 303);
});

/** 改角色。仅超管，且 Core 会拒绝降级最后一个超管。 */
adminRoutes.post("/users/set-role", requireRole(Role.SuperAdmin), async (c) => {
  const form = await c.req.formData();
  const userId = String(form.get("userId") ?? "");
  const role = String(form.get("role") ?? "");

  const result = await callCore(c.env, {
    method: "POST",
    path: "/user/set-role",
    caller: c.get("caller"),
    payload: { userId, role },
  });

  if (!result.ok) {
    const message = result.code === "last_super_admin" ? "不能降级最后一个超管" : "改角色失败";
    return c.redirect("/admin/users?error=" + encodeURIComponent(message), 303);
  }
  return c.redirect("/admin/users?done=" + encodeURIComponent("角色已更新"), 303);
});

/** 踢下线：吊销该用户全部会话与令牌。 */
adminRoutes.post("/users/revoke-sessions", requireRole(Role.Admin), async (c) => {
  const form = await c.req.formData();
  const userId = String(form.get("userId") ?? "");

  const result = await callCore(c.env, {
    method: "POST",
    path: "/user/revoke-all",
    caller: c.get("caller"),
    payload: { userId, reason: "revoked_by_admin" },
  });

  if (!result.ok) {
    return c.redirect("/admin/users?error=" + encodeURIComponent("操作失败，请确认权限"), 303);
  }
  return c.redirect("/admin/users?done=" + encodeURIComponent("已吊销该用户全部会话"), 303);
});

// ---------------------------------------------------------------- 邀请

adminRoutes.post("/invites/create", requireRole(Role.Admin), async (c) => {
  const form = await c.req.formData();
  const email = String(form.get("email") ?? "").trim();
  const role = String(form.get("role") ?? "user");

  const result = await callCore<{ ok: boolean; code: string; id: string }>(c.env, {
    method: "POST",
    path: "/invite/create",
    caller: c.get("caller"),
    payload: { role, ...(email ? { email } : {}) },
  });

  if (!result.ok) {
    return c.redirect("/admin/invites?error=" + encodeURIComponent("生成失败"), 303);
  }

  // 明文邀请码只显示这一次，用查询参数带回页面
  const params = new URLSearchParams({ created: result.data.code, role });
  return c.redirect(`/admin/invites?${params.toString()}`, 303);
});

adminRoutes.post("/invites/revoke", requireRole(Role.Admin), async (c) => {
  const form = await c.req.formData();
  const id = String(form.get("id") ?? "");

  const result = await callCore(c.env, {
    method: "POST",
    path: "/invite/revoke",
    caller: c.get("caller"),
    payload: { id },
  });

  if (!result.ok) {
    return c.redirect("/admin/invites?error=" + encodeURIComponent("撤销失败"), 303);
  }
  return c.redirect("/admin/invites?done=" + encodeURIComponent("已撤销"), 303);
});