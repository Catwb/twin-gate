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
  const result = await callCore<{ ok: boolean; users: UserRow[] }>(c.env, {
    method: "POST",
    path: "/user/list",
    caller: c.get("caller"),
    payload: { limit: PAGE_SIZE, offset },
  });

  const users = result.ok ? result.data.users : [];
  return c.html(
    <AdminLayout title="用户" current="/admin/users">
      <table class="table">
        <thead>
          <tr>
            <th>邮箱</th>
            <th>角色</th>
            <th>状态</th>
            <th>最后登录</th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr>
              <td>{user.email}</td>
              <td><span class="badge">{user.role}</span></td>
              <td><span class="badge">{user.status}</span></td>
              <td class="mono">{formatTime(user.lastLoginAt)}</td>
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
        邀请默认关闭。开启后生成的邀请码只显示一次，请立即复制并线下转达。
      </p>
      <table class="table">
        <thead>
          <tr>
            <th>邮箱</th>
            <th>角色</th>
            <th>状态</th>
            <th>过期时间</th>
          </tr>
        </thead>
        <tbody>
          {invitations.map((invitation) => (
            <tr>
              <td>{invitation.email ?? "任意"}</td>
              <td><span class="badge">{invitation.role}</span></td>
              <td><span class="badge">{invitationState(invitation)}</span></td>
              <td class="mono">{formatTime(invitation.expiresAt)}</td>
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