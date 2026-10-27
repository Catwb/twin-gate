/** @jsxImportSource hono/jsx */
import { Hono } from "hono";
import { PAGE_SIZE, Role } from "@sso/shared";
import { callCore } from "../core/callCore";
import { mfaGate } from "../middleware/mfaGate";
import { requireAuth, requireRole } from "../middleware/session";
import { AdminLayout, Pager } from "../components/AdminLayout";
import type { AppContext } from "../types";

export const adminAppsRoutes = new Hono<AppContext>();

adminAppsRoutes.use("*", requireAuth);
// 超管未绑定 MFA 前不得进入，只能去 /admin/security。
adminAppsRoutes.use("*", mfaGate);

/**
 * 创建客户端。
 * client_secret 只在这里返回一次，用查询参数带回列表页展示 —— 不落库、不回显第二次。
 */
adminAppsRoutes.post("/apps/create", requireRole(Role.SuperAdmin), async (c) => {
  const form = await c.req.formData();
  const name = String(form.get("name") ?? "").trim();
  const redirectRaw = String(form.get("redirectUris") ?? "");
  const postLogoutRaw = String(form.get("postLogoutRedirectUris") ?? "");

  const redirectUris = redirectRaw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const postLogoutRedirectUris = postLogoutRaw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  if (!name || redirectUris.length === 0) {
    return c.redirect("/admin/apps?error=" + encodeURIComponent("名称与至少一个回调地址必填"), 303);
  }

  for (const uri of [...redirectUris, ...postLogoutRedirectUris]) {
    try {
      new URL(uri);
    } catch {
      return c.redirect("/admin/apps?error=" + encodeURIComponent(`无效的 URL：${uri}`), 303);
    }
  }

  const result = await callCore<{ ok: boolean; clientId: string; clientSecret: string }>(c.env, {
    method: "POST",
    path: "/client/create",
    caller: c.get("caller"),
    payload: { name, redirectUris, ...(postLogoutRedirectUris.length ? { postLogoutRedirectUris } : {}) },
  });

  if (!result.ok) {
    return c.redirect("/admin/apps?error=" + encodeURIComponent("创建失败"), 303);
  }

  const params = new URLSearchParams({
    created: result.data.clientId,
    secret: result.data.clientSecret,
  });
  return c.redirect(`/admin/apps?${params.toString()}`, 303);
});

/** 轮换 secret —— 旧值立刻失效，下游必须立刻更新。 */
adminAppsRoutes.post("/apps/rotate", requireRole(Role.SuperAdmin), async (c) => {
  const form = await c.req.formData();
  const clientId = String(form.get("clientId") ?? "");

  const result = await callCore<{ ok: boolean; clientSecret: string }>(c.env, {
    method: "POST",
    path: "/client/rotate-secret",
    caller: c.get("caller"),
    payload: { clientId },
  });

  if (!result.ok) return c.redirect("/admin/apps?error=" + encodeURIComponent("轮换失败"), 303);

  const params = new URLSearchParams({ rotated: clientId, secret: result.data.clientSecret });
  return c.redirect(`/admin/apps?${params.toString()}`, 303);
});

/** 删除客户端 —— 连带它签出的授权码与令牌在过期后自然失效。 */
adminAppsRoutes.post("/apps/delete", requireRole(Role.SuperAdmin), async (c) => {
  const form = await c.req.formData();
  const clientId = String(form.get("clientId") ?? "");

  await callCore(c.env, {
    method: "POST",
    path: "/client/delete",
    caller: c.get("caller"),
    payload: { clientId },
  });

  return c.redirect("/admin/apps?deleted=" + encodeURIComponent(clientId), 303);
});

adminAppsRoutes.get("/apps", requireRole(Role.Admin), async (c) => {
  const offset = Math.max(0, Number(c.req.query("offset") ?? 0) || 0);
  const [appsResult, keysResult] = await Promise.all([
    callCore<{ ok: boolean; apps: AppRow[] }>(c.env, {
      method: "POST",
      path: "/client/list",
      caller: c.get("caller"),
      payload: { limit: PAGE_SIZE, offset },
    }),
    callCore<{ ok: boolean; keys: KeyRow[] }>(c.env, {
      method: "POST",
      path: "/keys/list",
      caller: c.get("caller"),
      payload: {},
    }),
  ]);

  const apps = appsResult.ok ? appsResult.data.apps : [];
  const keys = keysResult.ok ? keysResult.data.keys : [];
  const created = c.req.query("created");
  const rotated = c.req.query("rotated");
  const secret = c.req.query("secret");
  const errorMessage = c.req.query("error");
  const deleted = c.req.query("deleted");
  const isSuperAdmin = c.get("caller")?.role === "super_admin";

  return c.html(
    <AdminLayout title="应用与密钥" current="/admin/apps">
      {errorMessage ? <p class="alert alert-error">{errorMessage}</p> : null}
      {deleted ? <p class="alert alert-info">已删除客户端 {deleted}</p> : null}
      {secret ? (
        <div class="alert alert-info">
          <strong>{rotated ? "新密钥已生成，旧密钥立即失效" : "客户端已创建"}</strong>
          <p class="hint">密钥只显示这一次，请立即保存：</p>
          <p class="mono secret-box">{secret}</p>
        </div>
      ) : null}

      <h2 class="section-title">OIDC 客户端</h2>
      <table class="table">
        <thead>
          <tr>
            <th>名称</th>
            <th>client_id</th>
            <th>回调地址</th>
            {isSuperAdmin ? <th>操作</th> : null}
          </tr>
        </thead>
        <tbody>
          {apps.length === 0 ? (
            <tr>
              <td colspan={isSuperAdmin ? 4 : 3} class="hint">还没有客户端。</td>
            </tr>
          ) : null}
          {apps.map((app) => (
            <tr>
              <td>{app.name}</td>
              <td class="mono">{app.clientId}</td>
              <td class="mono">{parseUris(app.redirectUris).join(", ")}</td>
              {isSuperAdmin ? (
                <td class="actions">
                  <form method="post" action="/admin/apps/rotate" class="inline-form">
                    <input type="hidden" name="clientId" value={app.clientId} />
                    <button class="btn btn-secondary btn-sm" type="submit">轮换密钥</button>
                  </form>
                  <form method="post" action="/admin/apps/delete" class="inline-form">
                    <input type="hidden" name="clientId" value={app.clientId} />
                    <button class="btn btn-danger btn-sm" type="submit">删除</button>
                  </form>
                </td>
              ) : null}
            </tr>
          ))}
        </tbody>
      </table>
      <Pager base="/admin/apps" offset={offset} pageSize={PAGE_SIZE} hasNext={apps.length === PAGE_SIZE} />

      {isSuperAdmin ? (
        <>
          <h2 class="section-title">新建客户端</h2>
          <form method="post" action="/admin/apps/create" class="form form-wide">
            <label class="field">
              <span class="field-label">应用名称</span>
              <input class="input" name="name" required />
            </label>
            <label class="field">
              <span class="field-label">回调地址（每行一个，精确匹配，不支持通配符）</span>
              <textarea class="input" name="redirectUris" rows={2} placeholder="https://app.example.com/callback" required />
            </label>
            <label class="field">
              <span class="field-label">登出后跳转地址（可选，每行一个）</span>
              <textarea class="input" name="postLogoutRedirectUris" rows={2} placeholder="https://app.example.com/" />
            </label>
            <button class="btn btn-primary" type="submit">创建</button>
          </form>
        </>
      ) : (
        <p class="hint">只有超级管理员可以创建、轮换或删除客户端。</p>
      )}

      <h2 class="section-title">签名密钥</h2>
      <table class="table">
        <thead>
          <tr>
            <th>kid</th>
            <th>算法</th>
            <th>状态</th>
            <th>创建时间</th>
          </tr>
        </thead>
        <tbody>
          {keys.map((key) => (
            <tr>
              <td class="mono">{key.kid}</td>
              <td>{key.alg}</td>
              <td><span class="badge">{key.status}</span></td>
              <td class="mono">{formatTime(key.createdAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p class="hint">
        私钥不展示、不回显、不提供下载。轮换时把新密钥放到 SIGNING_KEYS_JSON 首位，旧密钥保留在数组中，
        JWKS 会自动同时输出两者，等下游缓存过期后再移除旧密钥。
      </p>
    </AdminLayout>,
  );
});

adminAppsRoutes.get("/sessions", requireRole(Role.Admin), async (c) => {
  const offset = Math.max(0, Number(c.req.query("offset") ?? 0) || 0);
  const result = await callCore<{ ok: boolean; sessions: SessionRow[] }>(c.env, {
    method: "POST",
    path: "/session/list",
    caller: c.get("caller"),
    payload: { limit: PAGE_SIZE, offset },
  });

  const sessions = result.ok ? result.data.sessions : [];
  return c.html(
    <AdminLayout title="活动会话" current="/admin/sessions">
      <table class="table">
        <thead>
          <tr>
            <th>会话</th>
            <th>状态</th>
            <th>最后活跃</th>
            <th>IP</th>
            <th>设备</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((session) => (
            <tr>
              <td class="mono">{session.id.slice(0, 8)}</td>
              <td><span class="badge">{session.status}</span></td>
              <td class="mono">{formatTime(session.lastUsedAt)}</td>
              <td class="mono">{session.ip ?? "-"}</td>
              <td class="mono">{shorten(session.userAgent)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pager base="/admin/sessions" offset={offset} pageSize={PAGE_SIZE} hasNext={sessions.length === PAGE_SIZE} />
    </AdminLayout>,
  );
});

type AppRow = { clientId: string; name: string; redirectUris: string; createdAt: number };
type KeyRow = { kid: string; alg: string; status: string; createdAt: number };
type SessionRow = {
  id: string;
  status: string;
  lastUsedAt: number | null;
  ip: string | null;
  userAgent: string | null;
};

function parseUris(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

function shorten(value: string | null): string {
  if (!value) return "-";
  return value.length > 48 ? `${value.slice(0, 48)}…` : value;
}

function formatTime(value: number | null): string {
  if (!value) return "-";
  const date = new Date(value * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}