/** @jsxImportSource hono/jsx */
import { Hono } from "hono";
import { getCookie } from "hono/cookie";
import { SESSION_COOKIE, SessionStatus, TTL, Role } from "@sso/shared";
import { callCore } from "../core/callCore";
import { clearSessionCookie, setSessionCookie } from "../middleware/session";
import { LoginPage } from "../pages/login";
import type { AppContext } from "../types";

export const authRoutes = new Hono<AppContext>();

type LoginResponse = {
  ok: boolean;
  sessionId: string;
  token: string;
  expiresAt: number;
  status: string;
  role: string;
  mustChangePassword: boolean;
};

/**
 * 登录端点有两条通道：表单提交（POST form）与 JSON（客户端脚本）。
 * 两者走完全相同的服务端逻辑，不做任何分支差异。
 */
authRoutes.post("/login", async (c) => {
  const contentType = c.req.header("content-type") ?? "";
  const isJson = contentType.includes("application/json");

  let email = "";
  let password = "";
  if (isJson) {
    const body = (await c.req.json().catch(() => null)) as { email?: string; password?: string } | null;
    email = body?.email ?? "";
    password = body?.password ?? "";
  } else {
    const form = await c.req.formData().catch(() => null);
    email = String(form?.get("email") ?? "");
    password = String(form?.get("password") ?? "");
  }

  const ip = c.req.header("cf-connecting-ip") ?? "0.0.0.0";
  const userAgent = c.req.header("user-agent") ?? "";

  const result = await callCore<LoginResponse>(c.env, {
    method: "POST",
    path: "/auth/login",
    payload: { email, password },
    ip,
    userAgent,
  });

  const fail = (message: string) => {
    if (isJson) return c.json({ ok: false, message }, 401);
    return c.html(<LoginPage error={message} />, 401);
  };

  if (!result.ok) {
    if (result.code === "locked") return fail("尝试次数过多，请稍后再试");
    return fail("邮箱或密码不正确");
  }

  const data = result.data;
  // 会话 Cookie 在 MFA 未完成前不下发完整权限，但令牌本身携带 mfa_pending 状态，
  // requireAuth 会显式拒绝它。
  const maxAge = data.status === SessionStatus.MfaPending ? TTL.mfaPending : TTL.session;
  setSessionCookie(c, data.token, maxAge);

  const next = isJson ? null : c.req.query("next");
  const safeNext = next && next.startsWith("/") && !next.startsWith("//") ? next : null;

  // 分角色落地：user 进入 /admin 会撞「无权限」，给 ta 自己的账户页。
  const redirect =
    data.status === SessionStatus.MfaPending
      ? "/mfa"
      : data.mustChangePassword
        ? "/account/password"
        : (safeNext ?? (data.role === "user" ? "/account" : "/admin"));

  if (isJson) return c.json({ ok: true, redirect });
  return c.redirect(redirect, 303);
});

authRoutes.post("/logout", async (c) => {
  const sessionId = c.get("sessionId");
  if (sessionId) {
    // best-effort：登出必须无条件成功，吊销失败也只能清 Cookie。
    await callCore(c.env, {
      method: "POST",
      path: "/session/revoke",
      caller: c.get("caller"),
      payload: { sessionId, reason: "logout" },
    });
  }
  clearSessionCookie(c);

  const wantsJson = (c.req.header("accept") ?? "").includes("application/json");
  if (wantsJson) return c.json({ ok: true, redirect: "/login" });
  return c.redirect("/login", 303);
});

/** 邀请码接受页：invite_enabled 关闭时直接 404，不暴露端点存在。 */
authRoutes.post("/invite/accept", async (c) => {
  if (c.env.INVITE_ENABLED !== "true") return c.notFound();

  const body = (await c.req.json().catch(() => null)) as {
    code?: string;
    email?: string;
    password?: string;
  } | null;

  const result = await callCore(c.env, {
    method: "POST",
    path: "/invite/accept",
    payload: { code: body?.code ?? "", email: body?.email ?? "", password: body?.password ?? "" },
    ip: c.req.header("cf-connecting-ip") ?? "0.0.0.0",
  });

  if (!result.ok) {
    if (result.code === "locked") return c.json({ ok: false, message: "尝试次数过多，请稍后再试" }, 429);
    return c.json({ ok: false, message: "邀请码无效或已过期" }, 400);
  }
  return c.json({ ok: true, redirect: "/login" });
});

export { getCookie, SESSION_COOKIE, Role };