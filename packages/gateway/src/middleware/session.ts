import type { Context } from "hono";
import { createMiddleware } from "hono/factory";
import { SESSION_COOKIE, SessionStatus, type Role } from "@sso/shared";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { callCore } from "../core/callCore";
import type { AppContext, Caller } from "../types";

type LookupResponse = {
  ok: boolean;
  valid: boolean;
  reason?: string;
  sessionId?: string;
  userId?: string;
  role?: Role;
};

export function sessionCookieOptions(maxAge: number) {
  return {
    // __Host- 前缀强制 Secure + Path=/ + 无 Domain：
    // 浏览器层面拒绝任何子域覆盖此 Cookie。
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "Lax" as const,
    maxAge,
  };
}

export function setSessionCookie(c: Parameters<typeof setCookie>[0], token: string, maxAge: number) {
  setCookie(c, SESSION_COOKIE, token, sessionCookieOptions(maxAge));
}

export function clearSessionCookie(c: Parameters<typeof deleteCookie>[0]) {
  deleteCookie(c, SESSION_COOKIE, { path: "/", secure: true, httpOnly: true, sameSite: "Lax" });
}

/**
 * requireAuth：
 *   1. 取 Cookie -> 交 Core 查 D1
 *   2. Core 侧显式拒绝 mfa_pending
 *   3. 注入 caller / sessionId
 */
export const requireAuth = createMiddleware<AppContext>(async (c, next) => {
  const token = getCookie(c, SESSION_COOKIE);
  if (!token) {
    if (wantsHtml(c.req.method, c.req.path)) return c.redirect("/login", 302);
    return c.json({ ok: false, code: "unauthorized" }, 401);
  }

  const result = await callCore<LookupResponse>(c.env, {
    method: "POST",
    path: "/session/lookup",
    payload: { token },
  });

  if (!result.ok) {
    if (wantsHtml(c.req.method, c.req.path)) return c.redirect("/login", 302);
    return c.json({ ok: false, code: "unauthorized" }, 401);
  }

  const data = result.data;
  if (!data.valid) {
    clearSessionCookie(c);
    if (wantsHtml(c.req.method, c.req.path)) return c.redirect("/login", 302);
    return c.json({ ok: false, code: "unauthorized", reason: data.reason ?? "invalid" }, 401);
  }

  c.set("caller", { userId: data.userId!, role: data.role! } satisfies Caller);
  c.set("sessionId", data.sessionId!);

  await next();
});

/**
 * 无副作用的会话查询：用于 /authorize 这类"可能未登录"的端点。
 * 与 requireAuth 复用同一套校验（含显式拒绝 mfa_pending），
 * 区别只是未登录时返回 null 而不是重定向。
 */
export async function getSessionCaller(c: Context<AppContext>): Promise<(Caller & { sessionId: string }) | null> {
  const token = getCookie(c, SESSION_COOKIE);
  if (!token) return null;

  const result = await callCore<LookupResponse>(c.env, {
    method: "POST",
    path: "/session/lookup",
    payload: { token },
  });
  if (!result.ok || !result.data.valid) return null;

  return {
    userId: result.data.userId!,
    role: result.data.role!,
    sessionId: result.data.sessionId!,
  };
}

export function requireRole(role: Role) {
  return createMiddleware<AppContext>(async (c, next) => {
    const caller = c.get("caller");
    if (!caller) return c.json({ ok: false, code: "unauthorized" }, 401);
    const rank: Record<Role, number> = { user: 1, admin: 2, super_admin: 3 };
    if (rank[caller.role] < rank[role]) {
      if (wantsHtml(c.req.method, c.req.path)) return c.text("无权限", 403);
      return c.json({ ok: false, code: "forbidden" }, 403);
    }
    await next();
  });
}

function wantsHtml(method: string, path: string): boolean {
  if (method !== "GET") return false;
  return !path.startsWith("/api/") && !path.startsWith("/auth/") && !path.startsWith("/oauth/");
}

export { SessionStatus };