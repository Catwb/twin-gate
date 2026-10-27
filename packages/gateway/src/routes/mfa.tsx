/** @jsxImportSource hono/jsx */
import { Hono } from "hono";
import { getCookie } from "hono/cookie";
import { SESSION_COOKIE, SessionStatus, TTL } from "@sso/shared";
import { callCore } from "../core/callCore";
import { clearSessionCookie, getSessionCaller, setSessionCookie } from "../middleware/session";
import { MfaPage } from "../pages/mfa";
import type { AppContext } from "../types";

export const mfaRoutes = new Hono<AppContext>();

type CookieContext = Parameters<typeof getCookie>[0];

/**
 * mfa_pending 会话允许访问的端点。
 * requireAuth 会拒绝这个状态，所以这里必须单独处理。
 */
async function getPendingSession(c: Parameters<typeof getSessionCaller>[0]) {
  const token = getCookie(c, SESSION_COOKIE);
  if (!token) return null;

  const result = await callCore<{
    ok: boolean;
    valid: boolean;
    reason?: string;
    sessionId?: string;
    userId?: string;
    role?: string;
  }>(c.env, {
    method: "POST",
    path: "/session/lookup",
    payload: { token },
    // 允许 mfa_pending 通过：这是升级流程本身
    ip: c.req.header("cf-connecting-ip") ?? undefined,
  });

  if (!result.ok || !result.data.valid) {
    // mfa_pending 会被 lookupSession 拒绝，需要单独查一次原始会话状态
    return await getPendingSessionRaw(c, token);
  }
  return null;
}

async function getPendingSessionRaw(c: Parameters<typeof getSessionCaller>[0], token: string) {
  const result = await callCore<{
    valid: boolean;
    sessionId?: string;
    userId?: string;
    status?: string;
  }>(c.env, {
    method: "POST",
    path: "/session/lookup-pending",
    payload: { token },
    ip: c.req.header("cf-connecting-ip") ?? undefined,
  });
  if (!result.ok || !result.data.valid) return null;
  return { sessionId: result.data.sessionId!, userId: result.data.userId! };
}

mfaRoutes.post("/mfa", async (c) => {
  const isJson = (c.req.header("content-type") ?? "").includes("application/json");
  const pending = await getPendingSession(c);

  if (!pending) {
    if (isJson) return c.json({ ok: false, message: "会话已失效，请重新登录" }, 401);
    return c.redirect("/login", 302);
  }

  let code = "";
  if (isJson) {
    const body = (await c.req.json().catch(() => null)) as { code?: string } | null;
    code = body?.code ?? "";
  } else {
    const form = await c.req.formData().catch(() => null);
    code = String(form?.get("code") ?? "");
  }

  const result = await callCore<{
    ok: boolean;
    token: string;
    expiresAt: number;
    role: string;
    mustChangePassword: boolean;
  }>(c.env, {
    method: "POST",
    path: "/mfa/verify-totp",
    payload: {
      userId: pending.userId,
      code: code.replace(/\s+/g, ""),
      sessionId: pending.sessionId,
      userAgent: (c.req.header("user-agent") ?? "").slice(0, 200),
      ip: c.req.header("cf-connecting-ip") ?? "0.0.0.0",
    },
  });

  const fail = (message: string) => {
    if (isJson) return c.json({ ok: false, message }, 401);
    return c.html(<MfaPage error={message} />, 401);
  };

  if (!result.ok) {
    const messages: Record<string, string> = {
      replayed: "该验证码已使用过，请等待下一个",
      invalid_code: "验证码不正确",
      no_factor: "没有可用的验证器",
    };
    return fail(messages[result.code] ?? "验证失败");
  }

  // MFA 通过：轮换 token 并升级为完整会话。
  setSessionCookie(c, result.data.token, TTL.session);

  const redirect = result.data.mustChangePassword ? "/admin/account/password" : "/admin";
  if (isJson) return c.json({ ok: true, redirect });
  return c.redirect(redirect, 303);
});

// ---------------------------------------------------------------- Passkey 登录（免密）

mfaRoutes.post("/passkey/options", async (c) => {
  const result = await callCore<{ ok: boolean; options: Record<string, unknown> }>(c.env, {
    method: "POST",
    path: "/passkey/login-options",
    payload: {},
    ip: c.req.header("cf-connecting-ip") ?? undefined,
  });

  if (!result.ok) return c.json({ ok: false, message: "无法开始 Passkey 登录" }, 400);

  return c.json({
    ok: true,
    data: {
      ...result.data.options,
      // 客户端需要 challenge 单独回传，便于服务端消费时精确匹配
      challenge: result.data.options.challenge,
    },
  });
});

mfaRoutes.post("/passkey/verify", async (c) => {
  const body = (await c.req.json().catch(() => null)) as {
    id?: string;
    clientDataJSON?: string;
    authenticatorData?: string;
    signature?: string;
    userHandle?: string | null;
  } | null;

  const challenge = decodeChallenge(body?.clientDataJSON ?? "");
  if (!challenge) return c.json({ ok: false, message: "请求无效" }, 400);

  const result = await callCore<{ ok: boolean; token: string; role: string; mustChangePassword: boolean }>(c.env, {
    method: "POST",
    path: "/passkey/login-verify",
    payload: {
      challenge,
      response: {
        id: body?.id ?? "",
        rawId: body?.id ?? "",
        type: "public-key",
        response: {
          clientDataJSON: body?.clientDataJSON ?? "",
          authenticatorData: body?.authenticatorData ?? "",
          signature: body?.signature ?? "",
          userHandle: body?.userHandle ?? undefined,
        },
        clientExtensionResults: {},
      },
      userAgent: (c.req.header("user-agent") ?? "").slice(0, 200),
      ip: c.req.header("cf-connecting-ip") ?? "0.0.0.0",
    },
  });

  if (!result.ok) return c.json({ ok: false, message: "Passkey 验证失败" }, 401);

  setSessionCookie(c, result.data.token, TTL.session);
  const redirect = result.data.mustChangePassword ? "/admin/account/password" : "/admin";
  return c.json({ ok: true, redirect });
});

/** 从 clientDataJSON 里取出 challenge —— 服务端必须用它精确匹配暂存的 challenge。 */
function decodeChallenge(clientDataJSON: string): string | null {
  try {
    const padded = clientDataJSON.replace(/-/g, "+").replace(/_/g, "/");
    const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
    const json = atob(padded + pad);
    const parsed = JSON.parse(json) as { challenge?: string };
    return parsed.challenge ?? null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- 恢复码

mfaRoutes.post("/mfa/recovery", async (c) => {
  const isJson = (c.req.header("content-type") ?? "").includes("application/json");
  const pending = await getPendingSession(c);
  if (!pending) {
    if (isJson) return c.json({ ok: false, message: "会话已失效" }, 401);
    return c.redirect("/login", 302);
  }

  let code = "";
  if (isJson) {
    const body = (await c.req.json().catch(() => null)) as { code?: string } | null;
    code = body?.code ?? "";
  } else {
    const form = await c.req.formData().catch(() => null);
    code = String(form?.get("code") ?? "");
  }

  const result = await callCore<{ ok: boolean; token: string; remaining: number }>(c.env, {
    method: "POST",
    path: "/mfa/verify-recovery",
    payload: { userId: pending.userId, code, sessionId: pending.sessionId },
    ip: c.req.header("cf-connecting-ip") ?? undefined,
  });

  if (!result.ok) {
    if (isJson) return c.json({ ok: false, message: "恢复码无效" }, 401);
    return c.html(<MfaPage error="恢复码无效或已使用" />, 401);
  }

  setSessionCookie(c, result.data.token, TTL.session);
  if (isJson) return c.json({ ok: true, redirect: "/admin", remaining: result.data.remaining });
  return c.redirect("/admin", 303);
});

export { SessionStatus, clearSessionCookie };
