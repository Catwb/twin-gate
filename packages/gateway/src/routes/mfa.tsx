/** @jsxImportSource hono/jsx */
import { Hono } from "hono";
import { SessionStatus, TTL } from "@sso/shared";
import { callCore } from "../core/callCore";
import { clearSessionCookie, getPendingSession, setSessionCookie } from "../middleware/session";
import { MfaPage } from "../pages/mfa";
import type { AppContext } from "../types";

export const mfaRoutes = new Hono<AppContext>();

// getPendingSession 现在在 middleware/session.ts，与登出共用一份实现。
// 旧实现在这里先查 /session/lookup（对 mfa_pending 必然返回 invalid），
// 再查 /session/lookup-pending —— 每次都多一轮 D1 查询。

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
      locked: "尝试次数过多，请稍后再试",
    };
    return fail(messages[result.code] ?? "验证失败");
  }

  // MFA 通过：轮换 token 并升级为完整会话。
  setSessionCookie(c, result.data.token, TTL.session);

  const redirect = result.data.mustChangePassword
    ? "/account/password"
    : result.data.role === "user"
      ? "/account"
      : "/admin";
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

  // 在 /mfa 页点「使用 Passkey」时，浏览器里还留着一条 mfa_pending 会话。
  // 验证成功后会新建 active 会话并覆盖 Cookie，那条 pending 会话就成了孤儿：
  // 没人吊销、也没人清理，白占一行。这里先主动吊销它。
  const pending = await getPendingSession(c);

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

  if (!result.ok) {
    if (result.code === "locked") return c.json({ ok: false, message: "尝试次数过多，请稍后再试" }, 429);
    return c.json({ ok: false, message: "Passkey 验证失败" }, 401);
  }

  // 新会话已建立，把之前那条 mfa_pending 会话吊销掉。
  // best-effort：吊销失败不影响本次登录成功。
  if (pending) {
    await callCore(c.env, {
      method: "POST",
      path: "/session/revoke",
      payload: { sessionId: pending.sessionId, reason: "replaced_by_passkey" },
    }).catch(() => undefined);
  }

  setSessionCookie(c, result.data.token, TTL.session);
  const redirect = result.data.mustChangePassword
    ? "/account/password"
    : result.data.role === "user"
      ? "/account"
      : "/admin";
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
    if (result.code === "locked") {
      if (isJson) return c.json({ ok: false, message: "尝试次数过多，请稍后再试" }, 429);
      return c.html(<MfaPage error="尝试次数过多，请稍后再试" />, 429);
    }
    if (isJson) return c.json({ ok: false, message: "恢复码无效" }, 401);
    return c.html(<MfaPage error="恢复码无效或已使用" />, 401);
  }

  setSessionCookie(c, result.data.token, TTL.session);
  if (isJson) return c.json({ ok: true, redirect: "/admin", remaining: result.data.remaining });
  return c.redirect("/admin", 303);
});

export { SessionStatus, clearSessionCookie };