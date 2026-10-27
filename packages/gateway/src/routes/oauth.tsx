import { Hono } from "hono";
import { getCookie } from "hono/cookie";
import { SESSION_COOKIE, TTL } from "@sso/shared";
import { callCore } from "../core/callCore";
import { getSessionCaller, clearSessionCookie } from "../middleware/session";
import {
  discoveryDocument,
  isValidScope,
  MAX_NONCE_LENGTH,
  MAX_STATE_LENGTH,
  MIN_CODE_CHALLENGE_LENGTH,
  normalizeScope,
} from "../lib/oidc";
import type { AppContext } from "../types";

export const oauthRoutes = new Hono<AppContext>();

function oauthError(c: Parameters<typeof callCore>[0] extends never ? never : any, error: string, description: string, status = 400) {
  return c.json({ error, error_description: description }, status);
}

// ---------------------------------------------------------------- discovery

oauthRoutes.get("/.well-known/openid-configuration", (c) => {
  c.header("cache-control", "public, max-age=300");
  return c.json(discoveryDocument(c.env.ISSUER));
});

// ---------------------------------------------------------------- jwks

oauthRoutes.get("/oauth/jwks.json", async (c) => {
  const result = await callCore<{ keys: unknown[] }>(c.env, {
    method: "POST",
    path: "/jwks/build",
  });
  if (!result.ok) return c.json({ keys: [] }, 500);

  // 分钟级缓存。JWKS 是公开信息，但不可做小时级长缓存 ——
  // 否则密钥轮换后下游拿不到新 kid。
  c.header("cache-control", "public, max-age=300");
  return c.json(result.data);
});

// ---------------------------------------------------------------- authorize

oauthRoutes.get("/oauth/authorize", async (c) => {
  const params = new URL(c.req.url).searchParams;
  const clientId = params.get("client_id") ?? "";
  const redirectUri = params.get("redirect_uri") ?? "";
  const responseType = params.get("response_type") ?? "";
  const scope = params.get("scope") ?? "";
  const state = params.get("state") ?? "";
  const nonce = params.get("nonce") ?? "";
  const codeChallenge = params.get("code_challenge") ?? "";
  const codeChallengeMethod = params.get("code_challenge_method") ?? "";

  // 这些错误不能重定向，否则等于开放重定向。
  if (!clientId) return c.text("缺少 client_id", 400);
  if (responseType !== "code") return c.text("仅支持 response_type=code", 400);
  if (!state || state.length > MAX_STATE_LENGTH) return c.text("缺少或非法的 state", 400);
  if (nonce.length > MAX_NONCE_LENGTH) return c.text("非法的 nonce", 400);
  if (codeChallenge.length < MIN_CODE_CHALLENGE_LENGTH) {
    return c.text("PKCE 强制要求：缺少 code_challenge", 400);
  }
  if (codeChallengeMethod !== "S256") return c.text("仅支持 code_challenge_method=S256", 400);
  if (!isValidScope(scope)) return c.text("非法的 scope", 400);

  // 未登录：先跳登录页，登录后回到同一个 URL。
  const session = await getSessionCaller(c);
  if (!session) {
    const original = new URL(c.req.url).pathname + new URL(c.req.url).search;
    return c.redirect(`/login?next=${encodeURIComponent(original)}`, 302);
  }

  const result = await callCore<{ ok: boolean; code: string; expiresAt: number; state: string }>(c.env, {
    method: "POST",
    path: "/authorize/prepare",
    caller: session,
    payload: {
      clientId,
      redirectUri,
      state,
      nonce: nonce || null,
      codeChallenge,
      codeChallengeMethod,
      scope: normalizeScope(scope),
      userId: session.userId,
    },
  });

  if (!result.ok) {
    // 客户端或 redirect_uri 有问题时绝不重定向，直接报错。
    if (result.code === "invalid_redirect_uri" || result.code === "unknown_client") {
      return c.text("无效的客户端或回调地址", 400);
    }
    return c.text("授权请求失败", 400);
  }

  const target = new URL(redirectUri);
  target.searchParams.set("code", result.data.code);
  target.searchParams.set("state", state);
  return c.redirect(target.toString(), 302);
});

// ---------------------------------------------------------------- token

oauthRoutes.post("/oauth/token", async (c) => {
  const contentType = c.req.header("content-type") ?? "";
  let fields: Record<string, string> = {};

  if (contentType.includes("application/x-www-form-urlencoded")) {
    const form = await c.req.formData().catch(() => null);
    if (form) {
      for (const [key, value] of form.entries()) fields[key] = String(value);
    }
  } else if (contentType.includes("application/json")) {
    const body = (await c.req.json().catch(() => null)) as Record<string, string> | null;
    if (body) fields = body;
  }

  if (fields.grant_type !== "authorization_code") {
    return oauthError(c, "unsupported_grant_type", "仅支持 authorization_code", 400);
  }
  for (const field of ["client_id", "client_secret", "code", "redirect_uri", "code_verifier"]) {
    if (!fields[field]) return oauthError(c, "invalid_request", `缺少 ${field}`, 400);
  }

  const result = await callCore<{
    ok: boolean;
    accessToken: string;
    expiresIn: number;
    idToken: string;
    tokenType: string;
    scope: string;
  }>(c.env, {
    method: "POST",
    path: "/token/exchange",
    payload: {
      clientId: fields.client_id,
      clientSecret: fields.client_secret,
      code: fields.code,
      redirectUri: fields.redirect_uri,
      codeVerifier: fields.code_verifier,
    },
  });

  if (!result.ok) {
    if (result.code === "invalid_client") {
      c.header("www-authenticate", 'Basic realm="sso"');
      return oauthError(c, "invalid_client", "客户端认证失败", 401);
    }
    return oauthError(c, "invalid_grant", "授权码无效或已使用", 400);
  }

  c.header("cache-control", "no-store");
  c.header("pragma", "no-cache");
  return c.json({
    access_token: result.data.accessToken,
    token_type: "Bearer",
    expires_in: result.data.expiresIn,
    id_token: result.data.idToken,
    scope: result.data.scope,
  });
});

// ---------------------------------------------------------------- userinfo

oauthRoutes.post("/oauth/userinfo", (c) => handleUserinfo(c));
oauthRoutes.get("/oauth/userinfo", (c) => handleUserinfo(c));

async function handleUserinfo(c: any) {
  const auth = c.req.header("authorization") ?? "";
  const token = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  if (!token) {
    c.header("www-authenticate", 'Bearer realm="sso"');
    return c.json({ error: "invalid_token" }, 401);
  }

  const result = await callCore<{ ok: boolean; userinfo: Record<string, unknown> }>(c.env, {
    method: "POST",
    path: "/userinfo",
    payload: { token },
  });

  if (!result.ok) {
    c.header("www-authenticate", 'Bearer realm="sso", error="invalid_token"');
    return c.json({ error: "invalid_token" }, 401);
  }

  c.header("cache-control", "no-store");
  return c.json(result.data.userinfo);
}

// ---------------------------------------------------------------- introspect

oauthRoutes.post("/oauth/introspect", async (c) => {
  const auth = c.req.header("authorization") ?? "";
  const form = c.req.header("content-type")?.includes("application/x-www-form-urlencoded")
    ? await c.req.formData().catch(() => null)
    : null;

  let clientId = "";
  let clientSecret = "";
  if (auth.toLowerCase().startsWith("basic ")) {
    try {
      const decoded = atob(auth.slice(6).trim());
      const index = decoded.indexOf(":");
      clientId = decodeURIComponent(decoded.slice(0, index));
      clientSecret = decodeURIComponent(decoded.slice(index + 1));
    } catch {
      return c.json({ active: false });
    }
  } else if (form) {
    clientId = String(form.get("client_id") ?? "");
    clientSecret = String(form.get("client_secret") ?? "");
  }

  const token = form ? String(form.get("token") ?? "") : "";
  if (!clientId || !clientSecret || !token) return c.json({ active: false });

  const result = await callCore<Record<string, unknown>>(c.env, {
    method: "POST",
    path: "/introspect",
    payload: { clientId, clientSecret, token },
  });

  // 任何异常都归到 { active: false }，绝不区分原因。
  c.header("cache-control", "no-store");
  return c.json(result.ok ? result.data : { active: false });
});

// ---------------------------------------------------------------- revoke

oauthRoutes.post("/oauth/revoke", async (c) => {
  const form = c.req.header("content-type")?.includes("application/x-www-form-urlencoded")
    ? await c.req.formData().catch(() => null)
    : null;

  const clientId = form ? String(form.get("client_id") ?? "") : "";
  const clientSecret = form ? String(form.get("client_secret") ?? "") : "";
  const token = form ? String(form.get("token") ?? "") : "";

  if (clientId && clientSecret && token) {
    await callCore(c.env, {
      method: "POST",
      path: "/revoke",
      payload: { clientId, clientSecret, token },
    });
  }

  // 按 RFC 7009：token 不存在、客户端无效，一律返回 200。
  return c.json({ ok: true });
});

// ---------------------------------------------------------------- logout

oauthRoutes.get("/oauth/logout", async (c) => {
  const params = new URL(c.req.url).searchParams;
  const clientId = params.get("client_id") ?? "";
  const postLogoutRedirectUri = params.get("post_logout_redirect_uri") ?? "";

  const session = await getSessionCaller(c);
  if (session) {
    await callCore(c.env, {
      method: "POST",
      path: "/session/revoke",
      caller: session,
      payload: { sessionId: session.sessionId, reason: "oidc_logout" },
    });
  }
  clearSessionCookie(c);

  if (!clientId) return c.redirect("/login", 302);

  const result = await callCore<{ ok: boolean; redirect: string | null }>(c.env, {
    method: "POST",
    path: "/logout/validate",
    payload: { clientId, postLogoutRedirectUri: postLogoutRedirectUri || null },
  });

  // post_logout_redirect_uri 必须命中客户端注册的白名单，否则不跳转。
  if (result.ok && result.data.redirect) return c.redirect(result.data.redirect, 302);
  return c.redirect("/login", 302);
});

export { TTL, SESSION_COOKIE, getCookie };
