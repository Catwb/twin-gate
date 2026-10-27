import { Hono } from "hono";
import { callCore } from "../core/callCore";
import { mfaGate } from "../middleware/mfaGate";
import { requireAuth } from "../middleware/session";
import type { AppContext } from "../types";

export const securityApiRoutes = new Hono<AppContext>();

securityApiRoutes.use("*", requireAuth);
// 超管未绑定 MFA 前不得进入，只能去 /admin/security。
securityApiRoutes.use("*", mfaGate);

securityApiRoutes.post("/security/passkey/options", async (c) => {
  const caller = c.get("caller")!;
  const result = await callCore<{ ok: boolean; options: Record<string, unknown> }>(c.env, {
    method: "POST",
    path: "/passkey/register-options",
    caller,
    payload: {},
  });

  if (!result.ok) return c.json({ ok: false, message: "无法生成绑定选项" }, 400);
  return c.json({ ok: true, data: result.data });
});

securityApiRoutes.post("/security/passkey/verify", async (c) => {
  const caller = c.get("caller")!;
  const body = (await c.req.json().catch(() => null)) as {
    challenge?: string;
    response?: unknown;
  } | null;

  if (!body?.challenge || !body?.response) return c.json({ ok: false, message: "请求无效" }, 400);

  const result = await callCore(c.env, {
    method: "POST",
    path: "/passkey/register-verify",
    caller,
    payload: { challenge: body.challenge, response: body.response },
    ip: c.req.header("cf-connecting-ip") ?? undefined,
  });

  if (!result.ok) return c.json({ ok: false, message: "绑定失败" }, 400);
  return c.json({ ok: true });
});

securityApiRoutes.post("/security/totp/begin", async (c) => {
  const caller = c.get("caller")!;
  const result = await callCore<{ ok: boolean; factorId: string; otpauthUri: string }>(c.env, {
    method: "POST",
    path: "/mfa/totp/begin",
    caller,
    payload: {},
  });

  if (!result.ok) return c.json({ ok: false, message: "无法开始启用 TOTP" }, 400);
  return c.json({ ok: true, data: result.data });
});

securityApiRoutes.post("/security/totp/confirm", async (c) => {
  const caller = c.get("caller")!;
  const body = (await c.req.json().catch(() => null)) as { code?: string } | null;

  const result = await callCore<{ ok: boolean; recoveryCodes: string[] }>(c.env, {
    method: "POST",
    path: "/mfa/totp/confirm",
    caller,
    payload: { code: body?.code ?? "" },
    ip: c.req.header("cf-connecting-ip") ?? undefined,
  });

  if (!result.ok) return c.json({ ok: false, message: "验证码不正确" }, 400);
  return c.json({ ok: true, data: result.data });
});

securityApiRoutes.post("/security/recovery/regenerate", async (c) => {
  const caller = c.get("caller")!;
  const result = await callCore<{ ok: boolean; codes: string[] }>(c.env, {
    method: "POST",
    path: "/mfa/recovery/regenerate",
    caller,
    payload: {},
  });

  if (!result.ok) return c.json({ ok: false, message: "生成失败" }, 400);
  return c.json({ ok: true, data: { recoveryCodes: result.data.codes } });
});