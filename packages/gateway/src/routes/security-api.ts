import { Hono } from "hono";
import { callCore } from "../core/callCore";
import { mfaGate } from "../middleware/mfaGate";
import { requireAuth } from "../middleware/session";
import { renderSecurityPage } from "./security";
import type { AppContext } from "../types";

export const securityApiRoutes = new Hono<AppContext>();

securityApiRoutes.use("*", requireAuth);
// 超管未绑定 MFA 前不得进入，只能去 /admin/security。
securityApiRoutes.use("*", mfaGate);

securityApiRoutes.post("/security/passkey/options", async (c) => {
  const caller = c.get("caller")!;
  const body = (await c.req.json().catch(() => null)) as { currentPassword?: string } | null;
  const result = await callCore<{ ok: boolean; options: Record<string, unknown> }>(c.env, {
    method: "POST",
    path: "/passkey/register-options",
    caller,
    payload: { currentPassword: body?.currentPassword ?? "" },
  });

  if (!result.ok) {
    const coreErr = result as { code?: string };
    if (coreErr.code === "password_required" || coreErr.code === "invalid_credentials") {
      return c.json({ ok: false, message: "请输入当前密码以确认身份", code: coreErr.code }, 400);
    }
    return c.json({ ok: false, message: "无法生成绑定选项" }, 400);
  }
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

  if (!result.ok) {
    // 把 Core 的 error code 一并带出，前端能区分"域名不匹配"和"用户取消"
    const coreErr = result as { code?: string; message?: string };
    return c.json(
      { ok: false, message: "绑定失败", code: coreErr.code ?? null },
      400,
    );
  }
  return c.json({ ok: true });
});

securityApiRoutes.post("/security/totp/begin", async (c) => {
  const caller = c.get("caller")!;
  const body = (await c.req.json().catch(() => null)) as { currentPassword?: string } | null;
  const result = await callCore<{ ok: boolean; factorId: string; otpauthUri: string }>(c.env, {
    method: "POST",
    path: "/mfa/totp/begin",
    caller,
    payload: { currentPassword: body?.currentPassword ?? "" },
  });

  if (!result.ok) {
    const coreErr = result as { code?: string };
    if (coreErr.code === "password_required" || coreErr.code === "invalid_credentials") {
      return c.json({ ok: false, message: "请输入当前密码以确认身份", code: coreErr.code }, 400);
    }
    return c.json({ ok: false, message: "无法开始启用 TOTP" }, 400);
  }
  return c.json({ ok: true, data: result.data });
});

securityApiRoutes.post("/security/totp/confirm", async (c) => {
  const caller = c.get("caller")!;
  const body = (await c.req.json().catch(() => null)) as { factorId?: string; code?: string } | null;
  if (!body?.factorId) return c.json({ ok: false, message: "缺少 factorId，请重新开始绑定" }, 400);

  const result = await callCore<{ ok: boolean; recoveryCodes: string[] }>(c.env, {
    method: "POST",
    path: "/mfa/totp/confirm",
    caller,
    payload: { factorId: body.factorId, code: body.code ?? "" },
    ip: c.req.header("cf-connecting-ip") ?? undefined,
  });

  if (!result.ok) return c.json({ ok: false, message: "验证码不正确" }, 400);

  // 恢复码只在这一次响应里出现：直接渲染页面，不跳转带查询串。
  return renderSecurityPage(c, { freshCodes: result.data.recoveryCodes, justEnabled: true });
});

securityApiRoutes.post("/security/recovery/regenerate", async (c) => {
  const caller = c.get("caller")!;
  const body = (await c.req.json().catch(() => null)) as { currentPassword?: string } | null;
  const result = await callCore<{ ok: boolean; codes: string[] }>(c.env, {
    method: "POST",
    path: "/mfa/recovery/regenerate",
    caller,
    payload: { currentPassword: body?.currentPassword ?? "" },
  });

  if (!result.ok) return c.json({ ok: false, message: "生成失败" }, 400);

  // 同上：新恢复码直接渲染，不进 URL。
  return renderSecurityPage(c, { freshCodes: result.data.codes });
});