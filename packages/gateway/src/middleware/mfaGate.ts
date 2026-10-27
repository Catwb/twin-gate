import { createMiddleware } from "hono/factory";
import { Role } from "@sso/shared";
import { callCore } from "../core/callCore";
import type { AppContext } from "../types";

/**
 * 超管强制 MFA 门禁。
 *
 * 漏洞链：超管账号 → 后台明文邀请码 / 重置令牌 → 接管所有人。
 * 所以 super_admin 只要还没绑定任何第二因子，就不允许进入管理后台，
 * 只能待在 /admin/security 完成绑定。
 *
 * 这条不能延后到"以后再说"——它是整个邀请制模型的前提。
 */
const ALLOWED_PATHS = ["/admin/security"];

export const mfaGate = createMiddleware<AppContext>(async (c, next) => {
  const caller = c.get("caller");
  if (!caller) return next();

  // 只有超管强制。admin 与 user 可以自行决定。
  if (caller.role !== Role.SuperAdmin) return next();

  // 绑定页面本身必须放行，否则永远无法完成绑定。
  if (ALLOWED_PATHS.some((path) => c.req.path.startsWith(path))) return next();

  const result = await callCore<{ ok: boolean; totp: boolean; passkey: boolean }>(c.env, {
    method: "POST",
    path: "/mfa/status",
    payload: { userId: caller.userId },
  });

  if (result.ok && (result.data.totp || result.data.passkey)) return next();

  if (c.req.path.startsWith("/admin/security/") || c.req.path.startsWith("/api/")) {
    return c.json({ ok: false, code: "mfa_binding_required" }, 403);
  }
  return c.redirect("/admin/security?require=1", 302);
});
