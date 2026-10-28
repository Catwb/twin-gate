import { createMiddleware } from "hono/factory";
import { Role } from "@sso/shared";
import { callCore } from "../core/callCore";
import type { AppContext } from "../types";

/**
 * 超管强制 MFA 门禁。
 *
 * 漏洞链：超管账号 → 后台明文邀请码 / 重置令牌 → 接管所有人。
 * 所以 super_admin 只要还没绑定任何第二因子，就不允许进入管理后台，
 * 只能待在账户安全页完成绑定。
 *
 * 这条不能延后到"以后再说"——它是整个邀请制模型的前提。
 */

/** 未绑定 MFA 时允许访问的路径前缀。 */
const ALLOWED_PREFIXES = [
  "/account/security", // 绑定页本身，否则永远无法完成绑定
  "/account/password", // 改密页：种子超管可能先被要求改密
  "/account", // 账户首页，提供去绑定页的入口
];

/** 受保护的前缀：命中即要求已绑定 MFA。 */
const PROTECTED_PREFIXES = ["/admin"];

export const mfaGate = createMiddleware<AppContext>(async (c, next) => {
  const caller = c.get("caller");
  if (!caller) return next();

  // 只有超管强制。admin 与 user 可以自行决定。
  if (caller.role !== Role.SuperAdmin) return next();

  const path = c.req.path;

  // 不在受保护范围内，直接放行
  if (!PROTECTED_PREFIXES.some((prefix) => path.startsWith(prefix))) return next();

  // 绑定页与账户页本身必须放行，否则死循环
  if (ALLOWED_PREFIXES.some((prefix) => path.startsWith(prefix))) return next();

  const result = await callCore<{ ok: boolean; totp: boolean; passkey: boolean }>(c.env, {
    method: "POST",
    path: "/mfa/status",
    payload: { userId: caller.userId },
  });

  if (result.ok && (result.data.totp || result.data.passkey)) return next();

  if (path.startsWith("/api/")) {
    return c.json({ ok: false, code: "mfa_binding_required" }, 403);
  }
  return c.redirect("/account/security?require=1", 302);
});
