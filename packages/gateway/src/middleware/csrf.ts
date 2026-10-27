import { createMiddleware } from "hono/factory";
import type { AppContext } from "../types";

/**
 * 同站子域投放是 SameSite=Lax 挡不住的，写操作必须额外要求自定义头。
 * 浏览器跨源请求无法在不触发预检的情况下携带自定义头。
 *
 * 豁免 /oauth/*：这些端点是服务端到服务端调用（客户端后端换令牌、下游 introspect），
 * 不带浏览器 Cookie，CSRF 语义不适用。它们的防伪依赖 client_secret + PKCE。
 */
const CSRF_HEADER = "x-requested-with";
const CSRF_VALUE = "sso-gateway";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const EXEMPT_PREFIXES = ["/oauth/"];

export const csrfMiddleware = createMiddleware<AppContext>(async (c, next) => {
  if (SAFE_METHODS.has(c.req.method)) return next();
  if (EXEMPT_PREFIXES.some((prefix) => c.req.path.startsWith(prefix))) return next();

  // 两种通过方式：
  //   1. 自定义头 —— fetch/JS 调用，跨源时必须预检，预检会失败
  //   2. 同源表单提交 —— 浏览器带 Origin/Referer，跨站提交时值不同
  const provided = c.req.header(CSRF_HEADER);
  if (provided === CSRF_VALUE) {
    await next();
    return;
  }

  if (isSameOriginFormSubmission(c)) {
    await next();
    return;
  }

  if (c.req.path.startsWith("/api/")) {
    return c.json({ ok: false, code: "csrf_failed" }, 403);
  }
  return c.text("请求校验失败", 403);
});

/**
 * 同源表单提交判定。
 * SameSite=Lax 已经挡掉大多数跨站 POST，这里再加一道 Origin 校验。
 * 跨站表单提交会带上攻击者站点的 Origin，与本站不符。
 */
function isSameOriginFormSubmission(c: { req: { header: (name: string) => string | undefined; url: string } }): boolean {
  const origin = c.req.header("origin");
  const referer = c.req.header("referer");
  if (!origin && !referer) return false;

  let requestHost: string;
  try {
    requestHost = new URL(c.req.url).host;
  } catch {
    return false;
  }

  const source = origin ?? referer ?? "";
  try {
    return new URL(source).host === requestHost;
  } catch {
    return false;
  }
}