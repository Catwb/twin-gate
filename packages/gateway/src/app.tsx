/** @jsxImportSource hono/jsx */
import { Hono } from "hono";
import { SessionStatus } from "@sso/shared";
import { authRoutes } from "./routes/auth";
import { oauthRoutes } from "./routes/oauth";
import { mfaRoutes } from "./routes/mfa";
import { securityRoutes } from "./routes/security";
import { securityApiRoutes } from "./routes/security-api";
import { adminRoutes } from "./routes/admin";
import { adminAppsRoutes } from "./routes/admin-apps";
import { securityMiddleware } from "./middleware/security";
import { csrfMiddleware } from "./middleware/csrf";
import { LoginPage } from "./pages/login";
import { MfaPage } from "./pages/mfa";
import { NotFoundPage } from "./pages/notFound";
import { callCore } from "./core/callCore";
import { setSessionCookie } from "./middleware/session";
import type { AppContext } from "./types";

export function createApp() {
  const app = new Hono<AppContext>();

  app.use("*", securityMiddleware);
  app.use("*", csrfMiddleware);

  // ---- 静态资源 ----
  // 生产环境由 Assets 直接命中，Worker 不执行；开发环境 run_worker_first=true
  // 会把请求交给 Worker，这里显式转发给 ASSETS，保证两种模式行为一致。
  app.get("/assets/*", (c) => c.env.ASSETS.fetch(c.req.raw));

  // ---- 公开静态页（生产环境由 Assets 直接命中，Worker 不执行） ----
  app.get("/login", (c) => c.html(<LoginPage />));
  app.get("/mfa", (c) => c.html(<MfaPage />));

  // ---- 认证 ----
  app.route("/auth", authRoutes);
  app.route("/auth", mfaRoutes);

  // ---- OIDC / OAuth ----
  // 注意路由顺序：/.well-known 必须在根路径之后挂载前声明，这里直接挂在 app 上。
  app.route("/", oauthRoutes);

  // ---- 管理后台（整组受 requireAuth 保护）----
  app.route("/admin", adminRoutes);
  app.route("/admin", adminAppsRoutes);
  app.route("/admin", securityRoutes);
  app.route("/admin", securityApiRoutes);

  app.get("/", (c) => c.redirect("/admin", 302));

  app.notFound((c) => {
    if ((c.req.header("accept") ?? "").includes("text/html")) {
      return c.html(<NotFoundPage />, 404);
    }
    return c.json({ ok: false, code: "not_found" }, 404);
  });

  app.onError((err, c) => {
    console.error("gateway error", err instanceof Error ? err.message : "unknown");
    return c.json({ ok: false, code: "internal" }, 500);
  });

  return app;
}

/**
 * 构建期静态页：只有不依赖用户数据的页面进得了这里。
 * 生产环境它们被 toSSG 预渲染成 HTML，请求走 Assets 直出，零 CPU。
 */
export const staticApp = createApp();

export { SessionStatus, callCore, setSessionCookie };