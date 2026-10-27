import { Hono } from "hono";
import { timingSafeEqual } from "./lib/crypto";
import { getDb } from "./db/client";
import { internalRoutes } from "./routes/internal";
import { oidcRoutes } from "./routes/oidc";
import { mfaRoutes } from "./routes/mfa";
import { runCleanup } from "./cron";
import { parseKeySet, syncSigningKeys } from "./services/signingKeys";
import type { Env } from "./types";

type Variables = { db: ReturnType<typeof getDb> };

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

/**
 * 唯一入口校验。Gateway 与 Core 用同一个 GATEWAY_TOKEN，
 * 不匹配一律 401，且不透露任何内部细节。
 *
 * 注意：这是纵深防御，不是安全边界。真正的边界是 Core 无公网路由。
 */
app.use("*", async (c, next) => {
  const provided = c.req.header("x-gateway-token") ?? "";
  const expected = c.env.GATEWAY_TOKEN ?? "";
  if (!expected || !timingSafeEqual(provided, expected)) {
    return c.json({ ok: false, code: "unauthorized" }, 401);
  }
  c.set("db", getDb(c.env.DB));
  await next();
});

app.route("/internal", internalRoutes);
app.route("/internal", oidcRoutes);
app.route("/internal", mfaRoutes);

app.notFound((c) => c.json({ ok: false, code: "not_found" }, 404));

app.onError((err, c) => {
  console.error("core error", err instanceof Error ? err.message : "unknown");
  return c.json({ ok: false, code: "internal" }, 500);
});

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext) {
    const db = getDb(env.DB);

    // 每次 cron 顺便把 secret 里的密钥同步进 D1（幂等），
    // 保证新增 kid 后 JWKS 自动可查，不需要额外的部署步骤。
    if (env.SIGNING_KEYS_JSON) {
      try {
        await syncSigningKeys(db, parseKeySet(env.SIGNING_KEYS_JSON));
      } catch (err) {
        console.error("signing key sync failed", err instanceof Error ? err.message : err);
      }
    }

    ctx.waitUntil(
      runCleanup(db)
        .then((report) => console.log("cleanup", JSON.stringify(report)))
        .catch((err) => console.error("cleanup failed", err instanceof Error ? err.message : err)),
    );
  },
} satisfies ExportedHandler<Env>;