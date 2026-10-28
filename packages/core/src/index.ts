import { Hono } from "hono";
import { timingSafeEqual } from "./lib/crypto";
import { getDb } from "./db/client";
import { internalRoutes } from "./routes/internal";
import { oidcRoutes } from "./routes/oidc";
import { mfaRoutes } from "./routes/mfa";
import { runCleanup } from "./cron";
import { parseKeySet, pruneRetiredKeys, syncSigningKeys } from "./services/signingKeys";
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

    // 密钥同步与清理都放进 waitUntil：
    // 两者都不是"必须在本轮返回前完成"的工作，串行 await 只会挤占 10ms CPU 预算，
    // 把真正要紧的清理拖到被截断。稳态下同步只做 1 次 SELECT、0 次写入。
    if (env.SIGNING_KEYS_JSON) {
      ctx.waitUntil(
        syncSigningKeys(db, parseKeySet(env.SIGNING_KEYS_JSON))
          .then(async (changed) => {
            if (changed > 0) {
              // 有变化才可能产生多余的退役公钥，没变化就不用再查一次
              await pruneRetiredKeys(db);
              console.log("signing keys synced", changed);
            }
          })
          .catch((err) => console.error("signing key sync failed", err instanceof Error ? err.message : err)),
      );
    }

    ctx.waitUntil(
      runCleanup(db)
        .then((report) => console.log("cleanup", JSON.stringify(report)))
        .catch((err) => console.error("cleanup failed", err instanceof Error ? err.message : err)),
    );
  },
} satisfies ExportedHandler<Env>;