import { createMiddleware } from "hono/factory";
import { securityHeaders } from "../lib/security";
import type { AppContext } from "../types";

export const securityMiddleware = createMiddleware<AppContext>(async (c, next) => {
  await next();
  for (const [key, value] of Object.entries(securityHeaders())) {
    c.header(key, value);
  }
});
