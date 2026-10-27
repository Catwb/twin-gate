import type { Caller, Env } from "../types";

/**
 * 全项目唯一允许出现 env.CORE.fetch 的位置。
 *
 * 身份只走 body —— 客户端自带的 X-Caller-* 头在结构上没有任何落点，
 * 不依赖“记得删头”这种人为纪律。
 */
export type CoreRequest = {
  method: "GET" | "POST";
  path: string;
  caller?: Caller | null;
  payload?: unknown;
  ip?: string;
  userAgent?: string;
};

export type CoreResponse<T> = { ok: true; data: T } | { ok: false; status: number; code: string; message?: string };

export async function callCore<T = unknown>(env: Env, req: CoreRequest): Promise<CoreResponse<T>> {
  const response = await env.CORE.fetch(
    new Request(`https://core.internal/internal${req.path}`, {
      method: req.method,
      headers: {
        "content-type": "application/json",
        "x-gateway-token": env.GATEWAY_TOKEN,
        ...(req.ip ? { "x-caller-ip": req.ip } : {}),
        ...(req.userAgent ? { "x-caller-ua": req.userAgent.slice(0, 200) } : {}),
      },
      body:
        req.method === "POST"
          ? JSON.stringify({ caller: req.caller ?? null, payload: req.payload ?? null })
          : undefined,
    }),
  );

  const text = await response.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }

  if (!response.ok) {
    const err = body as { code?: string; message?: string } | null;
    return {
      ok: false,
      status: response.status,
      code: err?.code ?? "core_error",
      ...(err?.message ? { message: err.message } : {}),
    };
  }

  return { ok: true, data: body as T };
}
