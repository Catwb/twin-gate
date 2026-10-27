/**
 * OIDC 与令牌吊销相关的硬约束检查。
 * 由 scripts/check-constraints.mjs 调用，共享同一套 readCode / check 工具。
 */
import { join } from "node:path";

export function registerOidcChecks({ check, readCode, ROOT }) {
  check("access token 不是 JWT（可吊销的前提）", () => {
    const oidc = readCode(join(ROOT, "packages/core/src/services/oidc.ts"));
    const start = oidc.indexOf("export async function issueAccessToken");
    if (start < 0) throw new Error("未找到 issueAccessToken");
    const block = oidc.slice(start, start + 900);
    if (block.includes("signJwt")) throw new Error("访问令牌被签成了 JWT");
    if (!block.includes("randomHex(32)")) throw new Error("访问令牌不是随机串");
    return "ok";
  });

  check("introspect 对无效令牌返回统一形状", () => {
    const oidc = readCode(join(ROOT, "packages/core/src/services/oidc.ts"));
    const start = oidc.indexOf("export async function introspect");
    const block = oidc.slice(start, start + 1800);
    const count = (block.match(/\{ active: false \}/g) ?? []).length;
    if (count < 3) throw new Error(`无效分支只有 ${count} 处，应覆盖不存在 / 已吊销 / 已过期`);
    return "ok";
  });

  check("revoke 对未知令牌也返回成功", () => {
    const gateway = readCode(join(ROOT, "packages/gateway/src/routes/oauth.tsx"));
    const start = gateway.indexOf('"/oauth/revoke"');
    if (start < 0) throw new Error("未找到 /oauth/revoke");
    const block = gateway.slice(start, start + 1400);

    // 必须无条件成功返回，且不得出现任何错误分支。
    if (!block.includes("{ ok: true }")) throw new Error("未返回 ok");
    if (/status\(40[0-9]\)|, 40[0-9]\)/.test(block)) throw new Error("revoke 存在错误状态码分支");
    if (block.includes("c.json({ error")) throw new Error("revoke 泄露了错误信息");

    // 只有 token / client 都齐全时才真正执行吊销，否则直接返回。
    if (!block.includes("if (clientId && clientSecret && token)")) {
      throw new Error("缺少条件吊销守卫");
    }
    return "ok";
  });

  check("JWKS 只由 public_jwk 生成", () => {
    const keys = readCode(join(ROOT, "packages/core/src/services/signingKeys.ts"));
    const start = keys.indexOf("export async function buildJwks");
    const end = keys.indexOf("export async function listSigningKeys");
    const block = keys.slice(start, end);
    if (block.includes("private_jwk")) throw new Error("buildJwks 读取了私钥材料");
    if (!block.includes("row.publicJwk")) throw new Error("buildJwks 未从 publicJwk 读取");
    return "ok";
  });

  check("私钥不落 D1", () => {
    const schema = readCode(join(ROOT, "packages/core/src/db/schema.ts"));
    const start = schema.indexOf("export const signingKeys");
    const end = schema.indexOf("export const passkeys");
    const block = schema.slice(start, end);
    if (/private/i.test(block)) throw new Error("signing_keys 表出现私钥字段");
    if (!block.includes("publicJwk")) throw new Error("signing_keys 缺少 publicJwk");
    return "ok";
  });

  check("授权码强制 PKCE 且单次使用", () => {
    const oidc = readCode(join(ROOT, "packages/core/src/services/oidc.ts"));
    if (!oidc.includes('method === "S256"')) throw new Error("未限定 S256");
    if (!oidc.includes("isNull(authorizationCodes.usedAt)")) throw new Error("授权码消费未做原子判定");
    if (!oidc.includes("returning()")) throw new Error("未以受影响行数判定");
    return "ok";
  });

  check("ID Token 含 sid 声明", () => {
    const routes = readCode(join(ROOT, "packages/core/src/routes/oidc.ts"));
    if (!routes.includes("sid: sessionId")) throw new Error("ID Token 缺少 sid");
    return "ok";
  });

  check("JWKS 缓存为分钟级", () => {
    const oauth = readCode(join(ROOT, "packages/gateway/src/routes/oauth.tsx"));
    if (!oauth.includes("max-age=300")) throw new Error("JWKS 未设置分钟级缓存");
    if (/max-age=(3600|86400)/.test(oauth)) throw new Error("出现小时级长缓存");
    return "ok";
  });

  check("CSRF 豁免仅限 /oauth/", () => {
    const csrf = readCode(join(ROOT, "packages/gateway/src/middleware/csrf.ts"));
    const match = csrf.match(/EXEMPT_PREFIXES = \[([^\]]*)\]/);
    if (!match) throw new Error("未声明豁免前缀");
    const entries = match[1].split(",").map((x) => x.trim()).filter(Boolean);
    if (entries.length !== 1 || entries[0] !== '"/oauth/"') {
      throw new Error(`豁免范围过大: ${entries.join(", ")}`);
    }
    return "ok";
  });

  check("post_logout_redirect_uri 走白名单校验", () => {
    const oidc = readCode(join(ROOT, "packages/core/src/routes/oidc.ts"));
    if (!oidc.includes("invalid_post_logout_redirect_uri")) throw new Error("缺少白名单校验");
    return "ok";
  });

  check("所有具名方法都有调用者角色校验", () => {
    const file = readCode(join(ROOT, "packages/core/src/routes/oidc.ts"));
    const adminRoutes = ["/client/create", "/client/update", "/client/delete", "/client/rotate-secret", "/keys/list"];
    for (const route of adminRoutes) {
      const start = file.indexOf(`oidcRoutes.post("${route}"`);
      if (start < 0) throw new Error(`未找到 ${route}`);
      const block = file.slice(start, start + 700);
      if (!block.includes("Role.SuperAdmin") && !block.includes("requireAdmin")) {
        throw new Error(`${route} 缺少角色校验`);
      }
    }
    return "ok";
  });
}
