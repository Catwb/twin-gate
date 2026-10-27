import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = resolve(__dirname, "..");
const oauthSource = readFileSync(resolve(ROOT, "src/routes/oauth.tsx"), "utf8");

describe("OIDC 端点安全契约", () => {
  it("authorize 强制要求 state", () => {
    expect(oauthSource).toMatch(/!state/);
  });

  it("authorize 强制要求 PKCE，且只接受 S256", () => {
    expect(oauthSource).toContain("MIN_CODE_CHALLENGE_LENGTH");
    expect(oauthSource).toContain('codeChallengeMethod !== "S256"');
  });

  it("无效 redirect_uri 时不重定向（防开放重定向）", () => {
    // 定位 authorize 处理器内部的错误分支，而不是文件里第一个 if (!result.ok)。
    const authorizeStart = oauthSource.indexOf('"/oauth/authorize"');
    const block = oauthSource.slice(authorizeStart, authorizeStart + 3000);
    expect(block).toContain("invalid_redirect_uri");
    expect(block).toContain("c.text(");
    // 该分支内绝不能出现重定向：用大括号配对精确截取 if 块。
    const start = block.indexOf("if (!result.ok)");
    const open = block.indexOf("{", start);
    let depth = 0;
    let end = open;
    for (let i = open; i < block.length; i++) {
      if (block[i] === "{") depth++;
      else if (block[i] === "}") {
        depth--;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    const errorBranch = block.slice(open, end + 1);
    expect(errorBranch.length).toBeGreaterThan(0);
    expect(errorBranch).not.toContain("c.redirect");
  });

  it("token 响应禁止缓存", () => {
    const index = oauthSource.indexOf('"/oauth/token"');
    const block = oauthSource.slice(index, index + 2500);
    expect(block).toContain('"no-store"');
  });

  it("introspect 异常一律返回 active:false", () => {
    const index = oauthSource.indexOf('"/oauth/introspect"');
    const block = oauthSource.slice(index, index + 1800);
    expect(block).toContain('{ active: false }');
    expect(block).not.toContain("invalid_token");
  });

  it("revoke 对无效输入也返回 200（防探测）", () => {
    const index = oauthSource.indexOf('"/oauth/revoke"');
    const block = oauthSource.slice(index, index + 1200);
    expect(block).toContain("{ ok: true }");
  });

  it("post_logout_redirect_uri 必须命中白名单", () => {
    expect(oauthSource).toContain("postLogoutRedirectUri");
    expect(oauthSource).toContain("logout/validate");
  });

  it("userinfo 只接受 Bearer 头", () => {
    expect(oauthSource).toContain('startsWith("bearer ")');
  });
});
