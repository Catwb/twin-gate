import { describe, expect, it } from "vitest";
import { LOCKOUT, PAGE_SIZE, SessionStatus, TTL } from "@sso/shared";

/**
 * 这些常量被硬约束清单直接引用，改动必须有意识。
 */
describe("共享常量契约", () => {
  it("mfa_pending 与会话音量不同", () => {
    expect(SessionStatus.MfaPending).toBe("mfa_pending");
    expect(SessionStatus.Active).toBe("active");
  });

  it("mfa_pending TTL 不超过 5 分钟", () => {
    expect(TTL.mfaPending).toBeLessThanOrEqual(300);
  });

  it("授权码 TTL 为 60 秒", () => {
    expect(TTL.authorizationCode).toBe(60);
  });

  it("分页上限为 25（免费版 CPU 预算）", () => {
    expect(PAGE_SIZE).toBe(25);
  });

  it("账号锁定为 10 次 / 15 分钟", () => {
    expect(LOCKOUT.perAccountFailures).toBe(10);
    expect(LOCKOUT.perAccountSeconds).toBe(900);
  });
});
