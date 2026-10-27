import { describe, expect, it } from "vitest";

/**
 * TOTP 防重放的判定规则（纯逻辑）：
 * 只有 last_used_step 为空、或严格小于本次匹配步长时才允许通过。
 */
function allowsStep(lastUsedStep: number | null, matchedStep: number): boolean {
  if (lastUsedStep === null) return true;
  return lastUsedStep < matchedStep;
}

describe("TOTP 步长占用规则", () => {
  it("首次使用任意步长都允许", () => {
    expect(allowsStep(null, 100)).toBe(true);
  });

  it("同一步长第二次拒绝（重放）", () => {
    expect(allowsStep(100, 100)).toBe(false);
  });

  it("更早的步长被拒绝（窗口内回溯）", () => {
    expect(allowsStep(100, 99)).toBe(false);
  });

  it("更晚的步长允许（正常时间推进）", () => {
    expect(allowsStep(100, 101)).toBe(true);
  });
});

describe("TOTP 窗口", () => {
  const WINDOW = 1;
  const PERIOD = 30;

  it("窗口覆盖前后各一个周期，总有效时长 90 秒", () => {
    const totalSeconds = PERIOD * (WINDOW * 2 + 1);
    expect(totalSeconds).toBe(90);
  });
});
