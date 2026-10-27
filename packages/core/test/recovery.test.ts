import { describe, expect, it } from "vitest";

/**
 * 恢复码的格式化与归一化是纯函数逻辑，
 * 这里直接测规则，避免为了一张表去搭 D1 mock。
 */
function normalizeCode(code: string): string {
  return code.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
}

describe("恢复码归一化", () => {
  it("忽略分隔符", () => {
    expect(normalizeCode("dc8a7-f7a4a")).toBe("dc8a7f7a4a");
  });

  it("忽略大小写", () => {
    expect(normalizeCode("DC8A7F7A4A")).toBe("dc8a7f7a4a");
  });

  it("不同格式的同一码归一化后相等", () => {
    expect(normalizeCode("dc8a7-f7a4a")).toBe(normalizeCode("DC8A7 F7A4A"));
  });

  it("空格与特殊字符被剥离", () => {
    expect(normalizeCode(" dc8a7 - f7a4a ")).toBe("dc8a7f7a4a");
  });
});
