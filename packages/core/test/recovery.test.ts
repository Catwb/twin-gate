import { describe, expect, it } from "vitest";
import { normalizeCode } from "../src/services/recovery";

/**
 * 这些用例曾经把 normalizeCode 的实现抄在测试文件里 ——
 * 那样改坏源码测试照样绿。现在直接导入真实实现。
 */
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
