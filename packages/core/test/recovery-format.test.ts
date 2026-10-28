import { describe, expect, it } from "vitest";
import {
  RECOVERY_CODE_BYTES,
  RECOVERY_CODE_COUNT,
  RECOVERY_CODE_ENTROPY_BITS,
  formatCode,
  normalizeCode,
} from "../src/services/recovery";

/**
 * 恢复码是「手机丢了」时唯一的自助出路，格式与熵都必须锁死。
 *
 * 曾经的写法是 randomHex(10) 再 slice(0, 10)：生成 20 个十六进制字符只用一个，
 * 熵减半也看不出来 —— 因为没有任何东西把「生成长度」和「截取长度」绑在一起。
 * 现在由 RECOVERY_CODE_BYTES 单点决定，formatCode 长度不符直接抛错。
 */
describe("恢复码格式", () => {
  it("展示为 xxxxx-xxxxx", () => {
    expect(formatCode("a1b2c3d4e5")).toBe("a1b2c-3d4e5");
  });

  it("分隔符只有中间一个连字符", () => {
    const formatted = formatCode("0123456789");
    expect(formatted).toMatch(/^[0-9a-z]{5}-[0-9a-z]{5}$/);
    expect(formatted.split("-")).toHaveLength(2);
  });

  it("长度与 RECOVERY_CODE_BYTES 绑定", () => {
    const expected = RECOVERY_CODE_BYTES * 2;
    expect(formatCode("a".repeat(expected))).toHaveLength(expected + 1);
  });

  it("输入长度不符时抛错，而不是静默截断", () => {
    // 这正是旧实现的问题：多给了 10 个字符也不吭声
    expect(() => formatCode("a".repeat(20))).toThrow(/恢复码长度异常/);
  });
});

describe("恢复码熵", () => {
  it("每个码 40 位熵", () => {
    expect(RECOVERY_CODE_ENTROPY_BITS).toBe(40);
  });

  it("10 个码合计 40 位单码安全边际仍然单次有效", () => {
    expect(RECOVERY_CODE_COUNT).toBe(10);
  });
});

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
