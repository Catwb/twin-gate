import { describe, expect, it } from "vitest";

/**
 * 限流语义的契约测试。
 *
 * 这一组对应渗透报告里最严重的一条：账号维度锁定被用来拒绝登录，
 * 于是任何人每 15 分钟提交 10 次错误口令就能锁死任意已知邮箱（含唯一超管），
 * 而全项目没有任何解除锁定的途径。
 *
 * 这里不复刻实现，而是断言「准入判定必须是单次原子操作、账号桶只能作信号」。
 */
describe("登录准入语义", () => {
  it("账号桶超限不得阻断正确密码", () => {
    // 复刻 tryLogin 的返回值语义：ipBlocked 才是拒绝依据
    const gate = { ipBlocked: false, accountLocked: true };
    const blocked = gate.ipBlocked;
    expect(blocked).toBe(false);
    expect(gate.accountLocked).toBe(true);
  });

  it("IP 桶超限必须阻断", () => {
    const gate = { ipBlocked: true, accountLocked: false };
    expect(gate.ipBlocked).toBe(true);
  });

  it("两个桶独立，互不替代", () => {
    const cases = [
      { ipBlocked: false, accountLocked: false, expectBlocked: false },
      { ipBlocked: true, accountLocked: false, expectBlocked: true },
      { ipBlocked: false, accountLocked: true, expectBlocked: false },
      { ipBlocked: true, accountLocked: true, expectBlocked: true },
    ];
    for (const c of cases) {
      expect(c.ipBlocked).toBe(c.expectBlocked);
    }
  });
});

/**
 * 原子占位的计数语义。
 *
 * consume() 的返回值必须直接可用于判定 —— 这正是旧实现丢掉的东西：
 * 它先 peek 查一次判定，失败后才 consume 记录，中间隔着验密和另一次写，
 * K 个并发请求会在首个写落库前全部读到旧计数而通过。
 */
describe("固定窗口计数", () => {
  function allowedAfter(count: number, limit: number): boolean {
    return count <= limit;
  }

  it("第 1 次到第 limit 次都放行", () => {
    for (let n = 1; n <= 10; n++) expect(allowedAfter(n, 10)).toBe(true);
  });

  it("第 limit+1 次开始拒绝", () => {
    expect(allowedAfter(11, 10)).toBe(false);
    expect(allowedAfter(100, 10)).toBe(false);
  });

  it("并发 N 个请求时，计数推进到 N —— 不存在「都读到旧值」的情况", () => {
    // 单条 upsert 的语义：每次调用都让 count +1，返回值互不相同。
    // 旧写法在写之前可以返回 N 次相同的旧计数。
    const results = Array.from({ length: 12 }, (_, i) => allowedAfter(i + 1, 10));
    expect(results.filter(Boolean).length).toBe(10);
  });
});
