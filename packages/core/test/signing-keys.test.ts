import { describe, expect, it } from "vitest";
import { planKeyChanges, type KeySet } from "../src/services/signingKeys";

/**
 * 这段逻辑以前一行测试都没有，而它每 15 分钟跑一次。
 *
 * 稳态下必须返回空数组 —— 否则 D1 每天白写 192 行，
 * 而免费版的行写入是共享配额。
 */
function makeKey(kid: string): KeySet["keys"][number] {
  return {
    kid,
    alg: "EdDSA",
    public_jwk: { kty: "OKP", crv: "Ed25519", x: `pub-${kid}` },
    private_jwk: { kty: "OKP", crv: "Ed25519", x: `pub-${kid}`, d: `priv-${kid}` },
  } as KeySet["keys"][number];
}

const TWO_KEYS: KeySet = { keys: [makeKey("k2"), makeKey("k1")] };

describe("密钥同步计划", () => {
  it("空库时两把都要插入", () => {
    const changes = planKeyChanges([], TWO_KEYS, 1000);
    expect(changes).toHaveLength(2);
    expect(changes.every((c) => c.kind === "insert")).toBe(true);
  });

  it("第一把是 active，其余是 retired", () => {
    const changes = planKeyChanges([], TWO_KEYS, 1000);
    expect(changes[0]).toMatchObject({ kid: "k2", status: "active", retiredAt: null });
    expect(changes[1]).toMatchObject({ kid: "k1", status: "retired", retiredAt: 1000 });
  });

  it("已经完全一致的库不产生任何写入", () => {
    const existing = [
      { kid: "k2", status: "active", retiredAt: null },
      { kid: "k1", status: "retired", retiredAt: 500 },
    ];
    expect(planKeyChanges(existing, TWO_KEYS, 1000)).toHaveLength(0);
  });

  it("重复调用依然是零写入（幂等）", () => {
    const existing = [
      { kid: "k2", status: "active", retiredAt: null },
      { kid: "k1", status: "retired", retiredAt: 500 },
    ];
    for (let i = 0; i < 10; i++) {
      expect(planKeyChanges(existing, TWO_KEYS, 1000 + i * 900)).toHaveLength(0);
    }
  });
});

describe("密钥轮换", () => {
  it("新密钥顶到首位时，旧的降级为 retired 并写 retiredAt", () => {
    const existing = [
      { kid: "k1", status: "active", retiredAt: null },
    ];
    const rotated: KeySet = { keys: [makeKey("k2"), makeKey("k1")] };
    const changes = planKeyChanges(existing, rotated, 2000);

    expect(changes).toHaveLength(2);
    expect(changes.find((c) => c.kid === "k2")).toMatchObject({ kind: "insert", status: "active" });
    expect(changes.find((c) => c.kid === "k1")).toMatchObject({
      kind: "update",
      status: "retired",
      retiredAt: 2000,
    });
  });

  it("retired 的键 retiredAt 为 NULL 时补上（历史数据自愈）", () => {
    const existing = [{ kid: "k1", status: "retired", retiredAt: null }];
    const changes = planKeyChanges(existing, TWO_KEYS, 3000);
    const fix = changes.find((c) => c.kid === "k1");
    expect(fix).toMatchObject({ kind: "update", status: "retired", retiredAt: 3000 });
  });

  it("已经是 active 的键不再重复写 active", () => {
    const existing = [{ kid: "k2", status: "active", retiredAt: null }];
    const changes = planKeyChanges(existing, { keys: [makeKey("k2")] }, 4000);
    expect(changes).toHaveLength(0);
  });

  it("active 键带着陈旧的 retiredAt 时会被清空", () => {
    const existing = [{ kid: "k2", status: "active", retiredAt: 999 }];
    const changes = planKeyChanges(existing, { keys: [makeKey("k2")] }, 4000);
    expect(changes).toHaveLength(1);
    expect(changes[0]).toMatchObject({ kind: "update", status: "active", retiredAt: null });
  });
});
