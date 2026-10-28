import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Cron 与签名密钥的门禁。
 *
 * 免费版 Cron 每次只有 10ms CPU，而它每 15 分钟跑一次、一天 96 次。
 * 任何"每轮都做一次多余的写"都会乘以 96，且和其它 Worker 共享 D1 写入配额。
 *
 * 三个真实问题：
 *   1. 稳态下仍然无条件 UPDATE 每把密钥（96 tick × 2 把 = 192 行/天，全是同一个值）
 *   2. 同步用 await 串行阻塞，挤占本该留给清理的预算
 *   3. retiredAt 在降级时从不写入，这个字段对降级的键永远为 NULL
 */
export function checkCronHygiene({ check, ROOT }) {
  const read = (rel) => readFileSync(join(ROOT, rel), "utf8");

  check("Cron：密钥同步稳态零写入", () => {
    const keys = read("packages/core/src/services/signingKeys.ts");

    // 必须有"先算差异、无差异就返回"的路径
    if (!/计划|planKeyChanges|changes\.length === 0/.test(keys)) {
      throw new Error("syncSigningKeys 没有跳过无变化写入的路径，每轮都会白写");
    }
    if (!/if \(changes\.length === 0\) return 0;/.test(keys)) {
      throw new Error("缺少数值相等时提前返回，稳态仍会产生写入");
    }

    // 循环里不得出现无条件 update
    const loop = keys.slice(keys.indexOf("for (const [index, key]"), keys.indexOf("export async function"));
    if (/else \{\s*await db\s*\.update/.test(loop)) {
      throw new Error("循环里仍然无条件 UPDATE；只有真的变了才该写");
    }

    // 写入必须合并成一次 batch
    if (!keys.includes("await db.batch(")) {
      throw new Error("多次写入应合并为一次 batch（D1 单事务单往返）");
    }
  });

  check("Cron：retiredAt 与 status 同步维护", () => {
    const keys = read("packages/core/src/services/signingKeys.ts");

    // 降级时必须写 retiredAt
    if (!/retiredAt: status === "active" \? null : now/.test(keys) && !/wantRetiredAt/.test(keys)) {
      throw new Error("降级为 retired 时没有写 retiredAt，字段永远是 NULL");
    }

    // active 的键必须清空 retiredAt
    if (!/retiredAt: null|\? current\.retiredAt \?\? now : null/.test(keys)) {
      throw new Error("active 的键没有清空 retiredAt，字段会残留旧值");
    }
  });

  check("Cron：所有任务放进 waitUntil，不串行阻塞", () => {
    const entry = read("packages/core/src/index.ts");
    const scheduled = entry.slice(entry.indexOf("async scheduled("));

    if (!/ctx\.waitUntil\([\s\S]*runCleanup/.test(scheduled)) {
      throw new Error("runCleanup 没有放进 waitUntil");
    }
    if (!/ctx\.waitUntil\([\s\S]*syncSigningKeys/.test(scheduled)) {
      throw new Error("syncSigningKeys 仍在 await 串行，会挤占清理的 CPU 预算");
    }
    // 不得在 scheduled 里直接 await 这两个慢任务
    if (/^\s*await syncSigningKeys/m.test(scheduled)) {
      throw new Error("scheduled 里仍然直接 await syncSigningKeys");
    }
  });

  check("Cron：signing_keys 超出保留窗口会被清理", () => {
    const keys = read("packages/core/src/services/signingKeys.ts");
    if (!/export async function pruneRetiredKeys/.test(keys)) {
      throw new Error("退役公钥没有清理路径，每次轮换净增一行");
    }

    // 清理必须挂在写路径（cron / 同步）上，不能挂在 JWKS 读路径上 ——
    // 读接口每次被下游轮询都顺手写一次库，是另一类污染。
    const jwks = keys.slice(keys.indexOf("export async function buildJwks"));
    if (/await pruneRetiredKeys\(db\)/.test(jwks)) {
      throw new Error("buildJwks 是只读路径，不得在其中写库");
    }

    const cron = read("packages/core/src/cron.ts");
    if (!/report\.signingKeys = await pruneRetiredKeys\(db\)/.test(cron)) {
      throw new Error("pruneRetiredKeys 没有挂到 cron 上");
    }

    // 保留数量与 JWKS 输出数量必须用同一个常量
    const retiredQuery = jwks.slice(jwks.indexOf('eq(signingKeys.status, "retired")'));
    if (!retiredQuery.includes("RETAINED_RETIRED_KEYS")) {
      throw new Error("JWKS 输出与清理用的保留常量不一致，会删掉仍在输出的键");
    }
  });
}
