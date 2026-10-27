/**
 * 阶段三（Passkey / TOTP / 恢复）的硬约束检查。
 */
import { join } from "node:path";

export function registerMfaChecks({ check, readCode, ROOT }) {
  check("TOTP secret 以 AES-GCM 加密存储", () => {
    const aes = readCode(join(ROOT, "packages/core/src/lib/aes.ts"));
    if (!aes.includes('"AES-GCM"')) throw new Error("未使用 AES-GCM");
    if (!aes.includes("deriveKey")) throw new Error("未从主密钥派生");

    const totp = readCode(join(ROOT, "packages/core/src/services/totp.ts"));
    if (!totp.includes("encryptSecret")) throw new Error("TOTP secret 未加密");
    return "ok";
  });

  check("TOTP 主密钥与密码 pepper 是两个独立 secret", () => {
    const types = readCode(join(ROOT, "packages/core/src/types.ts"));
    if (!types.includes("SESSION_PEPPER")) throw new Error("缺少 SESSION_PEPPER");
    if (!types.includes("TOTP_MASTER_KEY")) throw new Error("缺少 TOTP_MASTER_KEY");

    const toml = readCode(join(ROOT, "packages/core/wrangler.toml"));
    if (!toml.includes('"TOTP_MASTER_KEY"')) throw new Error("未声明 TOTP_MASTER_KEY 为必需 secret");
    return "ok";
  });

  check("TOTP 同一时间步不可重放", () => {
    const totp = readCode(join(ROOT, "packages/core/src/services/totp.ts"));
    if (!totp.includes("lastUsedStep")) throw new Error("未记录已用步长");
    if (!totp.includes("lt(mfaFactors.lastUsedStep")) throw new Error("缺少严格递增判定");
    if (!totp.includes("replayed")) throw new Error("未在重放时返回 replayed");
    return "ok";
  });

  check("Passkey 认证后更新 counter", () => {
    const passkey = readCode(join(ROOT, "packages/core/src/services/passkey.ts"));
    const start = passkey.indexOf("export async function completeAuthentication");
    const block = passkey.slice(start, start + 2200);
    if (!block.includes("newCounter")) throw new Error("未使用 newCounter");
    if (!block.includes("set({ counter: newCounter })")) throw new Error("未写回 counter");
    return "ok";
  });

  check("Passkey 注册要求 residentKey 与 userVerification", () => {
    const passkey = readCode(join(ROOT, "packages/core/src/services/passkey.ts"));
    if (!passkey.includes('residentKey: "required"')) throw new Error("未要求可发现凭证");
    if (!passkey.includes('userVerification: "required"')) throw new Error("未要求用户验证");
    if (!passkey.includes('attestationType: "none"')) throw new Error("attestation 应为 none");
    return "ok";
  });

  check("恢复码存哈希且单次使用", () => {
    const recovery = readCode(join(ROOT, "packages/core/src/services/recovery.ts"));
    if (!recovery.includes("sha256Hex")) throw new Error("恢复码未哈希存储");
    // 明文码绝不能进 values():只允许写 codeHash
    if (recovery.includes('code: code') || recovery.includes("code: codes[")) {
      throw new Error("疑似向数据库写入了明文恢复码");
    }
    if (!recovery.includes("isNull(mfaRecoveryCodes.usedAt)")) throw new Error("未做单次使用判定");
    if (!recovery.includes("returning(")) throw new Error("未以受影响行数判定");
    return "ok";
  });

  check("超管重置 MFA 同时吊销会话与令牌", () => {
    const mfa = readCode(join(ROOT, "packages/core/src/routes/mfa.ts"));
    const start = mfa.indexOf('"/mfa/reset"');
    const block = mfa.slice(start, start + 1400);
    if (!block.includes("revokeMfaStatements")) throw new Error("未吊销因子");
    if (!block.includes("revokeAllStatements")) throw new Error("未吊销会话与令牌");
    if (!block.includes("db.batch")) throw new Error("未走单事务");
    if (!block.includes("Role.SuperAdmin")) throw new Error("未限定超管");
    return "ok";
  });

  check("使用恢复码后吊销其余会话", () => {
    const mfa = readCode(join(ROOT, "packages/core/src/routes/mfa.ts"));
    const start = mfa.indexOf('"/mfa/verify-recovery"');
    const block = mfa.slice(start, start + 1600);
    if (!block.includes("revokeAllStatements")) throw new Error("恢复码用后未吊销会话");
    if (!block.includes("keepSessionId")) throw new Error("未保留当前会话");
    return "ok";
  });

  check("MFA 升级轮换会话 token 而非新建", () => {
    const mfa = readCode(join(ROOT, "packages/core/src/routes/mfa.ts"));
    const start = mfa.indexOf('"/mfa/verify-totp"');
    const block = mfa.slice(start, start + 2200);
    if (!block.includes("rotateSessionToken")) throw new Error("未轮换 token");
    if (block.includes("createSession(")) throw new Error("升级时新建了会话，会导致主键冲突与会话固定");
    return "ok";
  });

  check("超管未绑定 MFA 时不得进入后台", () => {
    const gate = readCode(join(ROOT, "packages/gateway/src/middleware/mfaGate.ts"));
    if (!gate.includes("Role.SuperAdmin")) throw new Error("未区分超管");
    if (!gate.includes("/admin/security")) throw new Error("未放行绑定页");
    if (!gate.includes("mfa_binding_required")) throw new Error("缺少拒绝码");

    const admin = readCode(join(ROOT, "packages/gateway/src/routes/admin.tsx"));
    if (!admin.includes("mfaGate")) throw new Error("admin 路由未挂门禁");
    return "ok";
  });

  check("mfa_pending 会话查询与鉴权查询分离", () => {
    const internal = readCode(join(ROOT, "packages/core/src/routes/internal.ts"));
    if (!internal.includes("/session/lookup-pending")) throw new Error("缺少 pending 专用查询");
    const block = internal.slice(internal.indexOf("/session/lookup-pending"), internal.indexOf("/session/lookup-pending") + 1400);
    if (!block.includes("SessionStatus.MfaPending")) throw new Error("未校验 pending 状态");
    return "ok";
  });

  check("Passkey challenge 单次使用且有过期", () => {
    const passkey = readCode(join(ROOT, "packages/core/src/services/passkey.ts"));
    if (!passkey.includes("isNull(passkeyChallenges.consumedAt)")) throw new Error("未做单次判定");
    if (!passkey.includes("gt(passkeyChallenges.expiresAt")) throw new Error("未校验过期");
    if (!passkey.includes("lazyCleanupChallenges")) throw new Error("缺少惰性清理");
    return "ok";
  });
}
