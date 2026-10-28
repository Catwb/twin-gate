import { generateAuthenticationOptions } from "@simplewebauthn/server";
import { eq } from "drizzle-orm";
import type { Db } from "../db/client";
import { passkeys } from "../db/schema";
import { lazyCleanupExpiredChallenges, saveChallenge } from "./passkey";

/**
 * 生成认证选项。
 * 未提供 userId 时走"可发现凭证"路径：不带 allowCredentials，
 * 由浏览器弹出账户选择器 —— 这正是 residentKey: required 的用途。
 */
export async function buildAuthenticationOptionsForUser(
  db: Db,
  params: { userId: string | null; rpId: string },
) {
  let allowCredentials: { id: string; transports?: never }[] | undefined;

  if (params.userId) {
    const rows = await db
      .select({ credentialId: passkeys.credentialId })
      .from(passkeys)
      .where(eq(passkeys.userId, params.userId));
    allowCredentials = rows.map((row) => ({ id: row.credentialId }));
  }

  // 这条路径（尤其是 userId 为 null 的可发现凭证路径）产生的 challenge
  // 不会被按 user_id 的清理碰到，必须先做一次全局过期清理。
  await lazyCleanupExpiredChallenges(db);

  const options = await generateAuthenticationOptions({
    rpID: params.rpId,
    userVerification: "required",
    ...(allowCredentials && allowCredentials.length > 0 ? { allowCredentials } : {}),
  });

  await saveChallenge(db, {
    userId: params.userId,
    challenge: options.challenge,
    type: "login",
  });

  return options;
}