import { generateAuthenticationOptions } from "@simplewebauthn/server";
import { eq } from "drizzle-orm";
import type { Db } from "../db/client";
import { passkeys } from "../db/schema";
import { saveChallenge } from "./passkey";

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
