import { desc, eq } from "drizzle-orm";
import type { Db } from "../db/client";
import { apps } from "../db/schema";
import { randomHex, sha256Hex } from "../lib/crypto";
import { nowSeconds } from "../lib/time";

export type CreatedApp = {
  clientId: string;
  /** 明文 secret 只此一次返回，D1 存哈希。 */
  clientSecret: string;
};

export async function createApp(
  db: Db,
  params: {
    name: string;
    redirectUris: string[];
    postLogoutRedirectUris?: string[];
  },
): Promise<CreatedApp> {
  const clientId = `app-${randomHex(8)}`;
  const clientSecret = randomHex(32);
  const clientSecretHash = await sha256Hex(clientSecret);

  await db.insert(apps).values({
    clientId,
    clientSecretHash,
    name: params.name,
    redirectUris: JSON.stringify(params.redirectUris),
    postLogoutRedirectUris: JSON.stringify(params.postLogoutRedirectUris ?? []),
    createdAt: nowSeconds(),
  });

  return { clientId, clientSecret };
}

export async function listApps(db: Db, limit: number, offset: number) {
  return db
    .select({
      clientId: apps.clientId,
      name: apps.name,
      redirectUris: apps.redirectUris,
      createdAt: apps.createdAt,
    })
    .from(apps)
    .orderBy(desc(apps.createdAt))
    .limit(limit)
    .offset(offset);
}

export async function deleteApp(db: Db, clientId: string): Promise<void> {
  await db.delete(apps).where(eq(apps.clientId, clientId));
}

export async function updateApp(
  db: Db,
  clientId: string,
  params: { name?: string; redirectUris?: string[]; postLogoutRedirectUris?: string[] },
): Promise<void> {
  const patch: Record<string, unknown> = {};
  if (params.name !== undefined) patch.name = params.name;
  if (params.redirectUris !== undefined) patch.redirectUris = JSON.stringify(params.redirectUris);
  if (params.postLogoutRedirectUris !== undefined) {
    patch.postLogoutRedirectUris = JSON.stringify(params.postLogoutRedirectUris);
  }
  if (Object.keys(patch).length === 0) return;
  await db.update(apps).set(patch).where(eq(apps.clientId, clientId));
}

/** 轮换 client secret —— 旧值立刻失效。 */
export async function rotateClientSecret(db: Db, clientId: string): Promise<string> {
  const clientSecret = randomHex(32);
  const clientSecretHash = await sha256Hex(clientSecret);
  await db.update(apps).set({ clientSecretHash }).where(eq(apps.clientId, clientId));
  return clientSecret;
}
