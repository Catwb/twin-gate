import { and, eq, isNull } from "drizzle-orm";
import type { Role } from "@sso/shared";
import type { Db } from "../db/client";
import { users } from "../db/schema";

export type UserRecord = typeof users.$inferSelect;

export async function findUserByEmail(db: Db, email: string): Promise<UserRecord | null> {
  const rows = await db
    .select()
    .from(users)
    .where(and(eq(users.email, email.toLowerCase()), eq(users.status, "active")))
    .limit(1);
  return rows[0] ?? null;
}

export async function findUserById(db: Db, id: string): Promise<UserRecord | null> {
  const rows = await db.select().from(users).where(eq(users.id, id)).limit(1);
  return rows[0] ?? null;
}

export async function roleOf(db: Db, userId: string): Promise<Role | null> {
  const rows = await db
    .select({ role: users.role })
    .from(users)
    .where(and(eq(users.id, userId), eq(users.status, "active")))
    .limit(1);
  const role = rows[0]?.role;
  return (role as Role | undefined) ?? null;
}

export async function markLogin(db: Db, userId: string): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await db.update(users).set({ lastLoginAt: now }).where(eq(users.id, userId));
}

export async function requirePasswordChange(db: Db, userId: string, required: boolean): Promise<void> {
  await db
    .update(users)
    .set({ mustChangePassword: required ? 1 : 0 })
    .where(eq(users.id, userId));
}

/** 管理列表分页：免费版 CPU 预算所限，硬上限 25 行。 */
export async function listUsers(db: Db, limit: number, offset: number) {
  return db
    .select({
      id: users.id,
      email: users.email,
      role: users.role,
      status: users.status,
      lastLoginAt: users.lastLoginAt,
      createdAt: users.createdAt,
    })
    .from(users)
    .orderBy(users.createdAt)
    .limit(limit)
    .offset(offset);
}

export async function countUsers(db: Db): Promise<number> {
  const rows = await db.select({ id: users.id }).from(users);
  return rows.length;
}

export async function setUserStatus(db: Db, userId: string, status: "active" | "disabled") {
  await db.update(users).set({ status }).where(eq(users.id, userId));
}

export async function setUserRole(db: Db, userId: string, role: Role) {
  await db.update(users).set({ role }).where(eq(users.id, userId));
}

export async function activeSuperAdminCount(db: Db): Promise<number> {
  const rows = await db
    .select({ id: users.id })
    .from(users)
    .where(and(eq(users.role, "super_admin"), eq(users.status, "active")));
  return rows.length;
}

export async function insertUser(
  db: Db,
  params: { id: string; email: string; passwordHash: string; role: Role; mustChangePassword: boolean },
) {
  await db.insert(users).values({
    id: params.id,
    email: params.email.toLowerCase(),
    passwordHash: params.passwordHash,
    role: params.role,
    status: "active",
    mustChangePassword: params.mustChangePassword ? 1 : 0,
    createdAt: Math.floor(Date.now() / 1000),
  });
}

export { isNull };
