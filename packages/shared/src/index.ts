export const SESSION_COOKIE = "__Host-sid";

/** 会话状态。mfa_pending 永远不得通过 requireAuth。 */
export const SessionStatus = {
  Active: "active",
  MfaPending: "mfa_pending",
} as const;
export type SessionStatus = (typeof SessionStatus)[keyof typeof SessionStatus];

export const Role = {
  SuperAdmin: "super_admin",
  Admin: "admin",
  User: "user",
} as const;
export type Role = (typeof Role)[keyof typeof Role];

export const ROLE_RANK: Record<Role, number> = {
  [Role.User]: 1,
  [Role.Admin]: 2,
  [Role.SuperAdmin]: 3,
};

export const UserStatus = { Active: "active", Disabled: "disabled" } as const;
export type UserStatus = (typeof UserStatus)[keyof typeof UserStatus];

/** 所有时间窗口（秒）。集中定义，禁止散落到业务代码。 */
export const TTL = {
  /** SSO 浏览器会话 */
  session: 7 * 24 * 3600,
  /** MFA 待验证令牌 */
  mfaPending: 5 * 60,
  /** 管理后台访问令牌 */
  accessToken: 3600,
  /** OIDC 授权码 */
  authorizationCode: 60,
  /** WebAuthn challenge */
  webauthnChallenge: 10 * 60,
  /** 邀请码 */
  invitation: 7 * 24 * 3600,
  /** 密码重置令牌 */
  passwordReset: 3600,
  /** 限流窗口 */
  rateLimitWindow: 60,
} as const;

/** 登录失败锁定策略 */
export const LOCKOUT = {
  perAccountFailures: 10,
  perAccountSeconds: 15 * 60,
  perIpFailures: 20,
  perIpSeconds: 60 * 60,
} as const;

/**
 * 第二因子验证限流。
 *
 * 密码登录有账号 + IP 双维度限制，但第二因子此前一次都没有 ——
 * 6 位 TOTP 只有 100 万种可能，不限流等于没有第二因子。
 *
 * 账号维度：TOTP 与恢复码共用同一个桶，换验证方式不重置计数。
 * IP 维度：Passkey 认证前还没有身份，只能按 IP 计。
 */
export const SECOND_FACTOR = {
  perAccountFailures: 10,
  perAccountSeconds: 15 * 60,
  perIpFailures: 30,
  perIpSeconds: 60 * 60,
} as const;

/** 邀请码接受是匿名入口，按 IP 限制。128 位熵不怕猜，怕的是被刷。 */
export const INVITE_LIMIT = {
  perIpFailures: 10,
  perIpSeconds: 60 * 60,
} as const;

/** 管理列表分页 —— 免费版 CPU 预算所限，硬上限 25 */
export const PAGE_SIZE = 25;

/** Cron 每轮删除行数，避免单次执行超时 */
export const CRON_DELETE_BATCH = 200;

export type Caller = {
  userId: string;
  role: Role;
};

export type ApiError = {
  code: string;
  message: string;
};

export const ERR = {
  unauthorized: { code: "unauthorized", message: "未认证" },
  forbidden: { code: "forbidden", message: "无权限" },
  mfaRequired: { code: "mfa_required", message: "需要完成二次验证" },
  invalidCredentials: { code: "invalid_credentials", message: "邮箱或密码不正确" },
  locked: { code: "locked", message: "尝试次数过多，请稍后再试" },
  csrfFailed: { code: "csrf_failed", message: "请求校验失败" },
  notFound: { code: "not_found", message: "不存在" },
  badRequest: { code: "bad_request", message: "请求无效" },
  internal: { code: "internal", message: "服务异常" },
} as const satisfies Record<string, ApiError>;
