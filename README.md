# twin-gate

部署在 Cloudflare Workers 上的单租户 SSO / OIDC 身份提供方。
面向「自用 + 偶尔给少数人开号」的场景，按 Workers 免费版预算设计。

> **定位：单租户 · ≤10 人 · Workers 免费版**
>
> 不是多租户 SaaS，不是企业级 IdP。范围外的东西写在 [SECURITY.md](SECURITY.md) 里。

```
两个 Worker，一道边界
┌──────────────────────────────────────────────┐
│  sso-gateway   公网                          │
│  ├─ Service Binding → Core                   │
│  └─ Workers Assets（登录页 / MFA 页 / 静态资源）│
└────────────────┬─────────────────────────────┘
                 │  X-Gateway-Token + 身份在 body
┌────────────────▼─────────────────────────────┐
│  sso-core      无公网路由                     │
│  ├─ D1（唯一数据访问层）                       │
│  └─ Cron（分批清理）                          │
└──────────────────────────────────────────────┘
```

## 它解决什么

给自己的几个应用提供统一登录，而不是为每个应用写一套账号系统。

- **OIDC 授权码流程**（PKCE S256 + state + nonce 强制）
- **Passkey + 密码**双登录通道，权重相同
- **TOTP 二次验证**，secret 加密存储
- **即时可吊销的访问令牌**（不透明串 + 内省端点）
- **单租户**，≤ 10 人规模

## 快速开始

```bash
pnpm install
pnpm --filter @sso/core db:migrate:local
pnpm dev:core      # 8788
pnpm dev:gateway   # 8787
```

复制 `.dev.vars.example` 为 `.dev.vars` 并填入值（或用 `node scripts/gen-secrets.mjs` 生成）。

本地管理员：`admin@local.test` / `admin-local-test-1234`（仅开发环境，见 `scripts/seed-superadmin.mjs`）

## 文档

| 文档 | 内容 |
|---|---|
| [docs/deploy.md](docs/deploy.md) | **第一次部署从这里开始**（Git → Workers Builds） |
| [docs/runbook.md](docs/runbook.md) | 日常运维速查 |
| [docs/下游集成.md](docs/下游集成.md) | 给接入方看的 OIDC 集成指南 |
| [SECURITY.md](SECURITY.md) | 威胁模型、能防什么、不防什么 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献规则与不可动的架构约束 |

## 部署形态

**GitHub Actions 全程部署，手动触发。**

| Workflow | 触发 | 作用 |
|---|---|---|
| `verify.yml` | push 自动 | 类型检查 + 单测 + 28 条门禁 + 构建 |
| `deploy.yml` | **手动** | guard → verify → build → 建库 → 部署 Core → 部署 Gateway → 冒烟测试 |

部署不需要本地操作。本地只负责：种子第一个超管、查库、导出备份、应急回滚。

`database_id` 不写进仓库 —— workflow 每次运行时动态查询后注入。

详见 [docs/deploy.md](docs/deploy.md)。

## 验证

```bash
pnpm verify      # 类型检查 + 单测 + 28 条硬约束门禁
```

门禁只查**测试测不到的架构约束**，按领域聚合成 28 条：

| 组 | 覆盖 |
|---|---|
| 部署边界 | Core 不可达、Gateway 绑定面最小 |
| 身份传播 | 身份只走 body、Core 无 SQL 透传 |
| 密码与会话 | HMAC、`__Host-`、Cookie 属性 |
| OIDC | 令牌可吊销、PKCE 强制、私钥不落库 |
| MFA 数据 | secret 加密、防重放、单次使用 |
| 第二因子 | 三道门户都有限流与会话绑定、桶必须真的接线 |
| 管理端反馈 | done/error 有人读、写操作检查返回值、role 传下去 |
| 前端路径 | 脚本里的 URL 都有对应路由 |
| 危险动作 | 重置/恢复/改密后的会话处理 |
| Cron 卫生 | 稳态零写入、retiredAt 跟随 status、读路径不写库 |
| 公开仓库卫生 | 不泄露真实域名与 database_id |

判定标准：**改了会导致数据泄露、认证绕过或部署失效，且测试覆盖不到。**
改错后测试立刻会红的，交给测试，不加门禁。

## 结构

```
packages/
  shared/    常量与类型（角色、TTL、分页上限）
  core/      唯一数据访问层。无公网路由，仅 D1 + Cron
  gateway/   公网入口。仅 Service Binding + Assets
scripts/     secret 生成、种子超管、建客户端、约束门禁
docs/        部署、运维、下游集成
```

## 设计取舍（有意为之，不是缺陷）

- **密码用 HMAC-SHA256 + pepper，不用 PBKDF2** —— 免费版每次请求只有 10ms CPU，且 workerd 对 PBKDF2 有 10 万次迭代硬上限。代价是 pepper 成为唯一防线，配合强制 MFA 与限流。
- **不签发 refresh token** —— 访问令牌 1 小时过期后靠会话 Cookie 静默重授权，用户无感。引入 refresh token 要处理轮换与重放检测，复杂度远超收益。
- **不发邮件** —— 邀请码与重置令牌后台一次性明文显示，线下转达。适合小团队。
- **ID Token 不可吊销** —— OIDC 协议限制。已写入 `sid` 声明，为将来补 Back-channel Logout 留钩子。

完整清单见 [SECURITY.md](SECURITY.md)。

## 不适用于

- 多租户 SaaS（没有 `tenant_id`）
- 数百人以上规模（分页上限 25 是 CPU 预算决定的）
- 需要合规审计留存 180 天以上的场景（免费版 D1 单库 500MB）

## License

[MIT](LICENSE)