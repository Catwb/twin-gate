# 部署 Runbook

> 原则：**先 Core 后 Gateway，先库后码，secret 一次性配齐。**

## 0. 前置

| 项 | 确认 |
|---|---|
| 套餐 | Workers **Free** 即可（本方案据此校准） |
| 域名 | **已定死**。issuer 一经对外发布不可更改，别拿 workers.dev 试 |
| 工具 | Node ≥ 20、`pnpm`（**不使用 npm/npx**，`npm install` 会被 `preinstall` 直接阻断） |

## 1. 生成 secret（只出现一次）

```bash
node scripts/gen-secrets.mjs
```

立刻保存到密码管理器：

| secret | 丢了会怎样 |
|---|---|
| `SESSION_PEPPER` | 全部密码作废，**含你自己** |
| `TOTP_MASTER_KEY` | 全部 TOTP secret 解不开（阶段三启用） |
| `GATEWAY_TOKEN` | Gateway 与 Core 无法通信 |
| `SIGNING_KEYS_JSON` | 无法签发 ID Token（阶段二启用） |

⚠️ **pepper 备份必须与 D1 备份分开存放。** 两者一起丢失 = 密码等同明文。

## 2. 建库

```bash
pnpm --filter @sso/core exec wrangler d1 create sso-db
```

把输出的 `database_id` 填进 `packages/core/wrangler.toml`（替换 `REPLACE_WITH_D1_DATABASE_ID`）。

```bash
pnpm --filter @sso/core db:migrate:remote
```

## 2.5 配置签名密钥

阶段二起 Core 需要 `SIGNING_KEYS_JSON`（Ed25519 私钥，JSON 数组，第一项为当前签名密钥）。

```bash
# 值来自 scripts/gen-secrets.mjs 的输出
cd packages/core
pnpm exec wrangler secret put SIGNING_KEYS_JSON
```

首次部署后同步进 D1（也可等下一次 cron 自动同步）：

```bash
curl -X POST https://<gateway>/internal/jwks/sync -H "x-gateway-token: <token>"
```

**密钥轮换**（一年一次）：

1. 在 `SIGNING_KEYS_JSON` 数组**首位**插入新密钥，旧的留在后面；
2. 重新 `wrangler secret put`；
3. 等 ≥ JWKS 缓存 TTL（5 分钟）+ 下游缓存时间；
4. 下游按 `kid` 自动选公钥，旧 ID Token 仍可验；
5. 确认无流量后，从数组中移除旧密钥。

⚠️ 不要"一把梭"直接替换——下游缓存里还是旧 JWKS 时会验签失败，表现为全站登录中断。

## 2.6 配置 TOTP 主密钥

```bash
cd packages/core
pnpm exec wrangler secret put TOTP_MASTER_KEY
```

**必须与 `SESSION_PEPPER` 是两个独立随机值。** 一个泄露不应牵连另一个。
丢了它，所有已启用的 TOTP 全部解不开。

## 3. 部署 Core

```bash
cd packages/core
pnpm exec wrangler secret put GATEWAY_TOKEN
pnpm exec wrangler secret put SESSION_PEPPER
pnpm exec wrangler deploy
```

`wrangler.toml` 已声明 `[secrets] required`，缺任何一个会部署失败。

**验证 Core 不可达：**

```bash
curl -s -o /dev/null -w "%{http_code}" https://<core>.<subdomain>.workers.dev
```

期望：非 200。**这一步没通过，后面全部别做。**

## 4. 部署 Gateway

```bash
cd packages/gateway
pnpm build                      # css -> js -> ssg，顺序不能变
pnpm exec wrangler secret put GATEWAY_TOKEN   # 与 Core 完全相同的值
pnpm exec wrangler deploy
```

⚠️ `GATEWAY_TOKEN` 两边不一致 = 登录页能开、一提交就 500。

## 5. 种子第一个超管

```bash
$env:SESSION_PEPPER='<你的 pepper>'
node scripts/seed-superadmin.mjs --email you@example.com --password '<临时密码>' > seed.sql
cat seed.sql                       # 检查后再执行
pnpm --filter @sso/core exec wrangler d1 execute sso-db --remote --file=./seed.sql
rm seed.sql                        # 执行后立刻删除
```

这是「所有 D1 操作必须经过 Core」的**唯一运维例外**，必须记录。

## 6. 冒烟测试

| # | 测试 | 期望 |
|---|---|---|
| 1 | `GET /login` | 200，静态页，**响应头无 Set-Cookie** |
| 2 | 错误密码 | 401，与「用户不存在」响应完全一致 |
| 3 | 正确密码 | `Set-Cookie: __Host-sid=...; Secure; HttpOnly; SameSite=Lax` |
| 4 | 带 cookie 访问 `/admin/users` | 200 |
| 5 | 不带 cookie | 302 → `/login` |
| 6 | POST 缺 `x-requested-with` | 403 |
| 7 | 连打 20 次错误密码 | 429（账号锁定） |

## 7. 上线后必做

1. **登录后立即绑定 Passkey 或 TOTP** —— 超管未绑定前无法进入任何管理页；
2. 保存 10 个恢复码（只显示一次）；
3. 建第二个 `super_admin`（防止唯一超管失联锁死全租户）；
2. 跑一次 `wrangler d1 export`，确认备份流程可用；
3. 配置 WAF 速率限制规则：`/auth/login` 每 IP 每分钟 10 次。

## 8. 日常

| 频率 | 动作 |
|---|---|
| 每周 | `wrangler d1 export`，存**与 pepper 分开的位置** |
| 每月 | 看 `/admin/audit` 的失败登录分布 |
| 每季 | 检查 `audit_logs` 行数（60 天自动清理） |
| 每年 | Ed25519 密钥轮换（阶段二后） |

## 9. 事故处置

**pepper 疑似泄露**

```
1. 立即轮换 SESSION_PEPPER
2. UPDATE users SET must_change_password = 1
3. 吊销全部 sessions 与 access_tokens（单次 db.batch）
4. 检查 audit_logs 近 7 天异常登录
5. 线下通知全部用户
```

注意：**轮换 pepper 后所有人立刻无法登录**，这是预期行为。

**唯一超管失联** —— 只能通过 `wrangler d1 execute` 直接改库恢复。这正是要求第二超管的原因。