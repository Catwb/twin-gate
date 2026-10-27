# 部署指南（Deploy Guide）

> 目标读者：第一次把这套 SSO 部署到 Cloudflare 的人。
>
> **部署形态：Git 导入 + Workers Builds。** 仓库推到 GitHub/GitLab，两个 Worker 各自连同一个仓库、
> 各自指定 root directory，push 即构建部署。本地 `wrangler` 只负责建库、迁移、种子和应急。
>
> 全程只用 **pnpm**。`npm install` / `npx` 会被 `scripts/preinstall.mjs` 直接阻断，这是故意的。

---

## 0. 部署形态一览

```
        git push
           │
           ▼
  ┌────────────────────┐        ┌────────────────────┐
  │  Workers Builds    │  ×2   │  Workers Builds    │
  │  root: packages/   │        │  root: packages/   │
  │        core        │        │        gateway     │
  │  build: (空)        │        │  build: pnpm build │
  │  deploy: wrangler  │        │  deploy: wrangler  │
  └─────────┬──────────┘        └─────────┬──────────┘
            ▼                             ▼
      sso-core                       sso-gateway
   （无公网路由）                    （自定义域名）
     D1 + Cron                  Service Binding + Assets
```

本地只做四件事：建 D1、跑迁移、种子超管、导出备份。其余全由 Git 驱动。

---

## 目录

1. [部署前必须想清楚的四件事](#1-部署前必须想清楚的四件事)
2. [环境要求](#2-环境要求)
3. [仓库结构与部署产物](#3-仓库结构与部署产物)
4. [第一次部署（Git 连接 Workers Builds）](#4-第一次部署git-连接-workers-builds)
5. [验证清单](#5-验证清单)
6. [配置 OIDC 下游应用](#6-配置-oidc-下游应用)
7. [日常运维](#7-日常运维)
8. [密钥轮换](#8-密钥轮换)
9. [事故处置](#9-事故处置)
10. [常见问题](#10-常见问题)

---

## 1. 部署前必须想清楚的四件事

这四件事一旦做了就很难回头，请在动手前定死。

### 1.1 域名 —— issuer 一经发布不可更改

`issuer` 是 OIDC 协议里下游客户端**注册时写死**的标识。换域名等于所有下游应用重新注册一次。

- ✅ 第一次就用**最终域名**，例如 `https://sso.your-domain.com`
- ❌ 不要拿 `*.workers.dev` 预览域名试水
- ❌ 不要先用临时域名再换

Gateway 部署在自定义域名上；Core 不需要域名（它本来就不该被访问到）。

### 1.2 套餐 —— 免费版能用，但要知道边界

本项目按 **Workers 免费版**的预算设计（详见方案 v5.2）。关键数字：

| 资源 | 免费额度 | 本方案的用量 |
|---|---|---|
| 请求 | 10 万/天 | 几百到几千 |
| **CPU/次** | **10 ms** | 密码登录约 1 ms，Passkey 约 5 ms |
| D1 行读 | 500 万/天 | 数千 |
| D1 行写 | 10 万/天 | 数百 |
| **D1 单库** | **500 MB** | 审计保留 60 天，约 100–200 MB |
| Cron | 5 个 | 1 个 |

两条硬性推导，改代码前请记住：

- **管理列表分页上限 25 条**（`PAGE_SIZE`）。渲染 100 行表格会吃掉 2–4 ms CPU，余量不够。
- **Cron 清理必须分批**（每轮 `LIMIT 200`）。一条 SQL 扫全表必超 10 ms。

> 密码哈希用的是 **HMAC-SHA256 + pepper**，不是 PBKDF2。
> 原因：Workers 免费版 10 ms CPU 跑不动 60 万次迭代，而且 workerd 对 PBKDF2 有 10 万次的硬上限。
> 代价是 `SESSION_PEPPER` 成为唯一防线 —— 见 1.3。

### 1.3 公开仓库意味着什么

如果你把 fork 推到**公开**仓库，请先明确这一点：

> **你的架构、弱点、默认配置都是公开的。**

这不必然是坏事——本项目的安全模型**不依赖保密**（Kerckhoffs 原则）。
但公开后有几个具体后果要在部署时确认：

| 公开信息 | 后果 | 你要做的 |
|---|---|---|
| 所有端点路径 | 攻击者不必扫描即可直接打 `/auth/login` | **必须**配 WAF 速率限制 |
| 密码用 HMAC 而非 PBKDF2 | 知道 pepper 是唯一防线 | **必须**离线备份 pepper，且与 D1 备份分开 |
| 默认管理员邮箱格式 | 可能被定向尝试 | 用非 `admin@` 的邮箱做超管 |
| 分页上限 25、审计保留 60 天 | 知道你的容量边界 | 无需处理 |
| 所有约束门禁内容 | 知道哪些检查会被跑 | 不要为了"过 CI"删门禁 |

**绝对不要**在公开仓库里放：

- `.dev.vars`（已在 `.gitignore`）
- 任何真实 `database_id`（模板里是 `REPLACE_WITH_D1_DATABASE_ID`）
- 种子导出的 `seed.sql`（含密码哈希，虽不可逆但没必要）
- 备份文件 `backup-*.sql`
- 你自己的生产域名（模板里是 `sso.your-domain.com`）

推送前自查：

```bash
git ls-files | grep -E "dev[.]vars|seed[.]sql|backup-|dist/"
# 应该没有任何输出

git grep -nE "sso[.]your-real-domain|sk-[a-zA-Z0-9]{20}" -- . ':!pnpm-lock.yaml'
# 应该没有自己的真实域名与任何形似 API key 的串
```

### 1.4 三个 secret 决定生死

| secret | 丢了会怎样 |
|---|---|
| `SESSION_PEPPER` | 所有 `password_hash` 作废，**包括你自己的密码** |
| `TOTP_MASTER_KEY` | 所有已启用的 TOTP 验证器全部解不开 |
| `SIGNING_KEYS_JSON` | 无法签发 ID Token，所有下游登录中断 |

**部署第一件事就是生成并离线保存这三个值。** 并且记住一条纪律：

> `SESSION_PEPPER` 的备份必须和 D1 备份**分开存放**。
> 两者一起丢失 = 密码等同明文。

---

## 2. 环境要求

| 项 | 要求 | 检查命令 |
|---|---|---|
| Node.js | ≥ 20 | `node -v` |
| pnpm | 10.x | `pnpm -v` |
| Cloudflare 账号 | 免费版即可 | — |
| Wrangler | 4.152.0（已锁在 devDependencies） | `pnpm exec wrangler --version` |

首次使用需要登录 Cloudflare：

```bash
pnpm exec wrangler login
```

> 如果 CI 环境无法交互登录，用 `CLOUDFLARE_API_TOKEN` 环境变量代替。

---

## 3. 仓库结构与部署产物

```
sso/
├── packages/
│   ├── shared/          常量与类型（角色、TTL、分页上限）
│   ├── core/            ★ 无公网路由，仅 D1 + Cron
│   │   ├── migrations/  D1 迁移（0001_init.sql、0002_mfa.sql）
│   │   ├── src/
│   │   └── wrangler.toml
│   └── gateway/         ★ 公网入口，仅 Service Binding + Assets
│       ├── public/      构建产物输入（CSS/JS/_headers）
│       ├── dist/        Assets 目录（构建输出）
│       ├── build.tsx    toSSG 预渲染
│       └── wrangler.toml
├── scripts/
│   ├── preinstall.mjs       强制 pnpm
│   ├── gen-secrets.mjs      生成四个 secret
│   ├── seed-superadmin.mjs  生成种子超管 SQL
│   └── check-constraints.mjs 硬约束门禁
├── docs/
└── pnpm-workspace.yaml
```

**两个部署单元**：

| Worker | 产物 | 公网 | 绑定 |
|---|---|---|---|
| `sso-core` | `packages/core/src/index.ts` | **否** | D1 ×1 + Cron |
| `sso-gateway` | `packages/gateway/dist`（Assets）+ `src/worker.ts` | 是 | Service Binding + Assets |

---

## 4. 第一次部署（Git 连接 Workers Builds）

> 主线是 **Git 导入**：仓库推到 GitHub/GitLab，两个 Worker 各自连接同一个仓库、各自指定 root directory。
> 本地 `wrangler deploy` 只在首次建库与应急时使用。

### 4.0 为什么是「两个 Worker 连同一个仓库」

`sso-core` 与 `sso-gateway` 是两个独立 Worker，但共享一个 monorepo。
Workers Builds 的 monorepo 做法是：**每个 Worker 连一次同一个仓库，各自设置 root directory**。

| Worker | Root directory | Build command | Deploy command |
|---|---|---|---|
| `sso-core` | `packages/core` | （留空） | `pnpm exec wrangler deploy` |
| `sso-gateway` | `packages/gateway` | `pnpm build` | `pnpm exec wrangler deploy` |

两条硬性要求，踩了会直接 build 失败：

1. **Worker 名必须与 `wrangler.toml` 里的 `name` 完全一致**（`sso-core` / `sso-gateway`）。
   Dashboard 建 Worker 时名字写错，构建立刻报 workers-name 错误。
2. **root directory 的 `package.json` 必须声明 `packageManager`**。
   本项目三个 `package.json`（根、core、gateway）都写了 `"packageManager": "pnpm@10.34.4"`，无需改动。

> 构建镜像默认带 pnpm 10.11.1，我们的 `packageManager` 会把它升到 10.34.4。
> 工作区的 `workspace:*` 协议由 pnpm 解析 —— **npm 会直接失败**，这也是仓库里 `preinstall.mjs` 强制 pnpm 的原因。

---

### 步骤 1：把仓库推到 Git

```bash
git init
git add .
git commit -m "初始提交"
git remote add origin git@github.com:<you>/sso.git
git push -u origin main
```

**推送前确认这些没被提交**（`.gitignore` 已覆盖）：

| 不该入库 | 原因 |
|---|---|
| `.dev.vars` | 本地开发用 secret |
| `dist/`、`packages/gateway/public/assets/` | 构建产物，CI 会重新生成 |
| `*.sql`（除 migrations） | 种子/备份文件含密码哈希 |
| `.wrangler/` | 本地状态 |

验证一下：

```bash
git ls-files | grep -E "dev[.]vars|dist/|public/assets|seed[.]sql"
# 应该没有任何输出
```

---

### 步骤 2：生成并保存 secret（本地做，不进仓库）

```bash
node scripts/gen-secrets.mjs
```

输出四个值，**立刻保存到密码管理器**：

```
SESSION_PEPPER=<44 字符>
TOTP_MASTER_KEY=<44 字符>
GATEWAY_TOKEN=<44 字符>
SIGNING_KEYS_JSON=[{"kid":"k20261027",...}]
```

> 存放纪律见第 1.4 节：`SESSION_PEPPER` 的备份必须与 D1 备份**分开存放**。

---

### 步骤 3：创建 D1 数据库（本地执行一次）

Git 部署**不会**替你建库，这一步必须在本地做。

```bash
pnpm install
pnpm --filter @sso/core exec wrangler d1 create sso-db
```

把输出的 `database_id` 填进 `packages/core/wrangler.toml`：

```toml
[[d1_databases]]
binding = "DB"
database_name = "sso-db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # ← 替换
migrations_dir = "migrations"
```

**提交这个改动并推送。** CI 需要它才能找到数据库。

> `database_id` 不是凭证，可以入库。绝不能入库的是 password / pepper / 私钥 / API token。

---

### 步骤 4：应用数据库迁移（本地执行一次）

```bash
pnpm --filter @sso/core db:migrate:remote
```

期望两个迁移都成功：

```
0001_init.sql   ✅
0002_mfa.sql    ✅
```

> 迁移**不放进 CI**。迁移失败会让整个部署卡住，而它通常只需本地人工确认一次。
> 后续新增迁移时，同样在本地跑这条命令。

验证表已建立：

```bash
pnpm --filter @sso/core exec wrangler d1 execute sso-db --remote \
  --command "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
```

应看到 15 张表：`access_tokens`、`apps`、`audit_logs`、`authorization_codes`、`invitations`、
`mfa_factors`、`mfa_recovery_codes`、`oidc_states`、`passkey_challenges`、`passkeys`、
`password_resets`、`rate_limits`、`sessions`、`signing_keys`、`users`。

---

### 步骤 5：修改生产配置并推送

**两个文件都要改**，且 `ISSUER` / `RP_ID` 必须**完全一致**。

`packages/core/wrangler.toml`：

```toml
[vars]
ISSUER = "https://sso.your-domain.com"
RP_ID = "sso.your-domain.com"
```

`packages/gateway/wrangler.toml`：

```toml
[vars]
ISSUER = "https://sso.your-domain.com"
RP_ID = "sso.your-domain.com"
INVITE_ENABLED = "false"
```

注意 Gateway 的生产配置**不能有** `run_worker_first`（免费版超额会 429 且不回退静态资源）。
`wrangler.toml` 里已用注释标出，改配置时别加回去。

```bash
git add packages/core/wrangler.toml packages/gateway/wrangler.toml
git commit -m "配置生产域名"
git push
```

---

### 步骤 6：连接 Core 到 Git

**先在本地把 Core 创建出来**，否则 Dashboard 里连不到已存在的 Worker：

```bash
cd packages/core
pnpm exec wrangler deploy
```

这次本地部署只为「占位」（把 `sso-core` 这个名字注册到账号下）。之后都由 Git 接管。

然后去 Dashboard：

1. **Workers & Pages** → 选中 `sso-core`
2. **Settings** → **Builds** → **Connect**
3. 选择仓库与分支（`main`）
4. 配置构建参数：

| 字段 | 值 |
|---|---|
| **Root directory** | `packages/core` |
| **Build command** | （留空） |
| **Deploy command** | `pnpm exec wrangler deploy` |
| **Preview command** | 不启用 |

> Preview 默认命令是 `npx wrangler preview` —— 本项目**不用**，因为 Core 的设计前提就是
> 「不可预览、不可公网访问」。如果 Dashboard 强制要求填写，写 `pnpm exec wrangler versions upload`。

5. **Save**，然后推一个 commit 触发构建。

---

### 步骤 7：注入 Core 的 secret

**secret 不通过 Git 传递**，必须在 Dashboard 或本地 wrangler 注入。

**A. Dashboard（推荐，Git 流程下更自然）**

Workers & Pages → `sso-core` → Settings → **Variables and Secrets** → Add：

| 名称 | 类型 | 值 |
|---|---|---|
| `GATEWAY_TOKEN` | Secret | 步骤 2 生成的值 |
| `SESSION_PEPPER` | Secret | 同上 |
| `TOTP_MASTER_KEY` | Secret | 同上 |
| `SIGNING_KEYS_JSON` | Secret | 整行 JSON |

每个都要选 **Encrypt**（Secret），不是 plaintext。

**B. 本地 wrangler**

```bash
cd packages/core
pnpm exec wrangler secret put GATEWAY_TOKEN
pnpm exec wrangler secret put SESSION_PEPPER
pnpm exec wrangler secret put TOTP_MASTER_KEY
pnpm exec wrangler secret put SIGNING_KEYS_JSON
```

> `wrangler.toml` 里有 `[secrets] required`，**四个缺任何一个，Git 构建会直接失败**。
> 这是刻意的：宁可构建失败，也不要「部署成功但线上 500」。

**验证 Core 不可达（没通过就别继续）：**

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://sso-core.<your-subdomain>.workers.dev
```

期望：**不是 200**（404 或 DNS 无解析）。返回 200 说明 `workers_dev = false` 被改坏了，**立刻停下**。

---

### 步骤 8：连接 Gateway 到 Git

同样先在本地占位：

```bash
cd ../gateway
pnpm build
pnpm exec wrangler deploy
```

然后 Dashboard → `sso-gateway` → Settings → Builds → Connect：

| 字段 | 值 |
|---|---|
| **Root directory** | `packages/gateway` |
| **Build command** | `pnpm build` |
| **Deploy command** | `pnpm exec wrangler deploy` |
| **Preview command** | 不启用 |

> Gateway 的 `pnpm build` 是必须的：它生成 `dist/`（Assets 目录）与 `public/assets/*.js`。
> 不跑构建，`wrangler deploy` 会因为找不到 `dist` 报错。

**注入 Gateway 的 secret：**

`GATEWAY_TOKEN` —— **必须与 Core 完全相同的值**。

Dashboard → `sso-gateway` → Settings → Variables and Secrets → Add → `GATEWAY_TOKEN` → Encrypt。

> ⚠️ 两边不一致的典型症状：**登录页能打开，一提交就 500**。
> 因为 Gateway 拿错误的 token 调 Core，Core 一律返回 401。

**绑定自定义域名：**

Workers & Pages → `sso-gateway` → Settings → Domains & Routes → Add Custom Domain →
`sso.your-domain.com`。

> 这一步必须在第一次实际登录前完成。issuer 已写进配置，域名要和它一致。

---

### 步骤 9：种子第一个超管（本地执行一次）

这是整个流程里**唯一**绕过 Core 直接写库的操作。

```bash
# Linux / macOS
SESSION_PEPPER='<步骤 2 的 pepper>' node scripts/seed-superadmin.mjs \
  --email you@example.com --password '<临时密码>' > seed.sql

# Windows PowerShell
$env:SESSION_PEPPER='<步骤 2 的 pepper>'
node scripts/seed-superadmin.mjs --email you@example.com --password '<临时密码>' > seed.sql
```

**先看生成的 SQL：**

```bash
cat seed.sql
# INSERT INTO users (...) VALUES ('...', 'you@example.com',
#   '<64位十六进制>', 'super_admin', 'active', 1, ...);
```

确认后执行并立刻删除：

```bash
pnpm --filter @sso/core exec wrangler d1 execute sso-db --remote --file=./seed.sql
rm seed.sql
```

要点：

- 密码至少 12 位（脚本会拒绝更短的）
- `must_change_password = 1` —— 首次登录强制改密
- `password_hash` = `HMAC-SHA256(SESSION_PEPPER, 明文)`，**必须用你注入的那个 pepper**

---

### 步骤 10：首次登录并绑定 MFA

1. 打开 `https://sso.your-domain.com/login`
2. 用种子邮箱与临时密码登录
3. **会被强制跳到 `/admin/security`** —— 超管 MFA 门禁在工作
4. 二选一绑定：
   - **Passkey**：点「绑定新设备」，用指纹/面容
   - **TOTP**：点「启用 TOTP」，页面显示 issuer 与密钥，验证器手动添加后输入 6 位码
5. **保存 10 个恢复码**（只显示一次）
6. 绑定成功后即可进入 `/admin`

> 建议绑两个 Passkey（手机 + 电脑），或 Passkey + TOTP，再加恢复码。

---

### 步骤 11：建第二个超管

```bash
SESSION_PEPPER='<pepper>' node scripts/seed-superadmin.mjs \
  --email backup@example.com --password '<另一个临时密码>' \
  --role super_admin > seed2.sql
pnpm --filter @sso/core exec wrangler d1 execute sso-db --remote --file=./seed2.sql
rm seed2.sql
```

**这一步不能省。** 唯一超管失联 = 全租户锁死。

---

### 4.12 Git 部署的日常节奏

连接完成后，日常只有一件事：

```bash
git add .
git commit -m "..."
git push
```

推送后两个 Worker **都会**触发构建。只想让其中一个重建，用 **Build watch paths**：

| Worker | Watch paths |
|---|---|
| `sso-core` | `packages/core/**`, `packages/shared/**` |
| `sso-gateway` | `packages/gateway/**`, `packages/shared/**` |

在 Dashboard → Worker → Settings → Builds → Watch paths 配置。

> `packages/shared/**` 必须同时出现在两边 —— 它是共享常量包，改了它两个 Worker 都要重建。

### 4.13 什么时候仍然需要本地 wrangler

| 场景 | 命令 |
|---|---|
| 创建 D1 数据库 | `wrangler d1 create` |
| 应用迁移 | `wrangler d1 migrations apply` |
| 种子超管 / 建客户端 | `wrangler d1 execute --file=` |
| 首次占位部署 | `wrangler deploy` |
| 导出备份 | `wrangler d1 export` |
| 应急回滚 | `wrangler rollback` |

这六件事 Git 流程不做。

---

## 5. 验证清单

部署完逐条过一遍。任何一条不符，先排查再开放使用。

### 5.1 边界

| # | 检查 | 命令 / 方法 | 期望 |
|---|---|---|---|
| 1 | Core 公网不可达 | `curl -o /dev/null -w "%{http_code}" https://sso-core.<sub>.workers.dev` | 非 200 |
| 2 | Gateway 无 D1 绑定 | Dashboard → Worker → Settings → Bindings | 只有 Service + Assets |
| 3 | Core 无 KV/R2 | 同上 | 只有 D1 + Cron |

### 5.2 页面

| # | 检查 | 期望 |
|---|---|---|
| 4 | `GET /login` | 200，静态页，**响应头无 Set-Cookie** |
| 5 | `GET /assets/app.css` | 200，`Content-Type: text/css` |
| 6 | `GET /oauth/jwks.json` | 200，含 `keys[].x`，**无 `d` 字段** |

### 5.3 认证

| # | 检查 | 期望 |
|---|---|---|
| 7 | 错误密码登录 | 401 |
| 8 | 不存在的邮箱登录 | 401，**与上一条响应完全一致** |
| 9 | 正确密码登录 | `Set-Cookie: __Host-sid=...; Secure; HttpOnly; SameSite=Lax` |
| 10 | 带 Cookie 访问 `/admin` | 200 |
| 11 | 不带 Cookie 访问 `/admin` | 302 → `/login` |
| 12 | 超管未绑 MFA 访问 `/admin/users` | 302 → `/admin/security?require=1` |
| 13 | POST 缺 `x-requested-with` 头 | 403 |

### 5.4 协议

| # | 检查 | 期望 |
|---|---|---|
| 14 | `GET /.well-known/openid-configuration` | 含 `introspection_endpoint`、`revocation_endpoint` |
| 15 | 同一授权码换两次 token | 第二次 `invalid_grant` |
| 16 | 吊销后调 `/oauth/introspect` | `{"active": false}` |
| 17 | 吊销后调 `/oauth/userinfo` | 401 |

### 5.5 自动化门禁

```bash
pnpm verify
```

应输出：

```
类型检查    3 包通过
单元测试    73 个通过
硬约束      39/39 通过
```

---

## 6. 配置 OIDC 下游应用

### 6.1 创建客户端

用配套脚本生成 SQL，再由 wrangler 写入：

```bash
node scripts/create-client.mjs \
  --name "My App" \
  --redirect https://app.example.com/callback \
  --redirect https://app.example.com/silent-callback \
  --post-logout https://app.example.com/ \
  --out client.sql
```

输出：

```
client_id     = app-41894e04cc13b4f5
client_secret = 471a00a1dd94c343bb11a451bd6ac04f27eb02a2daa37ba6e193625f2afc682a
redirect_uris = https://app.example.com/callback, ...
```

执行写入：

```bash
pnpm --filter @sso/core exec wrangler d1 execute sso-db --remote --file=./client.sql
rm client.sql
```

要点：

- **`client_secret` 只显示这一次**，D1 里只有它的 SHA-256
- `redirect_uris` **精确匹配**，不支持通配符；多域名就写多条 `--redirect`
- 回调地址必须是完整 URL（含协议），脚本会校验
- 创建完成后在 `/admin/apps` 能看到该客户端（**该页面目前是只读视图**）

管理界面 `/admin/apps` 支持完整操作（仅超级管理员）：

| 操作 | 位置 |
|---|---|
| 创建客户端 | 页面底部「新建客户端」表单 |
| 轮换 secret | 每行「轮换密钥」按钮，**旧密钥立即失效** |
| 删除客户端 | 每行「删除」按钮 |

> 也可以用 `scripts/create-client.mjs` 生成 SQL 后 `wrangler d1 execute`，
> 适合批量或脚本化场景。

### 6.2 下游要做的三件事

详见 `docs/下游集成.md`。核心三条：

1. **不要**把 ID Token 当长期授权依据（它签发即不可收回）
2. 内省缓存**不得超过 60 秒**，否则吊销对它不可见
3. 用户登出时调 `/oauth/revoke`

---

## 7. 日常运维

### 7.1 备份（每周）

```bash
pnpm --filter @sso/core exec wrangler d1 export sso-db --remote \
  --output=./backup-$(date +%Y%m%d).sql
```

Windows PowerShell：

```powershell
pnpm --filter @sso/core exec wrangler d1 export sso-db --remote --output=./backup-$(Get-Date -Format yyyyMMdd).sql
```

**存放纪律**：备份文件与 `SESSION_PEPPER` **分开存放**。

> D1 自带 Time Travel（30 天内任意时间点恢复），但它在你 Cloudflare 账号里。
> 账号被接管，备份一起没。所以外置导出是必要的。

### 7.2 查看状态

```bash
# 用户数
pnpm --filter @sso/core exec wrangler d1 execute sso-db --remote \
  --command "SELECT COUNT(*) FROM users"

# 活跃会话
pnpm --filter @sso/core exec wrangler d1 execute sso-db --remote \
  --command "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > strftime('%s','now')"

# 审计保留量（应稳定在 60 天窗口内）
pnpm --filter @sso/core exec wrangler d1 execute sso-db --remote \
  --command "SELECT COUNT(*) FROM audit_logs"
```

或在 `/admin/audit`、`/admin/sessions` 页面直接看。

### 7.3 Cron 是否在跑

Dashboard → Worker `sso-core` → Logs，过滤 `cleanup`。每 15 分钟一条：

```
cleanup {"sessions":0,"accessTokens":2,"authorizationCodes":0,...}
```

如果长时间没有，检查 `wrangler.toml` 的 `[triggers]` 是否还在。

### 7.4 限流配置

**WAF 速率限制规则**（推荐作为第一层，零 CPU 成本）：

Dashboard → Security → WAF → Rate limiting rules → Create：

- 路径：`/auth/login`
- 阈值：每 IP 每分钟 10 次
- 动作：Block

应用层还有第二层（D1 计数）：同账号连续失败 10 次锁 15 分钟，同 IP 失败 20 次锁 1 小时。

---

## 8. 密钥轮换

一年一次，或怀疑泄露时立刻做。

### 8.1 签名密钥轮换（Ed25519）

**必须两步，不能一把梭。**

```bash
# 1) 生成新密钥对
node -e "
const { generateKeyPairSync } = require('node:crypto');
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const kid = 'k' + new Date().toISOString().slice(0,10).replace(/-/g,'');
console.log(JSON.stringify({
  kid,
  alg: 'EdDSA',
  public_jwk: { ...publicKey.export({format:'jwk'}), kid, alg: 'EdDSA', use: 'sig' },
  private_jwk: privateKey.export({format:'jwk'})
}));
"
```

**第 1 步：把新密钥放到 `SIGNING_KEYS_JSON` 数组首位，旧密钥留在后面**

```json
[
  { "kid": "k20271027", ... 新密钥 ... },
  { "kid": "k20261027", ... 旧密钥 ... }
]
```

```bash
cd packages/core
pnpm exec wrangler secret put SIGNING_KEYS_JSON
pnpm deploy
```

此时新密钥开始签名，但 **JWKS 同时包含新旧两把**，下游按 `kid` 都能验。

**第 2 步：等 ≥ 5 分钟**（JWKS 缓存 `max-age=300`）+ 下游各自的缓存时间。

**第 3 步：从数组中移除旧密钥**，重新 `secret put` 并部署。

> ⚠️ 跳过等待直接替换 → 下游缓存里还是旧 JWKS，拿不到新 `kid` → **全站登录中断**（fail-closed，但影响是全面的）。

### 8.2 密码 pepper 轮换（高风险）

**轮换 pepper 会让所有人的密码立刻失效**，包括你自己。这是预期行为，不是故障。

```bash
# 1) 生成新 pepper
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"

# 2) 更新 secret
cd packages/core
pnpm exec wrangler secret put SESSION_PEPPER
pnpm deploy

# 3) 全员强制改密
pnpm exec wrangler d1 execute sso-db --remote \
  --command "UPDATE users SET must_change_password = 1"

# 4) 吊销全部会话
pnpm exec wrangler d1 execute sso-db --remote \
  --command "UPDATE sessions SET revoked_at = strftime('%s','now'), revoke_reason = 'pepper_rotation' WHERE revoked_at IS NULL"
```

然后线下通知每个人重新走一遍改密流程。

### 8.3 TOTP 主密钥轮换

现有实现支持 `key_version`，但**没有自动重加密**。轮换意味着已存在的 TOTP 因子全部作废。

若确需轮换：换 `TOTP_MASTER_KEY` → 用户重新绑定 TOTP。

---

## 9. 事故处置

### 9.1 pepper 疑似泄露

```
1. 立刻轮换 SESSION_PEPPER（见 8.2）
2. 全员 must_change_password = 1
3. 吊销全部 sessions 与 access_tokens
4. 查 /admin/audit 最近 7 天异常登录
5. 线下通知所有用户
```

### 9.2 签名私钥泄露

```
1. 立刻按 8.1 生成并替换密钥对（这次不需要保留旧密钥，直接移除）
2. 部署后所有旧 ID Token 失效
3. 通知下游重新拉 JWKS
```

### 9.3 唯一超管失联

如果有第二个超管：让 ta 登录后在 `/admin/users` 重置你的 MFA。

如果没有：只能直接改库。

```bash
# 先看当前超管
pnpm --filter @sso/core exec wrangler d1 execute sso-db --remote \
  --command "SELECT id, email, role, status FROM users WHERE role = 'super_admin'"

# 重置密码（用新 pepper 算哈希）
SESSION_PEPPER='<pepper>' node scripts/seed-superadmin.mjs \
  --email you@example.com --password '<新密码>' > reset.sql
# 手动改成 UPDATE 语句，或用种子脚本插入新账号
```

**这正是要求部署时建第二个超管的原因。**

### 9.4 登录页 500，但页面能打开

99% 是 `GATEWAY_TOKEN` 两边不一致。

```bash
# Core 侧
cd packages/core && pnpm exec wrangler secret list

# Gateway 侧
cd packages/gateway && pnpm exec wrangler secret list
```

注意 `secret list` 只显示名字不显示值。确认不一致就重新 `secret put` 一次。

---

## 10. 常见问题

**Q：`pnpm install` 报错说只允许 pnpm？**

这是 `scripts/preinstall.mjs` 在工作。用 `pnpm install`，不要用 `npm install` 或 `npx`。

**Q：部署 Gateway 时报错缺少 `dist` 目录？**

先跑 `pnpm --filter @sso/gateway build`。`dist` 是构建产物，不入库。

**Q：`wrangler secret put` 之后线上立刻变了？**

是的，`secret put` 会立即创建新版本并部署。这是正常行为。

**Q：为什么 Core 访问不了，怎么调试？**

Core 设计上不可达。本地调试用 `pnpm dev:core`（`wrangler dev`），它会监听 `localhost:8788`。
线上调试看 Dashboard 的 Logs。

**Q：改了 `RP_ID` 会怎样？**

所有已绑定的 Passkey 立刻失效（WebAuthn 按 RP ID 隔离凭证）。用户需要重新绑定。

**Q：能加 refresh token 吗？**

当前不签发。访问令牌 1 小时过期后，靠 SSO 会话 Cookie 静默重新授权 —— 用户无感。
加 refresh token 意味着要处理轮换与重放检测，复杂度远超收益。

**Q：审计日志能保存更久吗？**

默认 60 天（免费版 500 MB 限制）。要延长就改 `packages/core/src/cron.ts` 里的保留天数，
并确认 D1 用量。付费版可以放宽到 180 天。

**Q：怎么确认部署的是正确版本？**

```bash
curl https://sso.your-domain.com/.well-known/openid-configuration | grep issuer
```

应输出你的生产域名，不是 `localhost` 或 `workers.dev`。

---

## 附：一条命令复跑全部检查

```bash
pnpm verify
```

包含：类型检查（3 包）+ 单元测试（73 个）+ 硬约束门禁（39 条）。
CI 里跑这一条即可。