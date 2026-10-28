# 部署指南（Deploy Guide）

> 目标读者：第一次把这套 SSO 部署到 Cloudflare 的人。
>
> **部署形态：GitHub Actions 全程。** 仓库在 GitHub，手动触发 `deploy.yml` 完成构建与部署。
> 本地 `wrangler` 只负责种子超管、查库、备份和应急回滚。
>
> 全程只用 **pnpm**。`npm install` / `npx` 会被 `scripts/preinstall.mjs` 直接阻断，这是故意的。

---

## 0. 部署形态一览

```
  git push
     │
     ▼
  GitHub Actions
  ├─ verify.yml    自动：类型 + 单测 + 门禁 + 构建
  ├─ deploy.yml     手动：guard → verify → build → resolve-d1
  │                          → deploy-core → deploy-gateway → smoke
  └─ deploy-quick.yml  手动：轻量部署（不跑迁移，
                            有未应用迁移时直接拒绝）
     ▼
  Cloudflare
  ┌──────────────────────────────────────────────┐
  │  sso-gateway   公网 + 自定义域名              │
  │  ├─ Service Binding → Core                   │
  │  └─ Workers Assets（登录/MFA/静态资源）        │
  └────────────────┬─────────────────────────────┘
                   │  X-Gateway-Token（身份只走 body）
  ┌────────────────▼─────────────────────────────┐
  │  sso-core      无公网路由                     │
  │  ├─ D1（唯一数据访问层）                       │
  │  └─ Cron（每 15 分钟分批清理）                 │
  └──────────────────────────────────────────────┘
```

**本地只做三件事**：种子第一个超管、查库、导出备份。
**部署不需要本地操作。**

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
│   │   ├── migrations/  D1 迁移（NNNN_name.sql，编号连续）
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

## 4. 第一次部署（GitHub Actions 全程）

> **部署完全由 GitHub Actions 执行**，本地不需要跑 `wrangler deploy`。
> 手动触发：GitHub → Actions → **deploy** → Run workflow。

### 4.0 整体流程

```
你 push 代码
     │
     ▼
verify.yml        自动跑：类型检查 + 单测 + 门禁 + 构建
     │
     ▼
你在 Actions 页面点 Run workflow（输入 DEPLOY 确认）
     │
     ▼
deploy.yml
  ├─ guard        敏感文件检查
  ├─ verify       再跑一遍（防止跳过）
  ├─ build        构建 + 断言产物 + 打包验证
  ├─ resolve-d1   查询或创建 sso-db，拿到 database_id
  ├─ deploy-core  注入配置 → 迁移(可选) → 注入 secret → 部署
  ├─ deploy-gateway  构建 → 注入配置 → 注入 secret → 部署
  └─ smoke        线上冒烟测试（7 项）
```

**关键点：`database_id` 不写进仓库。** workflow 每次运行时动态查询，
用脚本注入到临时生成的 `wrangler.toml` 里。仓库里永远是占位符。

> 注入用的是 Node 而不是 `sed`。原因：`ISSUER` 是 URL，TOML 里必须写成
> `ISSUER = "https://..."` —— 带引号。`sed` 在多层 shell 引号里很容易把引号吃掉，
> 结果是 `ISSUER = https://...`，wrangler 报 `Invalid TOML document: invalid value`。
> 用 `JSON.stringify(value)` 生成带引号的字符串，从根上避免这个问题。

> ⚠️ **两个 D1 命令的参数不一样**，这点容易踩坑：
>
> | 命令 | `--json` | 说明 |
> |---|---|---|
> | `wrangler d1 list` | ✅ 支持 | 输出 JSON 数组，每项含 `uuid` / `name` |
> | `wrangler d1 create` | ❌ **不支持** | 只输出人类可读文本 |
>
> 所以 workflow 里查库用 `--json` 解析，建库只能从文本里抓
> `database_id = "..."`，抓不到再兜底抓 UUID，最后再查一次列表。
> 三重兜底是因为 `create` 的输出不是结构化契约，可能随版本变化。

---

### 步骤 1：把仓库推到 GitHub

```bash
git init
git add .
git commit -m "初始提交"
git remote add origin git@github.com:<你>/twin-gate.git
git push -u origin main
```

推送前自查（应该没输出）：

```bash
git ls-files | grep -E "dev[.]vars$|seed[.]sql|backup-"
```

---

### 步骤 2：创建 Cloudflare API Token

Dashboard → 右上头像 → **My Profile** → **API Tokens** → **Create Token**。

⚠️ **不要用 "Edit Cloudflare Workers" 模板** —— 它**不含 D1 权限**。

官方模板清单（[API token templates](https://developers.cloudflare.com/fundamentals/api/reference/template/)）里，
"Edit Cloudflare Workers" 只给了这几项：

```
Workers Routes Write     Zone
Workers Scripts Write    Account
Workers KV Storage Write Account
Workers Tail Read        Account
Workers R2 Storage Write Account
Account Settings Read    Account
User Details Read        User
User Memberships Read    User
```

**没有 D1。** 用它跑 workflow，`resolve-d1` 这一步会直接失败——而且报错是权限不足，
不一定能和"token 配错了"直接对上号。

#### 正确做法：自定义权限

选 **Create Custom Token**，手动勾选以下权限（Account 级）：

| 权限 | 用途 | 必需 |
|---|---|---|
| **Workers Scripts : Edit** | 部署两个 Worker | ✅ |
| **D1 : Edit** | 建库、列表查询、跑迁移 | ✅ |
| **Workers KV Storage : Edit** | 本项目**不用** | ❌ 不需要 |
| **Workers R2 Storage : Edit** | 本项目**不用** | ❌ 不需要 |
| **Account Settings : Read** | 一般不需要 | ❌ 可选 |

**最小权限集就两条**：

```
Account → Workers Scripts : Edit
Account → D1 : Edit
```

Account Resources 选 **Include → 你的账号**。
Zone Resources 选 **Include → 全部区域**或留空（本项目不绑定 Zone 级路由，
自定义域名走 Custom Domain，不需要 Zone 权限）。

#### 逐项对照：workflow 每步需要什么权限

| workflow 步骤 | 实际调用 | 需要的权限 |
|---|---|---|
| `resolve-d1` 查询 | `wrangler d1 list --json` | **D1 : Edit**（或 Read） |
| `resolve-d1` 创建 | `wrangler d1 create` | **D1 : Edit** |
| `deploy-core` 迁移 | `wrangler d1 migrations apply` | **D1 : Edit** |
| `deploy-core` 注入 secret | `wrangler secret bulk` | **Workers Scripts : Edit** |
| `deploy-core` 部署 | `wrangler deploy` | **Workers Scripts : Edit** |
| `deploy-gateway` 全部 | 同上 | 同上 |
| `smoke` 冒烟测试 | 公开 HTTP 请求 | **无需权限** |

> 如果你只想让 token 能部署、不想让它能建库，可以只给 `D1 : Read`，
> 然后自己手动建一次库。但这样 `run_migrations` 就跑不了。

#### 创建后

**立刻复制 token**（只显示一次）。

再记下 **Account ID**：Dashboard → Workers & Pages → 右侧栏底部。

> ⚠️ 不要用 Global API Key。它权限过大，且不受 IP/资源范围限制，泄露等于整个账号失守。

> ⚠️ 不要把 token 写进仓库、wrangler.toml 或任何提交的文件。
> 它只该出现在 GitHub Secrets 里。

---

### 步骤 3：生成四个运行时 secret

```bash
node scripts/gen-secrets.mjs
```

输出四个值，**立刻存进密码管理器**：

```
SESSION_PEPPER=<44 字符>
TOTP_MASTER_KEY=<44 字符>
GATEWAY_TOKEN=<44 字符>
SIGNING_KEYS_JSON=[{"kid":"k20261027",...}]
```

> `SIGNING_KEYS_JSON` 是整行 JSON，含首尾方括号，复制时别截断。
> `SESSION_PEPPER` 的备份必须与将来的 D1 备份**分开存放**。

---

### 步骤 4：配置 GitHub Secrets 与 Variables

仓库 → **Settings** → **Secrets and variables** → **Actions**。

#### Secrets（必须）

| 名称 | 值 |
|---|---|
| `CLOUDFLARE_API_TOKEN` | 步骤 2 创建的 token |
| `CLOUDFLARE_ACCOUNT_ID` | 步骤 2 记下的 Account ID |
| `GATEWAY_TOKEN` | 步骤 3 生成 |
| `SESSION_PEPPER` | 步骤 3 生成 |
| `TOTP_MASTER_KEY` | 步骤 3 生成 |
| `SIGNING_KEYS_JSON` | 步骤 3 生成（整行 JSON） |
| `SEED_ADMIN_EMAIL` | **第一个超管的邮箱** |
| `SEED_ADMIN_PASSWORD` | **第一个超管的密码**，至少 12 位 |

> `SEED_ADMIN_*` 只用于初始化。workflow 在 `run_migrations: true` 时会调用
> `scripts/seed-admin-ci.mjs` **幂等地**创建超管：库里已有任何 `super_admin` 就跳过。
>
> 首次部署成功后，建议把这两个 secret 删掉 —— 它们不需要长期存在。

#### Variables（建议配置）

| 名称 | 示例 | 说明 |
|---|---|---|
| `ISSUER` | `https://sso.example.com` | **一经发布不可更改** |
| `RP_ID` | `sso.example.com` | WebAuthn 的 RP ID，不带协议 |

> 不配 Variables 的话，会沿用仓库里 `wrangler.toml` 的 `localhost` 默认值——
> 那只能本地用。**生产必须配。**

---

### 步骤 5：绑定自定义域名（只做一次）

`ISSUER` 里的域名必须先指向 Gateway，否则登录页打不开。

两种方式：

**A. 先部署一次再绑（推荐）**

1. 跑一次 workflow（`target: gateway`）
2. Dashboard → Workers & Pages → `sso-gateway` → **Settings** → **Domains & Routes**
3. **Add Custom Domain** → 填 `sso.example.com`

**B. 直接在 Dashboard 建 Worker 占位**

Workers & Pages → Create → Worker → 命名 `sso-gateway` → Deploy。
之后再跑 workflow 覆盖它。

> Core **不要**绑任何域名。它必须保持公网不可达。

---

### 步骤 6：第一次部署

GitHub → **Actions** → 左侧选 **deploy** → **Run workflow**：

| 输入 | 第一次部署填什么 |
|---|---|
| `target` | `both` |
| `run_migrations` | **`true`**（首次必须建表） |
| `confirm` | `DEPLOY` |

点 **Run workflow**。

**job 顺序与预期：**

| Job | 做什么 | 失败时看什么 |
|---|---|---|
| guard | 敏感文件检查 | 哪个文件被误提交 |
| verify | 类型/测试/门禁 | 具体哪条门禁红 |
| build | 构建 + 产物断言 | 缺哪个 dist 文件 |
| resolve-d1 | 查/建 sso-db | token 权限是否够 |
| deploy-core | 部署 + 迁移 + secret | 缺哪个 secret |
| deploy-gateway | 构建 + 部署 | 构建产物或 secret |
| smoke | 线上 7 项检查 | 哪一项没通过 |

> **后续部署**：`run_migrations` 保持 `false`，除非你新增了迁移文件。

---

### 步骤 7：超管由 workflow 自动创建

**不需要本地操作。** `deploy.yml` 里有一个幂等步骤：

```yaml
- name: 创建初始超管（幂等）
  if: inputs.run_migrations
  env:
    SESSION_PEPPER: ${{ secrets.SESSION_PEPPER }}
    SEED_ADMIN_EMAIL: ${{ secrets.SEED_ADMIN_EMAIL }}
    SEED_ADMIN_PASSWORD: ${{ secrets.SEED_ADMIN_PASSWORD }}
  run: node scripts/seed-admin-ci.mjs
```

它的行为：

| 库中状态 | 结果 |
|---|---|
| 没有 `super_admin` | **创建**，输出 `created=true` |
| 已有 `super_admin` | **跳过**，输出 `created=false` |
| 邮箱被普通用户占用 | **报错退出**，提示换邮箱 |
| 密码不足 12 位 | **报错退出** |

**幂等意味着可以安全重复运行** —— 后续部署即使再次勾选 `run_migrations` 也不会重复建号，
也不会覆盖你后来改过的密码。

首次部署时填的账号密码：

```
邮箱：SEED_ADMIN_EMAIL 的值
密码：SEED_ADMIN_PASSWORD 的值
```

> 首次登录**不会**强制改密 —— `SEED_ADMIN_PASSWORD` 是部署者自己设定的，
> 不是系统生成的临时密码，没有必要再改一次。
>
> 但登录后会被强制跳到 `/admin/security` 绑定 MFA，这是超管门禁在工作。

#### 如果种子步骤失败

看 job 日志里 `[seed]` 开头的行，它会打印具体原因。常见的：

| 日志 | 原因 |
|---|---|
| `缺少 SESSION_PEPPER` | 这个 secret 没配 |
| `SEED_ADMIN_PASSWORD 至少 12 位` | 密码太短 |
| `邮箱 xxx 已被占用（但不是超管）` | 该邮箱有普通用户账号 |

修复后重新触发 workflow 即可，**不需要先清库**。

---

#### 恢复码怎么用

启用 TOTP 时会生成 10 个一次性恢复码（形如 `dc8a7-f7a4a`），**只显示一次**。

**用途**：TOTP 验证器和 Passkey 都用不了的时候（手机丢失、换设备、系统时间错乱）。

**怎么用**：

1. 正常输入邮箱密码登录
2. 跳到 `/mfa` 二次验证页
3. 点 **使用恢复码** 展开输入框
4. 输入一个码，点 **用恢复码登录**
5. 登录成功后该码立即失效，其余会话被吊销

> 码里的连字符和大小写都不敏感：`dc8a7-f7a4a`、`dc8a7f7a4a`、`DC8A7-F7A4A` 都认。

**剩余数量**在 `/admin/security` 可查。剩 1-2 个时点「重新生成」。

> ⚠️ 重新生成会让**所有旧码立即失效**（不是追加）。生成后请立刻保存新的 10 个。

### 步骤 8：首次登录并绑定 MFA

1. 打开 `https://sso.your-domain.com/login`
2. 用种子邮箱 + 临时密码登录
3. **被强制跳到 `/admin/security`** —— 超管门禁在工作
4. 二选一绑定：
   - **Passkey**：点「绑定新设备」
   - **TOTP**：点「启用 TOTP」，页面显示 issuer 与密钥，验证器手动添加
5. **保存 10 个恢复码**（只显示一次）
6. 绑定后可进 `/admin`

---

### 步骤 9：建第二个超管

```bash
SESSION_PEPPER='<pepper>' node scripts/seed-superadmin.mjs \
  --email backup@example.com --password '<另一个临时密码>' \
  --role super_admin > seed2.sql
pnpm --filter @sso/core exec wrangler d1 execute sso-db --remote --file=./seed2.sql
rm seed2.sql
```

**不能省。** 唯一超管失联 = 全租户锁死。

---

### 4.10 日常部署节奏

```bash
git add .
git commit -m "..."
git push          # 触发 verify.yml，只做质量门禁
```

然后去 Actions 页面手动跑 `deploy`。

**常用组合：**

| 场景 | target | run_migrations |
|---|---|---|
| 改了前端/路由 | `gateway` | false |
| 改了 Core 逻辑 | `core` | false |
| 新增了迁移文件 | `both` | **true** |
| 全量重部 | `both` | false |
| 只回滚 | 见 4.11 | — |

### 4.11 回滚

Cloudflare 保留历史版本：

```bash
pnpm exec wrangler deployments list
pnpm exec wrangler rollback <deployment-id> --name sso-gateway
```

> 回滚只回代码，**不回数据库**。迁移是不可逆的，回滚前确认没有新增迁移。

### 4.12 本地还能做什么

| 场景 | 命令 |
|---|---|
| 本地开发 | `pnpm dev:core` / `pnpm dev:gateway` |
| 跑全部检查 | `pnpm verify` |
| 建/查数据库 | `wrangler d1 list` / `wrangler d1 execute` |
| 种子超管 | `wrangler d1 execute --file=` |
| 导出备份 | `wrangler d1 export` |
| 应急回滚 | `wrangler rollback` |

**日常部署不需要本地做任何事。**

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
单元测试    126 个通过
硬约束      16/16 通过
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

## 8.5 Passkey 绑定失败排查

Passkey 对域名极其敏感，配错时的表现很不直观。按这个顺序查：

### 先确认服务端认为的配置

workflow 部署后，Core 有个诊断端点会告诉你生效值：

```bash
# 需要 X-Gateway-Token，本地或 CI 里都能跑
curl -X POST https://<core>/internal/passkey/config \
  -H 'x-gateway-token: <GATEWAY_TOKEN>' \
  -H 'content-type: application/json' \
  -d '{"caller":null,"payload":{}}'
```

返回：

```json
{
  "ok": true,
  "origin": "https://sso.example.com",
  "rpId": "sso.example.com",
  "configuredRaw": { "issuer": "...", "rpIdRaw": "..." }
}
```

### 三条硬规则

| 规则 | 违反时的现象 |
|---|---|
| 浏览器地址栏域名必须等于 `rpId`（或是其子域） | 浏览器直接报 `SecurityError`，**请求根本没发出** |
| `expectedOrigin` 必须等于浏览器 origin（含协议与端口，不带路径） | 服务端返回 `verification_failed` |
| 一个 Passkey 绑定在哪个 `rpId` 上就永远只在那个域可用 | 换域名后旧凭证全部失效 |

### 常见原因

**1. 在 workers.dev 域名上测试**

```
配置 rpId = sso.example.com
实际访问 https://<worker-name>.<subdomain>.workers.dev
→ SecurityError，绑定必然失败
```

必须用绑定了 Custom Domain 的那个域名访问。

**2. `ISSUER` 带了结尾斜杠**

```toml
ISSUER = "https://sso.example.com/"   # 末尾多了 /
```

说明：代码里已做 `normalizeOrigin()` 规范化，会去掉斜杠与路径。
但配置本身仍建议写规范，避免其它地方引用时出问题。

**3. `RP_ID` 写了协议**

```toml
RP_ID = "https://sso.example.com"   # 错，不能带协议
RP_ID = "sso.example.com"            # 对
```

**4. 设备上已有同一账号的旧 Passkey**

浏览器会抛 `InvalidStateError`。到系统设置里删掉旧的，或换一台设备试。

### 浏览器报特定异常时

| 异常 | 含义与处理 |
|---|---|
| `NotReadableError` | **系统凭证管理器拒绝响应**。按顺序检查：① 手机已设置**屏幕锁**（PIN/密码/图案；只有指纹不够）② Chrome 密码管理器已启用 ③ 不在工作资料 / 无痕模式 ④ 换用 Google 密码管理器而非第三方 |
| `NotAllowedError` | 用户取消，或超过 60 秒未完成指纹/PIN 验证 |
| `SecurityError` | 当前域名与 `RP_ID` 不匹配（用了 IP、workers.dev 或其它域名） |
| `InvalidStateError` | 该设备已绑定过此账号，换设备或先在系统设置删掉旧凭证 |
| `UnknownError` | 系统层未知错误，通常是上面几种的变体 |

> **Passkey 绑不上时的替代路径**：先用 TOTP 完成二次验证。
> 超管门禁只要求「绑定任意第二因子」，TOTP 同样满足。
> 之后换设备再补绑 Passkey 即可。

### 看服务端日志

绑定失败时 Core 会打印真因：

```
[passkey] 注册验证失败: Unexpected RP ID hash in authenticator data
```

常见几类：

| 日志关键词 | 含义 |
|---|---|
| `RP ID hash` | rpId 与浏览器实际域不符 |
| `origin` | expectedOrigin 与浏览器 origin 不符 |
| `challenge` | 挑战过期（默认 10 分钟）或已被使用 |
| `User verification` | 设备未完成指纹/PIN 验证 |

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

包含：类型检查（3 包）+ 单元测试（132 个）+ 硬约束门禁（16 条）。
CI 里跑这一条即可。