# 参与贡献

## 先读这个

这是**单人维护的自用项目**，公开只是为了让部署者能审计代码。所以：

- 不接受"请支持多租户"这类范围外功能请求
- 接受的 PR 类型：修 bug、补测试、改文档、明确的漏洞修复
- 大改动请先开 issue 讨论，别直接提 PR

## 硬性规则

### 1. 只用 pnpm

`npm install` / `npx` 会被 `scripts/preinstall.mjs` 直接阻断。这是刻意的：
workspace 用了 `workspace:*` 协议，npm 解析不了，混用会装出坏掉的依赖树。

### 2. 提交前必须 `pnpm verify` 全绿

```bash
pnpm verify     # 类型检查 + 单测 + 43 条硬约束门禁
```

任何一条红都不许合。门禁检查的是架构假设，不是代码风格。

### 3. 不要把 secret 写进任何文件

- 本地开发用 `.dev.vars`（已 gitignore）
- 新增 secret 时同步更新 `.dev.vars.example`
- 生产用 `wrangler secret put` 或 Dashboard

### 4. 改架构前先看这 5 条

这几条是整套设计的地基，动了要同时改门禁并说明理由：

| 约束 | 为什么不能动 |
|---|---|
| Gateway 不持 D1 | 被攻破的 Gateway 不能触达数据库 |
| Core 无公网路由 | 唯一入口是 Service Binding 与 Cron |
| 身份只走 body | 客户端头部在结构上没有落点 |
| 密码只存 `HMAC(pepper, 明文)` | 免费版 10ms CPU 跑不动 PBKDF2 |
| 访问令牌是不透明串 | JWT 无法即时吊销 |

### 5. 新增具名方法要挂角色校验

Core 的每个 `/internal/*` 端点都是"Gateway 可调用的能力"。
新增时必须在 handler 里检查 `caller.role`，否则等于给攻破的 Gateway 开了后门。

## 代码风格

没有 linter 配置，靠几条约定：

- 注释解释**为什么**，不解释**是什么**
- 安全相关的判断必须写清原因（读者需要知道能不能改）
- 单测测行为，不测实现细节
- 中文注释，英文标识符

## 提交信息

```
<范围>: <做了什么>

<为什么，可选>
```

范围用：`core`、`gateway`、`shared`、`scripts`、`docs`

例：

```
core: 授权码消费改为原子条件更新

先查后写存在重放窗口，改用 UPDATE ... WHERE used_at IS NULL
并以受影响行数判定。
```

## 新增硬约束

如果你修了一个"本不该发生"的 bug，**顺手加一条门禁**。

这是这个项目的习惯：每修一个真问题，就把它变成不可能再犯的检查。
现有 43 条门禁里，一大半都来自实际踩过的坑。

位置：`scripts/checks/`（按领域分文件），在主脚本里注册。
