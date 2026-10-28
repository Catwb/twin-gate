/** @jsxImportSource hono/jsx */
import type { Child } from "hono/jsx";
import type { Role } from "@sso/shared";
import { Layout } from "./Layout";

type NavItem = { href: string; label: string; adminOnly?: boolean };

const NAV: NavItem[] = [
  { href: "/admin/users", label: "用户", adminOnly: true },
  { href: "/admin/invites", label: "邀请", adminOnly: true },
  { href: "/admin/apps", label: "应用与密钥", adminOnly: true },
  { href: "/admin/sessions", label: "活动会话", adminOnly: true },
  { href: "/admin/audit", label: "审计", adminOnly: true },
  // 账户相关页面在 /account 下，普通用户也能访问
  { href: "/account", label: "我的账户" },
  { href: "/account/security", label: "安全设置" },
];

const ADMIN_ROLES: Role[] = ["admin", "super_admin"];

export function AdminLayout(props: {
  title: string;
  current: string;
  /** 当前用户角色。不传则视为管理员，兼容既有调用。 */
  role?: Role | null;
  scripts?: string[];
  children: Child;
}) {
  const isAdmin = props.role == null || ADMIN_ROLES.includes(props.role);
  // 普通用户不该看到管理菜单 —— 那些页面要求 Role.Admin，点了就是「无权限」。
  const items = NAV.filter((item) => isAdmin || !item.adminOnly);

  return (
    <Layout title={props.title} variant="app" scripts={props.scripts}>
      <div class="admin-shell">
        <nav class="admin-nav">
          {items.map((item) => (
            <a href={item.href} aria-current={item.href === props.current ? "page" : undefined}>
              {item.label}
            </a>
          ))}
          <form method="post" action="/auth/logout" class="logout-form">
            <button class="btn btn-secondary" type="submit">退出</button>
          </form>
        </nav>
        <section class="admin-main">
          <header class="admin-header">
            <h1 class="admin-title">{props.title}</h1>
          </header>
          {props.children}
        </section>
      </div>
    </Layout>
  );
}

export function Pager(props: { base: string; offset: number; pageSize: number; hasNext: boolean }) {
  const prevOffset = Math.max(0, props.offset - props.pageSize);
  const nextOffset = props.offset + props.pageSize;
  return (
    <div class="pager">
      {props.offset > 0 ? <a class="btn btn-secondary" href={`${props.base}?offset=${prevOffset}`}>上一页</a> : null}
      {props.hasNext ? <a class="btn btn-secondary" href={`${props.base}?offset=${nextOffset}`}>下一页</a> : null}
    </div>
  );
}
