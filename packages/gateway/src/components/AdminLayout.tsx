/** @jsxImportSource hono/jsx */
import type { Child } from "hono/jsx";
import { Layout } from "./Layout";

const NAV = [
  { href: "/admin/users", label: "用户" },
  { href: "/admin/invites", label: "邀请" },
  { href: "/admin/apps", label: "应用与密钥" },
  { href: "/admin/sessions", label: "活动会话" },
  { href: "/admin/security", label: "安全" },
  { href: "/admin/audit", label: "审计" },
];

export function AdminLayout(props: { title: string; current: string; scripts?: string[]; children: Child }) {
  return (
    <Layout title={props.title} variant="app" scripts={props.scripts}>
      <div class="admin-shell">
        <nav class="admin-nav">
          {NAV.map((item) => (
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