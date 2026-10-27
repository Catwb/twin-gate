/** @jsxImportSource hono/jsx */
import type { Child } from "hono/jsx";

type LayoutProps = {
  title: string;
  /** 是否加载交互脚本（登录/MFA 页需要，纯展示页可省） */
  script?: boolean;
  /** 登录类页面居中；管理后台占满视口 */
  variant?: "centered" | "app";
  /** 额外脚本（如安全页的 security.js） */
  scripts?: string[];
  children: Child;
};

/**
 * 全站唯一布局。
 * CSS 只从 /assets/app.css 引入 —— 模板内禁止任何 CSS 导入，也不允许使用框架自带的 CSS-in-JSX。
 */
export function Layout({ title, script = false, variant = "centered", scripts, children }: LayoutProps) {
  return (
    <html lang="zh-CN">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{title}</title>
        <link rel="stylesheet" href="/assets/app.css" />
        {script ? <script type="module" src="/assets/app.js" /> : null}
        {(scripts ?? []).map((src) => (
          <script type="module" src={src} />
        ))}
      </head>
      <body>
        <main class={variant === "app" ? "app-root" : "page"}>{children}</main>
      </body>
    </html>
  );
}

export function Field(props: { label: string; name: string; type?: string; autocomplete?: string; required?: boolean }) {
  return (
    <label class="field">
      <span class="field-label">{props.label}</span>
      <input
        class="input"
        type={props.type ?? "text"}
        name={props.name}
        autocomplete={props.autocomplete}
        required={props.required ?? true}
        spellcheck={false}
      />
    </label>
  );
}

export function Alert(props: { kind: "error" | "info"; message: string | null }) {
  if (!props.message) return null;
  return <p class={`alert alert-${props.kind}`} role="alert">{props.message}</p>;
}