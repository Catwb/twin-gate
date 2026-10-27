/** @jsxImportSource hono/jsx */
import { Layout } from "../components/Layout";

export function NotFoundPage() {
  return (
    <Layout title="页面不存在">
      <section class="card">
        <h1 class="card-title">404</h1>
        <p class="hint">页面不存在。</p>
        <a class="btn btn-secondary" href="/login">返回登录</a>
      </section>
    </Layout>
  );
}