/**
 * 管理界面的反馈与权限一致性检查。
 *
 * 四个真实问题都出在这类地方：
 *   1. 操作后跳转带 ?done= / ?error=，但目标页面从不读取 —— 用户看不到任何反馈
 *   2. 丢弃 callCore 的返回值，失败也报成功
 *   3. 面向普通用户的页面没传 role，侧栏显示管理菜单，点进去全是无权限
 *   4. 前端脚本里写的路径在服务端根本不存在
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** 管理端所有会写数据的路由文件。 */
const ADMIN_ROUTE_FILES = [
  "packages/gateway/src/routes/admin.tsx",
  "packages/gateway/src/routes/admin-apps.tsx",
];

/** 登录页 / 账户页也带操作反馈，一并检查。 */
const FEEDBACK_PAGES = [
  "packages/gateway/src/routes/admin.tsx",
  "packages/gateway/src/routes/admin-apps.tsx",
  "packages/gateway/src/routes/account.tsx",
];

export function checkAdminFeedback({ check, ROOT }) {
  const read = (rel) => readFileSync(join(ROOT, rel), "utf8");

  check("管理操作的反馈能显示给用户", () => {
    for (const file of FEEDBACK_PAGES) {
      const src = read(file);

      // 跳转里带的每个反馈参数，都必须在这个文件里被读出来
      const written = new Set(
        [...src.matchAll(/\?(done|error|deleted)=/g)].map((m) => m[1]),
      );
      if (written.size === 0) continue;

      const readParams = new Set(
        [...src.matchAll(/c\.req\.query\("(\w+)"\)/g)].map((m) => m[1]),
      );

      for (const param of written) {
        if (!readParams.has(param)) {
          throw new Error(
            file + " 跳转带了 ?" + param + "= 但页面从不读取，用户看不到结果",
          );
        }
      }
    }

    // 不该有永不填充的占位元素
    const admin = read("packages/gateway/src/routes/admin.tsx");
    if (admin.includes('id="page-notice"')) {
      throw new Error("page-notice 是死元素，没有任何代码给它填内容");
    }
  });

  check("管理端的写操作检查返回值", () => {
    // 明确允许丢弃结果的场景：登出、OAuth 吊销这些协议要求"无论如何返回成功"
    const ALLOWED = /best-effort/;

    for (const file of ADMIN_ROUTE_FILES) {
      const lines = read(file).split("\n");
      const offenders = [];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!/await callCore/.test(line)) continue;
        if (/=\s*await callCore/.test(line)) continue;

        // 上一行有显式豁免标记
        const previous = lines[i - 1] ?? "";
        if (ALLOWED.test(previous) || ALLOWED.test(line)) continue;

        offenders.push(i + 1);
      }

      if (offenders.length > 0) {
        throw new Error(
          file + " 以下行丢弃了 callCore 的返回值，失败会假装成功: 第 " + offenders.join(", ") + " 行",
        );
      }
    }
  });

  check("AdminLayout 的使用方都传了 role", () => {
    const files = [
      "packages/gateway/src/routes/admin.tsx",
      "packages/gateway/src/routes/admin-apps.tsx",
      "packages/gateway/src/routes/account.tsx",
      "packages/gateway/src/routes/security.tsx",
    ];

    for (const file of files) {
      const src = read(file);
      const uses = [...src.matchAll(/<AdminLayout[^>]*>/g)].map((m) => m[0]);
      for (const use of uses) {
        // 只有面向普通用户的 /account 页面必须传；/admin 下的页面本就要求 Admin
        const isAccountPage = use.includes('current="/account"');
        if (isAccountPage && !use.includes("role=")) {
          throw new Error(file + " 的账户页没传 role，普通用户会看到管理菜单");
        }
      }
    }
  });
}
