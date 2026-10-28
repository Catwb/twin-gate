/**
 * 管理界面的反馈与权限一致性检查。
 *
 * 三个真实问题都出在这类地方：
 *   1. 操作后跳转带 ?done= / ?error=，但目标页面从不读取 —— 用户看不到任何反馈
 *   2. 丢弃 callCore 的返回值，失败也报成功
 *   3. 面向普通用户的页面没传 role，侧栏显示管理菜单，点进去全是无权限
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

export function checkAdminFeedback({ check, ROOT }) {
  const adminPath = join(ROOT, 'packages/gateway/src/routes/admin.tsx');

  check('管理操作的反馈能显示给用户', () => {
    const src = readFileSync(adminPath, 'utf8');

    // 统计带 done/error 的跳转，与真正读取 query 的次数比对
    const redirects = (src.match(/\?(done|error)=/g) ?? []).length;
    const reads = (src.match(/c\.req\.query\("(done|error)"\)/g) ?? []).length;

    if (redirects > 0 && reads === 0) {
      throw new Error(
        'admin.tsx 有 ' + redirects + ' 处跳转带反馈参数，但一次都没读取',
      );
    }

    // 不该有永不填充的占位元素
    if (src.includes('id="page-notice"')) {
      throw new Error('page-notice 是死元素，没有任何代码给它填内容');
    }
  });

  check('管理端的写操作检查返回值', () => {
    const src = readFileSync(adminPath, 'utf8');

    // 找到所有 await callCore 但没接结果的行
    const lines = src.split('\n');
    const offenders = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/await callCore/.test(line) && !/=\s*await callCore/.test(line)) {
        // 允许：明确忽略结果的只读操作（如 touch），但 admin 里不该有
        offenders.push(i + 1);
      }
    }
    if (offenders.length > 0) {
      throw new Error(
        '以下行丢弃了 callCore 的返回值，失败会假装成功: 第 ' + offenders.join(', ') + ' 行',
      );
    }
  });

  check('AdminLayout 的使用方都传了 role', () => {
    const files = [
      'packages/gateway/src/routes/admin.tsx',
      'packages/gateway/src/routes/admin-apps.tsx',
      'packages/gateway/src/routes/account.tsx',
      'packages/gateway/src/routes/security.tsx',
    ];

    for (const file of files) {
      const src = readFileSync(join(ROOT, file), 'utf8');
      const uses = [...src.matchAll(/<AdminLayout[^>]*>/g)].map((m) => m[0]);
      for (const use of uses) {
        // 只有面向普通用户的 /account 页面必须传；/admin 下的页面本就要求 Admin
        const isAccountPage = use.includes('current="/account"');
        if (isAccountPage && !use.includes('role=')) {
          throw new Error(file + ' 的账户页没传 role，普通用户会看到管理菜单');
        }
      }
    }
  });
}
