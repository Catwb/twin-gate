/**
 * 前端路径与路由表一致性检查。
 *
 * 起因：路由从 /admin/security 迁到 /account/security 时，服务端改了，
 * 浏览器脚本里的硬编码路径没跟着改，所有按钮点下去都是 404。
 * 类型系统看不见字符串字面量，这类问题只能靠脚本比对。
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

/**
 * 只移除整行注释，不做块注释剥离。
 * 原因：代码里的 `/*` 出现在字符串中（如 assets 通配路径），
 * 用正则做块注释匹配会把正常代码一起吃掉。
 */
function stripLineComments(content) {
  return content
    .split('\n')
    .filter((line) => {
      const t = line.trimStart();
      return !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('/*');
    })
    .join('\n');
}

/** 提取脚本中形如 "/admin/xxx" 的绝对路径字面量。 */
function extractPaths(src) {
  const found = [];
  const prefixes = ['/admin', '/account', '/auth', '/oauth'];
  const quotes = ['"', String.fromCharCode(39), String.fromCharCode(96)];
  const stopChars = ['?', String.fromCharCode(36), '{'];

  for (let i = 0; i < src.length; i++) {
    if (!quotes.includes(src[i])) continue;
    for (const prefix of prefixes) {
      if (!src.startsWith(prefix, i + 1)) continue;
      let j = i + 1;
      while (j < src.length) {
        const c = src[j];
        if (c === src[i] || stopChars.includes(c) || /\s/.test(c)) break;
        j++;
      }
      const path = src.slice(i + 1, j);
      if (path.length > 1) found.push(path.endsWith('/') ? path.slice(0, -1) : path);
    }
  }
  return found;
}

export function checkFrontendPaths({ check, ROOT }) {
  check('前端脚本调用的路径都有对应路由', () => {
    const app = readFileSync(join(ROOT, 'packages/gateway/src/app.tsx'), 'utf8');

    const mounts = new Map();
    const routeRe = /app\.route\("([^"]+)",\s*(\w+)\)/g;
    let m;
    while ((m = routeRe.exec(app)) !== null) mounts.set(m[2], m[1]);

    const knownPaths = new Set(['/']);
    const routeDir = join(ROOT, 'packages/gateway/src/routes');
    for (const entry of readdirSync(routeDir)) {
      if (!entry.endsWith('.ts') && !entry.endsWith('.tsx')) continue;
      const src = stripLineComments(readFileSync(join(routeDir, entry), 'utf8'));
      const defRe = /(\w+)\.(?:get|post|use)\("([^"]+)"/g;
      let d;
      while ((d = defRe.exec(src)) !== null) {
        const instance = d[1];
        const path = d[2];
        if (path.includes('*')) continue;
        const prefix = mounts.get(instance);
        if (prefix === undefined) continue;
        const full = prefix === '/' ? path : prefix + path;
        knownPaths.add(full.length > 1 && full.endsWith('/') ? full.slice(0, -1) : full);
      }
    }

    const usedPaths = new Set();
    for (const file of ['client.ts', 'security-client.ts', 'password-client.ts']) {
      const src = readFileSync(join(ROOT, 'packages/gateway/src/pages', file), 'utf8');
      for (const p of extractPaths(src)) usedPaths.add(p);
    }

    const missing = [...usedPaths].filter((p) => !knownPaths.has(p));
    if (missing.length > 0) {
      throw new Error('前端调用了不存在的路径: ' + missing.join(', '));
    }
  });
}
