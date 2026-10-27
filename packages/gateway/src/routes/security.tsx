/** @jsxImportSource hono/jsx */
import { Hono } from "hono";
import { Role } from "@sso/shared";
import { callCore } from "../core/callCore";
import { mfaGate } from "../middleware/mfaGate";
import { requireAuth, requireRole } from "../middleware/session";
import { AdminLayout } from "../components/AdminLayout";
import type { AppContext } from "../types";

export const securityRoutes = new Hono<AppContext>();

securityRoutes.use("*", requireAuth);
// 超管未绑定 MFA 前不得进入，只能去 /admin/security。
securityRoutes.use("*", mfaGate);

securityRoutes.get("/security", async (c) => {
  const caller = c.get("caller")!;
  const result = await callCore<{
    ok: boolean;
    totp: boolean;
    passkey: boolean;
    recoveryCodesRemaining: number;
  }>(c.env, {
    method: "POST",
    path: "/mfa/status",
    payload: { userId: caller.userId },
  });

  const status = result.ok ? result.data : { totp: false, passkey: false, recoveryCodesRemaining: 0 };
  const freshCodes = c.req.query("codes");
  const justEnabled = c.req.query("totp") === "on";

  return c.html(
    <AdminLayout title="安全" current="/admin/security" scripts={["/assets/security.js"]}>
      {freshCodes ? (
        <div class="alert alert-info">
          <strong>恢复码（只显示这一次，请立即保存）</strong>
          <ul class="code-list">
            {freshCodes.split(",").map((code) => (
              <li class="mono">{code}</li>
            ))}
          </ul>
          <p class="hint">手机丢失、Passkey 设备丢失时，这是唯一的自助出路。</p>
        </div>
      ) : null}

      <h2 class="section-title">二次验证</h2>
      <table class="table">
        <tbody>
          <tr>
            <th>Passkey</th>
            <td>
              <span class="badge">{status.passkey ? "已绑定" : "未绑定"}</span>
            </td>
            <td>
              <button class="btn btn-secondary" id="passkey-register" type="button">
                绑定新设备
              </button>
            </td>
          </tr>
          <tr>
            <th>TOTP 验证器</th>
            <td>
              <span class="badge">{status.totp ? "已启用" : "未启用"}</span>
            </td>
            <td>
              {status.totp ? null : (
                <button class="btn btn-secondary" id="totp-begin" type="button">
                  启用 TOTP
                </button>
              )}
            </td>
          </tr>
          <tr>
            <th>恢复码</th>
            <td>
              <span class="badge">剩余 {status.recoveryCodesRemaining}</span>
            </td>
            <td>
              <button class="btn btn-secondary" id="recovery-regenerate" type="button">
                重新生成
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      {justEnabled ? <p class="alert alert-info">TOTP 已启用。</p> : null}

      <div id="totp-setup" class="card totp-setup" hidden>
        <h2 class="section-title">用验证器扫描</h2>
        <div id="totp-qr" class="totp-qr"></div>
        <p class="hint mono" id="totp-uri"></p>
        <form id="totp-confirm" class="form">
          <label class="field">
            <span class="field-label">输入当前验证码</span>
            <input class="input" name="code" inputmode="numeric" autocomplete="one-time-code" required />
          </label>
          <button class="btn btn-primary" type="submit">确认启用</button>
        </form>
        <p class="hint" id="totp-status"></p>
      </div>

      <p class="hint">
        超级管理员必须完成二次验证绑定后才能进入管理后台。
      </p>
    </AdminLayout>,
  );
});

securityRoutes.get("/roles", requireRole(Role.SuperAdmin), async (c) => {
  return c.html(
    <AdminLayout title="角色" current="/admin/roles">
      <p class="hint">角色模型为固定的三个：super_admin / admin / user。在 /admin/users 中调整。</p>
    </AdminLayout>,
  );
});