-- 0003_authorization_code_session.sql
-- 授权码必须记住「是哪个会话发起的授权」。
--
-- 之前 token/exchange 拿不到原始 Cookie（它是一次无状态的后端调用），
-- 只能反查该用户任意一个活跃会话，取到的 sid 可能与发起授权的会话不是同一个。
-- 同一用户开两个浏览器时，下游据此踢会话会踢错人。
--
-- 允许为 NULL：迁移前签发的授权码还在 60 秒有效期内，它们没有这个字段。
-- 应用层要求新码必须带值，见 issueAuthorizationCode。

ALTER TABLE authorization_codes ADD COLUMN session_id TEXT;
