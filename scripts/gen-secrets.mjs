#!/usr/bin/env node
/**
 * 生成部署所需的随机 secret。
 * 输出只打印一次，请立刻保存到密码管理器，并把 SESSION_PEPPER 与 D1 备份分开存放。
 */
import { randomBytes, generateKeyPairSync } from "node:crypto";

const random = (bytes = 32) => randomBytes(bytes).toString("base64");

const ed25519 = generateKeyPairSync("ed25519");
const privateJwk = ed25519.privateKey.export({ format: "jwk" });
const publicJwk = ed25519.publicKey.export({ format: "jwk" });

const kid = `k${new Date().toISOString().slice(0, 10).replace(/-/g, "")}`;

console.log("# 以下值只会出现这一次，请立即保存");
console.log();
console.log(`SESSION_PEPPER=${random()}`);
console.log();
console.log(`TOTP_MASTER_KEY=${random()}`);
console.log();
console.log(`GATEWAY_TOKEN=${random()}`);
console.log();
console.log("# SIGNING_KEYS_JSON（整段作为 secret 值传给 wrangler secret put）");
console.log(
  JSON.stringify([
    {
      kid,
      alg: "EdDSA",
      public_jwk: { ...publicJwk, kid, alg: "EdDSA", use: "sig" },
      private_jwk: privateJwk,
    },
  ]),
);
console.log();
console.log("# 注意：SESSION_PEPPER 泄露 = 所有密码可被离线爆破；");
console.log("#       它与 D1 备份必须分开存放。");
