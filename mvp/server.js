// -*- coding: utf-8 -*-
// 第三方平台 MVP (本地演示用, Node >= 18, 零依赖)
//
// 角色: 一个"新平台"的后端。它自己**不存密码**, 只把用户同步到本站授权后台,
// 再借用本站的登录/时长/换绑体系。密钥只在服务端, 浏览器永远看不到。
//
//   浏览器 ──同源──► mvp/server.js ──HMAC──► 授权后台 /api/open/v1/*
//                         └── 订单表 (request_id 幂等) ──► users/extend
//
// 配置 (环境变量):
//   MVP_PORT    默认 3020
//   HZ_BASE     默认 http://127.0.0.1:3012
//   HZ_APP_ID   默认 demoapp
//   HZ_APP_SECRET 默认与 start.sh 里的一致 (只用于本地演示)
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.MVP_PORT || 3020);
const HZ_BASE = String(process.env.HZ_BASE || "http://127.0.0.1:3012").replace(/\/+$/, "");
const APP_ID = String(process.env.HZ_APP_ID || "demoapp");
const APP_SECRET = String(process.env.HZ_APP_SECRET || "DemoSecret2026_local_9x");
const UPSTREAM_TIMEOUT = 8000;
const MAX_BODY = 16 * 1024;
const LOG_KEEP = 50;
const DAY = 86400;

// 签名调用日志: 只留最近 N 条, 前端拿它当"真的发出去了"的证据 (不含 secret)
const exchangeLog = [];
let logSeq = 0;

// 本平台的订单表 (内存版 MVP): request_id 是幂等键。
// 生产做法是落库 + 唯一索引; 这里只为演示"同一次补单不会把时长加两次"。
const orders = new Map();

function sign(method, p, raw, ts, nonce) {
  const canon = [method, p, APP_ID, ts, nonce,
    crypto.createHash("sha256").update(raw).digest("hex")].join("\n");
  return crypto.createHmac("sha256", APP_SECRET).update(canon).digest("hex");
}

function pushLog(entry) {
  exchangeLog.push(entry);
  while (exchangeLog.length > LOG_KEEP) exchangeLog.shift();
  return entry;
}

async function openCall(method, p, body, signed = true) {
  const raw = body ? JSON.stringify(body) : "";
  const ts = String(Date.now());
  const nonce = crypto.randomBytes(12).toString("hex");
  const headers = { "Content-Type": "application/json" };
  if (signed) {
    headers["x-app-id"] = APP_ID;
    headers["x-timestamp"] = ts;
    headers["x-nonce"] = nonce;
    headers["x-signature"] = sign(method, p, raw, ts, nonce);
  }
  const t0 = Date.now();
  let status = 0;
  let data = null;
  try {
    const r = await fetch(HZ_BASE + p, {
      method,
      headers,
      body: method === "GET" ? undefined : raw || undefined,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT),
    });
    status = r.status;
    const text = await r.text();
    try { data = JSON.parse(text); } catch (e) { data = { ok: false, msg: "上游返回非 JSON: " + text.slice(0, 200) }; }
  } catch (e) {
    data = { ok: false, msg: "连不上授权后台 (" + HZ_BASE + "): " + (e && e.message || e) };
  }
  return pushLog({
    id: ++logSeq,
    at: Date.now(),
    method, path: p, status, ms: Date.now() - t0,
    signed, nonce: signed ? nonce.slice(0, 8) : "",
    req: body || null,
    resp: data,
  });
}

// 浏览器可触发的操作白名单 —— 绝不让前端传任意 path 过来
const OPS = {
  ping:     { method: "GET",  path: "/api/open/v1/ping",        fields: [] },
  register: { method: "POST", path: "/api/open/v1/users/register", fields: ["external_id", "username", "password", "recovery", "note"] },
  status:   { method: "POST", path: "/api/open/v1/users/status",   fields: ["external_id", "username"] },
  extend:   { method: "POST", path: "/api/open/v1/users/extend",  fields: ["external_id", "seconds"] },
  login:    { method: "POST", path: "/api/open/v1/auth/login",    fields: ["username", "password", "machine"] },
  verify:   { method: "POST", path: "/api/open/v1/auth/verify",   fields: ["token", "machine"] },
  // 反向证明: 同一个 token 直接打客户端接口 (不经开放接口) 也认
  me:       { method: "POST", path: "/api/auth/me", fields: ["token", "machine"], signed: false },
};

function pick(fields, body) {
  const out = {};
  for (const k of fields) {
    const v = body[k];
    if (v === undefined || v === null) continue;
    const s = String(v).trim();
    if (s) out[k] = s.slice(0, 200);
  }
  return out;
}

function json(res, code, obj) {
  const s = JSON.stringify(obj);
  res.writeHead(code, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(s);
}

function readBody(req, res) {
  return new Promise((resolve) => {
    let raw = "";
    let over = false;
    req.on("data", (c) => {
      if (over) return;
      raw += c;
      if (Buffer.byteLength(raw) > MAX_BODY) {
        over = true;
        json(res, 413, { ok: false, msg: "请求体过大" });
        req.resume();
        resolve(null);
      }
    });
    req.on("end", () => {
      if (over) return;
      try { resolve(raw ? JSON.parse(raw) : {}); } catch (e) { json(res, 400, { ok: false, msg: "JSON 解析失败" }); resolve(null); }
    });
    req.on("error", () => resolve(null));
  });
}

const PAGE = path.join(__dirname, "public", "index.html");

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    const p = url.pathname;

    if (req.method === "GET" && (p === "/" || p === "/index.html")) {
      const html = fs.readFileSync(PAGE);
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'",
      });
      return res.end(html);
    }

    if (!p.startsWith("/api/")) return json(res, 404, { ok: false, msg: "not found" });
    if (req.method !== "POST") return json(res, 405, { ok: false, msg: "仅接受 POST" });

    const body = await readBody(req, res);
    if (body === null) return;

    if (p === "/api/info")
      return json(res, 200, { ok: true, base: HZ_BASE, app_id: APP_ID,
        secret_mask: APP_SECRET.slice(0, 4) + "****" + APP_SECRET.slice(-4),
        orders: orders.size });

    if (p === "/api/call") {
      const op = String(body.op || "");
      const spec = OPS[op];
      if (!spec) return json(res, 400, { ok: false, msg: "未知操作" });
      const payload = pick(spec.fields, body);
      const entry = await openCall(spec.method, spec.path, spec.method === "GET" ? null : payload, spec.signed !== false);
      return json(res, 200, { ok: !!(entry.resp && entry.resp.ok), entry });
    }

    // 购买会员: 模拟支付成功后把权益折算成秒同步过去。
    // request_id 是幂等键 —— 同一个 id 重复提交只返回上次结果, 不会二次加时长。
    if (p === "/api/purchase") {
      const ext = String(body.external_id || "").trim();
      const days = Number(body.days);
      const rid = String(body.request_id || "").trim() || ("req_" + crypto.randomBytes(8).toString("hex"));
      if (!ext) return json(res, 400, { ok: false, msg: "缺少 external_id" });
      if (![7, 30, 90, 365].includes(days)) return json(res, 400, { ok: false, msg: "套餐天数不合法" });
      if (orders.has(rid)) {
        const o = orders.get(rid);
        return json(res, 200, { ok: true, duplicate: true, order: o, entry: null });
      }
      const order = {
        request_id: rid, external_id: ext, days,
        seconds: days * DAY, at: Date.now(), remaining: 0, status: "paying",
      };
      const entry = await openCall("POST", "/api/open/v1/users/extend",
        { external_id: ext, seconds: order.seconds }, true);
      const up = entry.resp || {};
      if (!up.ok) {
        order.status = up.code === "NOT_FOUND" ? "账号不存在" : "失败";
        return json(res, 200, { ok: false, duplicate: false, order, entry,
          msg: up.msg || "权益同步失败" });
      }
      order.status = "已同步";
      order.remaining = up.remaining || 0;
      orders.set(rid, order);
      return json(res, 200, { ok: true, duplicate: false, order, entry });
    }

    if (p === "/api/log")
      return json(res, 200, { ok: true, entries: exchangeLog.slice(-20).reverse() });

    return json(res, 404, { ok: false, msg: "not found" });
  } catch (e) {
    try { json(res, 500, { ok: false, msg: "服务端错误: " + (e && e.message) }); } catch (x) {}
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log("[mvp] 第三方平台演示: http://127.0.0.1:" + PORT);
  console.log("[mvp] 授权后台: " + HZ_BASE + "  app_id=" + APP_ID);
});

process.on("SIGINT", () => process.exit(0));
process.on("SIGTERM", () => process.exit(0));
