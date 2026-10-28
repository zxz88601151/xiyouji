// -*- coding: utf-8 -*-
// 阿信电脑同步器 KEY 商业后台 v2 (零依赖, Node >= 14)
// 卡密类型: trial体验卡(3小时) day日卡(1天) week周卡(7天) month月卡(30天) year年卡(365天)
//
// v2 新增:
//   * 管理员账号体系 (scrypt 密码哈希 / 角色 owner|admin|viewer)
//   * 会话登录 (HttpOnly+SameSite Cookie, 12h 过期, 空闲 2h 掉线)
//   * 登录爆破防护 (IP+账号双维度限流, 连续失败锁定 15 分钟)
//   * 卡密加时长 (已激活直接续期; 未激活记入 pending_extend, 激活时一并生效)
//   * 卡密解绑/改备注/删除/搜索筛选/CSV 导出
//   * 审计日志 (data/audit.log, JSONL, 滚动 2MB)
//   * 每日数据自动备份 (data/backup/, 保留最近 7 份)
//   * 分层限流 / 参数白名单校验 / 安全响应头 / 管理页 CSP
//   * 前端全面去 innerHTML 拼接 (消除存储型 XSS)
//
// 存储: data/keys.json, data/machines.json, data/admins.json, data/sessions.json
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3010;
// 数据目录: 默认 ./data, 可用 HZ_DATA_DIR 指定 (便于测试隔离 / 多实例部署)
const DATA_DIR = path.resolve(process.env.HZ_DATA_DIR || path.join(__dirname, "data"));
const BACKUP_DIR = path.join(DATA_DIR, "backup");
const KEYS_FILE = path.join(DATA_DIR, "keys.json");
const MACHINES_FILE = path.join(DATA_DIR, "machines.json");
const ADMINS_FILE = path.join(DATA_DIR, "admins.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");
// ---- v4 账号体系 ----
const USERS_FILE = path.join(DATA_DIR, "users.json");        // 用户账号 (scrypt 哈希)
const USER_SESS_FILE = path.join(DATA_DIR, "user_sessions.json"); // 客户端登录令牌
const ORDERS_FILE = path.join(DATA_DIR, "orders.json");      // 支付订单
const IDENT_FILE = path.join(DATA_DIR, "identities.json");   // 开放接口: 外部平台账号 ↔ 本站账号映射
const TOKEN_FILE = path.join(DATA_DIR, "admin_token.txt");
const AUDIT_FILE = path.join(DATA_DIR, "audit.log");

const SECURE_COOKIE = process.env.HZ_SECURE_COOKIE === "1"; // HTTPS 部署时置 1
const SESSION_TTL = 12 * 3600 * 1000;   // 会话绝对寿命 12 小时
const SESSION_IDLE = 2 * 3600 * 1000;   // 空闲 2 小时掉线
const AUDIT_MAX = 2 * 1024 * 1024;      // 审计日志滚动阈值

const CARD_TYPES = {
  trial: { name: "体验卡", seconds: 3 * 3600 },
  day: { name: "日卡", seconds: 24 * 3600 },
  week: { name: "周卡", seconds: 7 * 24 * 3600 },
  month: { name: "月卡", seconds: 30 * 24 * 3600 },
  year: { name: "年卡", seconds: 365 * 24 * 3600 },
};
const TRIAL_SECONDS = 3 * 3600;
// ---- 换机重绑策略 (v3 一卡一机) ----
// 一张卡密首次激活即绑定机器码; 客户换电脑时, 在新机器上输入同一张卡密即完成重绑。
// 为了防止"一张卡多人轮流用", 换绑要付代价:
//   · REBIND_MAX_TIMES  一张卡最多换绑几次, 用完只能联系管理员解绑或重新买卡;
//   · REBIND_COST_SECONDS 每次换绑从剩余时长里扣掉多少秒 (默认 6 小时)。
// 两条都是硬上限, 不做"扣到 0 就算了" —— 剩余时长不够扣时直接拒绝换绑并提示续期,
// 避免用户换完机器发现卡已经废了。
const REBIND_MAX_TIMES = 3;
const REBIND_COST_SECONDS = 6 * 3600;

// ================= v4 账号体系 =================
// 商业模型: 注册 → 登录 → 选套餐 → 支付 → 开通 → 登录看到剩余时间。
// 卡密 (CDK) 不再是"授权凭证", 降级为【充值码】: 兑换后把时长充进账号。
// 设备绑定仍在账号级: 一个账号同一时刻只允许一台机器使用, 换机要付代价。
const USER_SESSION_TTL = 30 * 24 * 3600 * 1000; // 客户端登录令牌 30 天绝对有效期
const USER_SESSION_IDLE = 7 * 24 * 3600 * 1000; // 7 天不用即失效 (需重新登录)
const PWD_MIN = 8, PWD_MAX = 64;
// ---- 安全码 (注册时自设, 忘记密码时用它自助重置) ----
// 规则与密码同源: 8-32 位、必须同时含字母和数字。库里只存 scrypt 哈希,
// 管理台只显示"已设/未设", 任何接口都不回传明文。
const RC_MIN = 8, RC_MAX = 32;
const RECOVER_MAX_FAILS = 5;                 // 安全码连错 5 次锁 30 分钟 (比登录更狠)
const RECOVER_LOCK_MS = 30 * 60 * 1000;
// 注册限流 (每 IP 每分钟)。默认 6; 集成测试/压测可用 HZ_REG_PER_MIN 调高,
// 生产不要动 —— 注册本身不发权限(体验时长按机器去重), 限流只防脚本刷库。
const REG_PER_MIN = Math.max(1, Math.min(parseInt(process.env.HZ_REG_PER_MIN) || 6, 200));
// 请求体上限。开放接口的报文很小, 64KB 足够; 超限回 413 (见 read_body)。
const MAX_BODY = 64 * 1024;
// 反向代理: 只有显式设置 HZ_TRUST_PROXY=1 才采信 X-Forwarded-For。
// 不设时一律用 socket 地址 —— 否则客户端自己伪造 XFF 就能绕过限流和锁定。
const TRUST_PROXY = /^(1|true|yes)$/i.test(String(process.env.HZ_TRUST_PROXY || ""));

// 套餐表: 价格单位【分】, 服务端定价 —— 客户端只传 plan_id, 绝不传金额,
// 否则改一个请求就能用 1 分钱买年卡。
const PLANS = [
  { id: "day",     name: "日卡",  days: 1,   price: 500,   tag: "" },
  { id: "week",    name: "周卡",  days: 7,   price: 2500,  tag: "入门" },
  { id: "month",   name: "月卡",  days: 30,  price: 6900,  tag: "最受欢迎" },
  { id: "quarter", name: "季卡",  days: 90,  price: 17900, tag: "省 20%" },
  { id: "year",    name: "年卡",  days: 365, price: 59900, tag: "省 30%" },
];
const PLAN_MAP = Object.fromEntries(PLANS.map((p) => [p.id, p]));

// 支付通道: mock = 未接支付时的占位通道 (仅测试用, 订单可被"手动确认");
//           epay = 易支付协议 (需要 EPAY_PID / EPAY_KEY / EPAY_URL)
// 接真实支付时只需实现 /api/pay/notify 的验签, 其余流程不用动。
const PAY_PROVIDER = (process.env.HZ_PAY_PROVIDER || "mock").toLowerCase();
const EPAY_PID = process.env.HZ_EPAY_PID || "";
const EPAY_KEY = process.env.HZ_EPAY_KEY || "";
const EPAY_URL = process.env.HZ_EPAY_URL || "";

// 开放接口: 未来其它平台共用这套账号体系 (服务端到服务端, HMAC 签名)。
// 凭据格式 HZ_OPEN_APPS="appid:secret,appid2:secret2"; secret 至少 16 位。
// 可选 scope (用 | 分隔, 逗号列表): HZ_OPEN_APPS="app:secret|own,all"
//   own  (默认) 只能操作本应用代注册的账号 —— 应用之间互相看不见
//   all         允许按 username 访问任意会员 (跨应用/本站直注册), 老的"统一后台"用法
// 留空 = 整个 /api/open/v1 返回 501 (未启用), 生产上不开就没人能摸到。
const OPEN_APPS = (() => {
  const out = {};
  for (const raw of String(process.env.HZ_OPEN_APPS || "").split(",")) {
    const [cred, scopeStr] = String(raw).split("|");
    const i = cred.indexOf(":");
    if (i <= 0) continue;
    const id = cred.slice(0, i).trim();
    const sec = cred.slice(i + 1).trim();
    if (!id || sec.length < 16) continue;
    const scopes = String(scopeStr || "").split(/[;+]/).map((x) => x.trim().toLowerCase()).filter(Boolean);
    out[id] = { secret: sec, scopes: new Set(scopes.length ? scopes : ["own"]) };
  }
  return out;
})();
const OPEN_TS_SKEW = 5 * 60 * 1000;   // 签名时间戳容差 5 分钟

const ROLE_LEVEL = { viewer: 1, admin: 2, owner: 3 };

// 首次启动时创建的 owner 登录名 (可用 HZ_OWNER_NAME 改; 已存在的账号改名请用 reset_admin.js)
const OWNER_NAME = (process.env.HZ_OWNER_NAME || "admin").slice(0, 24);

// ---------- 存储 ----------
function load(file, def) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch (e) { return def; }
}
function save(file, obj) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  daily_backup(file);
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 1));
  fs.renameSync(tmp, file);
}
function daily_backup(file) {
  // 每天首次写入前, 把旧文件另存一份 (保留最近 7 份)
  try {
    if (!fs.existsSync(file)) return;
    const day = new Date().toISOString().slice(0, 10);
    const name = path.basename(file, ".json") + "-" + day + ".json";
    const dst = path.join(BACKUP_DIR, name);
    if (fs.existsSync(dst)) return;
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    fs.copyFileSync(file, dst);
    const files = fs.readdirSync(BACKUP_DIR)
      .filter((f) => f.startsWith(path.basename(file, ".json") + "-"))
      .sort();
    while (files.length > 7) fs.unlinkSync(path.join(BACKUP_DIR, files.shift()));
  } catch (e) { /* 备份失败不影响主流程 */ }
}

let keys = load(KEYS_FILE, {});
let machines = load(MACHINES_FILE, {});
let admins = load(ADMINS_FILE, null);
let sessions = load(SESSIONS_FILE, {});
let users = load(USERS_FILE, {});
let userSessions = load(USER_SESS_FILE, {});
let orders = load(ORDERS_FILE, {});
let identities = load(IDENT_FILE, {});

// 老数据字段补齐 (向前兼容 v1 的 keys.json)
(function migrate() {
  let dirty = false;
  for (const k of Object.values(keys)) {
    if (k.pending_extend === undefined) { k.pending_extend = 0; dirty = true; }
    if (k.note === undefined) { k.note = ""; dirty = true; }
  }
  if (dirty) save(KEYS_FILE, keys);
})();

// ---------- 管理员账号 ----------
// scrypt 参数显式写死: 必须与历史版本一致 (N=16384, r=8, p=1), 否则老密码全部失效。
const SCRYPT_OPTS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
// 同步版只用于启动时初始化 owner (一次性, 不在请求路径上)。
function hash_password_sync(pw, salt) {
  return crypto.scryptSync(String(pw), salt, 64, SCRYPT_OPTS).toString("hex");
}
// 异步版走 libuv 线程池: 并发登录时不会把事件循环卡住 (同步版 8 并发能把全站卡近 1 秒)。
function hash_password(pw, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(String(pw), salt, 64, SCRYPT_OPTS,
      (err, key) => (err ? reject(err) : resolve(key.toString("hex"))));
  });
}
async function new_password(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return { salt, hash: await hash_password(pw, salt) };
}
function new_password_sync(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return { salt, hash: hash_password_sync(pw, salt) };
}
async function check_password(pw, rec) {
  const h = Buffer.from(await hash_password(pw, rec.salt), "hex");
  let want;
  try { want = Buffer.from(String(rec.hash || ""), "hex"); } catch (e) { return false; }
  // 长度不同时 timingSafeEqual 会抛异常 —— 先比长度, 再恒时比较
  return want.length === h.length && crypto.timingSafeEqual(h, want);
}
function save_admins() { save(ADMINS_FILE, admins); }

(function init_admins() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (admins && Object.keys(admins).length) return;
  // 首次启动: 创建 owner, 随机密码落盘, 首次登录强制改密
  const pw = crypto.randomBytes(6).toString("base64").replace(/[^A-Za-z0-9]/g, "").slice(0, 10);
  const rec = new_password_sync(pw);
  admins = {
    [OWNER_NAME]: {
      ...rec, role: "owner", created_at: Date.now(),
      disabled: false, must_change: true, last_login: 0, note: "初始管理员",
    },
  };
  save_admins();
  try {
    fs.writeFileSync(path.join(DATA_DIR, "owner_password.txt"),
      "初始管理员账号: " + OWNER_NAME + "\n初始密码: " + pw + "\n(首次登录必须修改密码; 改密后请删除本文件)\n");
    fs.chmodSync(path.join(DATA_DIR, "owner_password.txt"), 0o600);
  } catch (e) {}
  console.log("[阿信KEY后台] 已创建初始管理员 %s / %s (见 data/owner_password.txt)", OWNER_NAME, pw);
})();

// 根令牌: 兼容 v1 的 x-admin-token (命令行/自动化用), 每次使用记审计
const ROOT_TOKEN = (function () {
  try { return fs.readFileSync(TOKEN_FILE, "utf8").trim(); } catch (e) {}
  const t = crypto.randomBytes(16).toString("hex");
  fs.writeFileSync(TOKEN_FILE, t);
  return t;
})();

// ---------- 工具 ----------
function gen_key() {
  const cs = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 去掉易混淆字符
  const seg = () => Array.from({ length: 4 }, () => cs[crypto.randomInt(cs.length)]).join("");
  return "HZ-" + [seg(), seg(), seg()].join("-");
}
function clean(s, max) { return String(s == null ? "" : s).replace(/[\x00-\x1f]/g, "").slice(0, max || 64); }
const RE_KEY = /^HZ-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/;
const RE_MACHINE = /^[A-Za-z0-9]{8,32}$/;
const RE_USER = /^[A-Za-z0-9_.-]{3,24}$/;

// ---------- 限流 / 锁定 (状态落盘, 重启不清零) ----------
// 为什么落盘: 这些计数器是防撞库的最后一道闸。只在内存里的话, 一次崩溃自恢复
// (hzkey.sh 会自动拉起) 就把所有锁定清零, 攻击者反而能靠"打崩进程"解除锁定。
const THROTTLE_FILE = path.join(DATA_DIR, "throttle.json");
const rateMap = {};
const failMap = {};

// 滑动窗口限流
function rate_ok(bucket, limit, windowMs) {
  const now = Date.now();
  const arr = (rateMap[bucket] = (rateMap[bucket] || []).filter((t) => now - t < windowMs));
  if (arr.length >= limit) return false;
  arr.push(now);
  if (arr.length > 2000) arr.splice(0, arr.length - 2000);   // 极端刷量时别把内存撑爆
  save_throttle();
  return true;
}
// 登录失败锁定
function fail_locked(bucket) {
  const f = failMap[bucket];
  return f && f.until > Date.now() ? Math.ceil((f.until - Date.now()) / 1000) : 0;
}
function fail_hit(bucket, max, lockMs) {
  const f = (failMap[bucket] = failMap[bucket] || { count: 0, until: 0 });
  f.count++;
  if (f.count >= max) f.until = Date.now() + lockMs;
  save_throttle(true);
}
function fail_clear(bucket) { delete failMap[bucket]; save_throttle(true); }

let _throttleTimer = null;
// immediate=true 用于失败计数: 锁定是安全闸门, 必须在进程被强杀 (Windows 上
// terminate 不走 SIGTERM) 之前落盘; 失败是低频事件, 多写几次无所谓。
function save_throttle(immediate) {
  if (immediate) {
    if (_throttleTimer) { clearTimeout(_throttleTimer); _throttleTimer = null; }
    flush_throttle();
    return;
  }
  if (_throttleTimer) return;
  _throttleTimer = setTimeout(() => {
    _throttleTimer = null;
    flush_throttle();
  }, 250);
  if (_throttleTimer.unref) _throttleTimer.unref();
}
function flush_throttle() {
  try {
    const now = Date.now();
    const out = { fail: {}, rate: {} };
    for (const [k, v] of Object.entries(failMap))
      if (v && v.until > now) out.fail[k] = v;
    for (const [k, arr] of Object.entries(rateMap)) {
      const keep = arr.filter((t) => now - t < 3600 * 1000);
      if (keep.length) out.rate[k] = keep;
    }
    fs.writeFileSync(THROTTLE_FILE, JSON.stringify(out));
    try { fs.chmodSync(THROTTLE_FILE, 0o600); } catch (e) {}
  } catch (e) {}
}
(function load_throttle() {
  try {
    const d = JSON.parse(fs.readFileSync(THROTTLE_FILE, "utf8"));
    const now = Date.now();
    for (const [k, v] of Object.entries(d.fail || {}))
      if (v && v.until > now) failMap[k] = { count: v.count || 0, until: v.until };
    for (const [k, arr] of Object.entries(d.rate || {})) {
      const keep = (arr || []).filter((t) => now - t < 3600 * 1000);
      if (keep.length) rateMap[k] = keep;
    }
    const nf = Object.keys(failMap).length, nr = Object.keys(rateMap).length;
    if (nf || nr) console.log("[限流] 已恢复落盘状态: 锁定 %d 项, 限流窗口 %d 项", nf, nr);
  } catch (e) {}
})();

// 审计日志 (JSONL, 滚动)
function audit(user, role, action, target, detail, ip) {
  try {
    let line = JSON.stringify({
      t: new Date().toISOString(), user, role, action,
      target: String(target || ""), detail: String(detail || "").slice(0, 300), ip,
    }) + "\n";
    if (fs.existsSync(AUDIT_FILE) && fs.statSync(AUDIT_FILE).size > AUDIT_MAX) {
      fs.renameSync(AUDIT_FILE, AUDIT_FILE + "." + Date.now() + ".bak");
    }
    fs.appendFileSync(AUDIT_FILE, line);
  } catch (e) {}
}

// ---------- 业务 ----------
function key_remaining(k) { return Math.max(0, Math.floor((k.expires_at - Date.now()) / 1000)); }
function key_state(k) {
  if (k.banned) return "banned";
  if (k.status !== "active") return k.status === "active" ? "active" : "unused";
  return key_remaining(k) > 0 ? "active" : "expired";
}
function do_activate(keyStr, machine) {
  const k = keys[keyStr];
  if (!k) return { ok: false, msg: "卡密不存在" };
  if (k.banned) return { ok: false, msg: "卡密已被封禁" };

  // ---- 1) 同一台机器重复激活: 免费, 不占换绑次数, 不扣时 ----
  // 用户重装系统/换目录后重新激活都会走到这里, 这种情况不该受罚。
  if (k.status === "active" && k.bound_machine === machine) {
    const rem = key_remaining(k);
    if (rem <= 0) return { ok: false, msg: "卡密已到期" };
    return { ok: true, remaining: rem, card_type: CARD_TYPES[k.type].name };
  }

  // 是否属于"换机重绑": 曾经绑定过 (ever_bound), 或当前正绑在别的机器上,
  // 或是旧数据里已激活过但被管理员解绑的卡 (activated_at > 0)。
  const is_rebind = !!k.ever_bound || k.status === "active" || (k.activated_at || 0) > 0;
  // 单位约定: key_remaining() 与 pending_extend 都是【秒】, expires_at 是【毫秒】。
  // 换算只在这一处做, 避免再出现"秒当毫秒扣"把年卡算成两小时的错。
  const cost_s = REBIND_COST_SECONDS;

  if (is_rebind) {
    // ---- 2) 换机重绑: 次数上限 + 扣时 ----
    const used = k.rebind_count || 0;
    if (used >= REBIND_MAX_TIMES)
      return { ok: false,
               msg: "该卡密换绑次数已用完 (最多 " + REBIND_MAX_TIMES + " 次), 请联系客服处理" };

    // 剩余时长(秒): 正绑着的卡看 expires_at, 已被管理员解绑的卡看 pending_extend
    const rem = k.status === "active" ? key_remaining(k) : (k.pending_extend || 0);
    if (rem <= 0) return { ok: false, msg: "卡密已到期" };
    if (rem <= cost_s)
      return { ok: false,
               msg: "剩余时长不足 " + (cost_s / 3600) +
                    " 小时, 换绑后会立即到期, 请先续期再加新机器" };

    // 扣时并把剩余时长落到新机器上 (不从零重算, 也不白送卡面时长)
    const left = rem - cost_s;
    k.expires_at = Date.now() + left * 1000;
    k.pending_extend = 0;
    k.status = "active";
    k.bound_machine = machine;
    k.ever_bound = true;
    k.rebind_count = used + 1;
    k.last_rebind_at = Date.now();
    k.rebind_cost_total = (k.rebind_cost_total || 0) + cost_s;
    save(KEYS_FILE, keys);
    return { ok: true, remaining: left, card_type: CARD_TYPES[k.type].name,
             rebound: true, cost_seconds: cost_s,
             rebind_count: k.rebind_count,
             rebind_left: REBIND_MAX_TIMES - k.rebind_count };
  }

  // ---- 3) 首次激活: 卡面时长 + 管理员预先加的时长 ----
  const extra = (k.pending_extend || 0) * 1000;
  k.pending_extend = 0;
  k.status = "active";
  k.bound_machine = machine;
  k.ever_bound = true;
  k.activated_at = Date.now();
  k.expires_at = Date.now() + CARD_TYPES[k.type].seconds * 1000 + extra;
  k.extend_total = (k.extend_total || 0) + extra / 1000;
  save(KEYS_FILE, keys);
  return { ok: true, remaining: key_remaining(k), card_type: CARD_TYPES[k.type].name };
}
function do_verify(keyStr, machine) {
  const k = keys[keyStr];
  if (!k || k.banned || k.status !== "active" || k.bound_machine !== machine)
    return { ok: false, msg: "授权失效" };
  const rem = key_remaining(k);
  if (rem <= 0) return { ok: false, msg: "卡密已到期" };
  return { ok: true, remaining: rem, card_type: CARD_TYPES[k.type].name };
}
// 试用计时: 按 heartbeat 累加在线时长 (单次心跳最多计 90s, 离线不扣时)
function trial_touch(machine) {
  const now = Date.now();
  let m = machines[machine];
  if (!m) m = machines[machine] = { trial_used: 0, first_seen: now, last_seen: now };
  const elapsed = Math.floor((now - m.last_seen) / 1000);
  m.trial_used += Math.min(Math.max(elapsed, 0), 90);
  m.last_seen = now;
  save(MACHINES_FILE, machines);
  return Math.max(0, TRIAL_SECONDS - m.trial_used);
}

// ================= v4 账号体系 =================
// 设计要点 (与"业内最专业"的那套对齐):
//   1. 密码只存 scrypt(64B) + 每用户独立盐, 永不落明文、永不出现在日志里;
//   2. 登录失败按【账号】和【IP】双维度计数, 达到阈值锁定, 防撞库;
//   3. 客户端拿到的是可撤销的会话令牌, 不是密码 —— 令牌泄露可单点踢下线;
//   4. 金额只在服务端算, 客户端只传 plan_id; 订单状态机 pending→paid 单向;
//   5. 到期时间以服务端为准, 客户端改本地文件没有任何收益。

function pwd_problem(pw) {
  pw = String(pw || "");
  if (pw.length < PWD_MIN) return "密码至少 " + PWD_MIN + " 位";
  if (pw.length > PWD_MAX) return "密码过长";
  if (!/[A-Za-z]/.test(pw) || !/[0-9]/.test(pw)) return "密码需同时包含字母和数字";
  if (/^\s|\s$/.test(pw)) return "密码首尾不能是空格";
  return "";
}

/** 安全码校验: 与 pwd_problem 同规则, 只是长度区间不同 (8-32) */
function rc_problem(code) {
  const s = String(code || "");
  if (s.length < RC_MIN) return "安全码至少 " + RC_MIN + " 位";
  if (s.length > RC_MAX) return "安全码最多 " + RC_MAX + " 位";
  if (!/[A-Za-z]/.test(s) || !/[0-9]/.test(s)) return "安全码需同时包含字母和数字";
  if (/^\s|\s$/.test(s)) return "安全码首尾不能是空格";
  return "";
}
function set_recovery_code(u, code) {
  return new_password(code).then((rec) => {   // 复用 scrypt+盐, 不落明文
    u.rc_salt = rec.salt;
    u.rc_hash = rec.hash;
    u.rc_set_at = Date.now();
  });
}
async function check_recovery_code(u, code) {
  if (!u || !u.rc_salt || !u.rc_hash) return false;
  return check_password(code, { salt: u.rc_salt, hash: u.rc_hash });
}

function user_remaining(u) {
  return Math.max(0, Math.floor(((u.expires_at || 0) - Date.now()) / 1000));
}
function user_state(u) {
  if (!u) return "none";
  if (u.status === "banned") return "banned";
  return user_remaining(u) > 0 ? "active" : "expired";
}
/** 返回给客户端的账号视图 (绝不含 salt/hash) */
function user_public(name, u, machine) {
  const rem = user_remaining(u);
  return {
    user: name,
    state: user_state(u),
    plan_id: u.plan_id || "",
    plan_name: (PLAN_MAP[u.plan_id] || {}).name || "",
    remaining: rem,
    expires_at: u.expires_at || 0,
    machine: u.bound_machine || "",
    machine_ok: !u.bound_machine || u.bound_machine === machine,
    rebind_left: Math.max(0, REBIND_MAX_TIMES - (u.rebind_count || 0)),
    rc_set: !!u.rc_hash,
  };
}

function user_save() { save(USERS_FILE, users); }

async function create_user(name, pw, recovery) {
  const rec = await new_password(pw);
  users[name] = {
    ...rec, created_at: Date.now(), status: "active",
    plan_id: "", expires_at: 0, bound_machine: "", rebind_count: 0,
    total_paid: 0, last_login: 0, last_ip: "", note: "",
  };
  if (recovery) await set_recovery_code(users[name], recovery);
  user_save();
  return users[name];
}

/**
 * 设备绑定 / 换机。
 * 返回 { ok, rebound, cost_seconds, msg }。
 * 规则与卡密时代一致: 一账号一机; 换机扣 REBIND_COST_SECONDS, 最多 REBIND_MAX_TIMES 次;
 * 账号没有剩余时长时不扣费 (没东西可扣), 直接重绑。
 */
function bind_machine(name, u, machine) {
  if (!u.bound_machine) {
    u.bound_machine = machine;
    user_save();
    return { ok: true, rebound: false, cost_seconds: 0 };
  }
  if (u.bound_machine === machine) return { ok: true, rebound: false, cost_seconds: 0 };

  const rem = user_remaining(u);
  if (rem <= 0) {   // 已到期: 没有时长可扣, 允许直接换绑
    u.bound_machine = machine;
    user_save();
    return { ok: true, rebound: true, cost_seconds: 0, msg: "已换绑到本机" };
  }
  const used = u.rebind_count || 0;
  if (used >= REBIND_MAX_TIMES)
    return { ok: false, msg: "该账号换绑次数已用完 (最多 " + REBIND_MAX_TIMES + " 次), 请联系客服" };
  if (rem <= REBIND_COST_SECONDS)
    return { ok: false, msg: "剩余时长不足 " + (REBIND_COST_SECONDS / 3600) +
                             " 小时, 换绑后会立即到期, 请先续费" };

  u.expires_at = Date.now() + (rem - REBIND_COST_SECONDS) * 1000;
  u.bound_machine = machine;
  u.rebind_count = used + 1;
  u.last_rebind_at = Date.now();
  user_save();
  return { ok: true, rebound: true, cost_seconds: REBIND_COST_SECONDS,
           rebind_left: REBIND_MAX_TIMES - u.rebind_count };
}

function user_session_create(name, machine, ip, ua) {
  const token = crypto.randomBytes(32).toString("hex");
  const now = Date.now();
  userSessions[token] = {
    user: name, machine, created: now, last: now,
    expires: now + USER_SESSION_TTL, ip, ua: String(ua || "").slice(0, 120),
  };
  // 单账号最多保留 5 个有效令牌, 超出踢最旧的 (防止令牌无限堆积)
  const mine = Object.entries(userSessions).filter(([, s]) => s.user === name)
    .sort((a, b) => a[1].last - b[1].last);
  while (mine.length > 5) delete userSessions[mine.shift()[0]];
  save(USER_SESS_FILE, userSessions);
  return token;
}

function user_session_get(token) {
  if (!token) return null;
  const s = userSessions[token];
  if (!s) return null;
  const now = Date.now();
  if (now > s.expires || now - s.last > USER_SESSION_IDLE) {
    delete userSessions[token];
    save(USER_SESS_FILE, userSessions);
    return null;
  }
  s.last = now;
  return s;
}

/** 校验令牌 + 取账号。返回 { name, u, s } 或 null */
function user_auth(token) {
  const s = user_session_get(token);
  if (!s) return null;
  const u = users[s.user];
  if (!u || u.status === "banned") return null;
  return { name: s.user, u, s };
}

/** 踢掉某账号的全部登录令牌, 返回清掉几个。改密/找回/封禁后都要调, 
 *  否则"旧密码泄露→改密"这种补救措施根本拦不住已经登录的攻击者。 */
function revoke_user_sessions(name) {
  let n = 0;
  for (const t of Object.keys(userSessions)) {
    if (userSessions[t].user === name) { delete userSessions[t]; n++; }
  }
  if (n) save(USER_SESS_FILE, userSessions);
  return n;
}

/** 强随机密码 (排除易混字符), 用于开放接口代注册时没给密码的情况 */
function rand_password(len) {
  const abc = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  for (let guard = 0; guard < 20; guard++) {
    let s = "";
    while (s.length < len) s += abc[crypto.randomInt(abc.length)];
    if (/[A-Za-z]/.test(s) && /[0-9]/.test(s)) return s;
  }
  return "Hz" + crypto.randomBytes(8).toString("hex");
}

/**
 * 账号密码登录的核心路径 —— /api/auth/login 与 /api/open/v1/auth/login 共用,
 * 避免"客户端能登录、开放接口却是另一套规则"这种双头逻辑漂移。
 * 返回 { ok:false, msg } 或 { ok:true, u, token, rebound, cost_seconds }。
 * tag 决定审计动作名 (LOGIN / OPEN_LOGIN)。
 */
async function user_login_core(name, pw, machine, ip, ua, tag) {
  // 锁定按 (IP, 账号) 为主维度: 别人在家乱试也锁不住你;
  // 另设账号级高阈值 (50 次/15 分钟) 兜底分布式撞库。
  const pairB = "ul:" + ip + "|" + String(name).toLowerCase();
  const acctB = "u:" + String(name).toLowerCase();
  const lock = Math.max(fail_locked(pairB), fail_locked(acctB));
  if (lock) return { ok: false, msg: "失败次数过多, 请 " + lock + " 秒后再试" };

  const u = users[name];
  let pwOk = false;
  try { pwOk = !!u && await check_password(pw, u); } catch (e) { pwOk = false; }
  if (!pwOk) {
    fail_hit(pairB, 8, 15 * 60 * 1000);
    fail_hit(acctB, 50, 15 * 60 * 1000);
    audit(name, "-", tag + "_FAIL", name, "密码错误", ip);
    return { ok: false, msg: "账号或密码错误" };
  }
  fail_clear(pairB); fail_clear(acctB);
  if (u.status === "banned") {
    audit(name, "user", tag + "_DENY", name, "账号封禁", ip);
    return { ok: false, msg: "账号已被封禁, 请联系客服" };
  }

  // 设备绑定: 换机要扣时/计次, 失败即拒绝登录 (避免"能登进来但用不了")
  const b = bind_machine(name, u, machine);
  if (!b.ok) {
    audit(name, "user", "REBIND_DENY", name, b.msg, ip);
    return { ok: false, msg: b.msg, need_support: true };
  }
  if (b.rebound)
    audit(name, "user", "REBIND", name,
          "新机器=" + machine + " 扣时=" + (b.cost_seconds / 3600) + "h", ip);

  u.last_login = Date.now();
  u.last_ip = ip;
  user_save();
  const token = user_session_create(name, machine, ip, ua);
  audit(name, "user", tag + "_OK", name, "机器=" + machine, ip);
  return { ok: true, u, token, rebound: !!b.rebound, cost_seconds: b.cost_seconds || 0 };
}

function extend_user(name, u, seconds) {
  const base = Math.max(Date.now(), u.expires_at || 0);
  u.expires_at = base + Math.max(0, Math.floor(seconds)) * 1000;
  u.last_pay_at = Date.now();
  user_save();
  return user_remaining(u);
}

function order_create(name, planId) {
  const plan = PLAN_MAP[planId];
  if (!plan) return { ok: false, msg: "套餐不存在" };
  const id = "HZ" + Date.now().toString(36).toUpperCase() +
             crypto.randomBytes(3).toString("hex").toUpperCase();
  orders[id] = {
    id, user: name, plan_id: plan.id, plan_name: plan.name,
    amount: plan.price,          // 单位: 分
    days: plan.days,
    status: "pending", channel: PAY_PROVIDER, trade_no: "",
    created_at: Date.now(), paid_at: 0,
  };
  save(ORDERS_FILE, orders);
  return { ok: true, order: orders[id], pay: pay_params(orders[id]) };
}

/** 支付参数: 真实通道在这里生成跳转链接/二维码; mock 通道只回一个占位说明 */
function pay_params(o) {
  if (PAY_PROVIDER === "epay" && EPAY_URL) {
    // 易支付: 客户端拿到 URL 后直接打开浏览器完成支付, 服务端等异步通知
    const q = new URLSearchParams({
      pid: EPAY_PID, type: "alipay", out_trade_no: o.id,
      notify_url: (process.env.HZ_PUBLIC_URL || "") + "/api/pay/notify",
      return_url: (process.env.HZ_PUBLIC_URL || "") + "/pay/return",
      name: "阿信电脑同步器-" + o.plan_name, money: (o.amount / 100).toFixed(2),
    });
    return { provider: "epay", url: EPAY_URL + "/submit.php?" + q.toString() };
  }
  return { provider: "mock", url: "", note: "未接入支付通道, 当前为测试模式" };
}

/** 订单完成 (幂等): 标记已付 + 给账号加时长 */
function order_complete(orderId, tradeNo, channel) {
  const o = orders[orderId];
  if (!o) return { ok: false, msg: "订单不存在" };
  if (o.status === "paid") return { ok: true, msg: "订单已支付", already: true };
  if (o.status !== "pending") return { ok: false, msg: "订单状态异常: " + o.status };
  const u = users[o.user];
  if (!u) return { ok: false, msg: "账号不存在" };

  o.status = "paid";
  o.paid_at = Date.now();
  o.trade_no = String(tradeNo || "").slice(0, 64);
  o.channel = channel || o.channel;
  save(ORDERS_FILE, orders);

  u.plan_id = o.plan_id;
  u.total_paid = (u.total_paid || 0) + o.amount;
  const rem = extend_user(o.user, u, o.days * 86400);
  audit(o.user, "user", "ORDER_PAID", o.id,
        o.plan_name + " ¥" + (o.amount / 100).toFixed(2) + " 剩余=" + rem + "s", "");
  return { ok: true, msg: "开通成功", remaining: rem };
}

/** CDK 兑换: 卡密降级为"充值码", 时长充进账号 */
function redeem_key(name, u, keyStr) {
  const k = keys[keyStr];
  if (!k) return { ok: false, msg: "卡密不存在" };
  if (k.banned) return { ok: false, msg: "卡密已被封禁" };
  if (k.status === "redeemed" || k.status === "used")
    return { ok: false, msg: "该卡密已被兑换" };
  if (k.bound_user && k.bound_user !== name)
    return { ok: false, msg: "该卡密已被其他账号兑换" };

  // 时长 = 卡面时长 + 管理员预先加的时长 (pending_extend 单位是秒)
  const secs = CARD_TYPES[k.type].seconds + (k.pending_extend || 0);
  k.status = "redeemed";
  k.bound_user = name;
  k.redeemed_at = Date.now();
  k.pending_extend = 0;
  save(KEYS_FILE, keys);

  const rem = extend_user(name, u, secs);
  u.plan_id = u.plan_id || k.type;
  user_save();
  audit(name, "user", "REDEEM", keyStr,
        CARD_TYPES[k.type].name + " +" + Math.round(secs / 3600) + "h 剩余=" + rem + "s", "");
  return { ok: true, msg: "兑换成功, 增加 " + Math.round(secs / 3600) + " 小时",
           remaining: rem, card_type: CARD_TYPES[k.type].name };
}

// ---------- 会话 ----------
function session_create(user, role, ip, ua) {
  const sid = crypto.randomBytes(32).toString("hex");
  const now = Date.now();
  sessions[sid] = { user, role, created: now, last: now, expires: now + SESSION_TTL, ip, ua: String(ua || "").slice(0, 120) };
  save(SESSIONS_FILE, sessions);
  return sid;
}
function session_get(sid) {
  const s = sessions[sid];
  if (!s) return null;
  const now = Date.now();
  if (now > s.expires || now - s.last > SESSION_IDLE) { delete sessions[sid]; save(SESSIONS_FILE, sessions); return null; }
  s.last = now;
  return s;
}
function parse_cookies(req) {
  const out = {};
  const raw = req.headers.cookie || "";
  raw.split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}
function cookie_header(sid, maxAgeSec) {
  const age = maxAgeSec === undefined ? Math.floor(SESSION_TTL / 1000) : maxAgeSec;
  return "hzsid=" + sid + "; HttpOnly; SameSite=Lax; Path=/; Max-Age=" + age +
    (SECURE_COOKIE ? "; Secure" : "");
}
// 鉴权: 优先会话 Cookie, 其次根令牌 (x-admin-token)
function auth_admin(req) {
  const sid = parse_cookies(req).hzsid;
  if (sid) {
    const s = session_get(sid);
    if (s) {
      const a = admins[s.user];
      if (a && !a.disabled) return { user: s.user, role: a.role, via: "session" };
    }
  }
  const t = req.headers["x-admin-token"];
  if (t && typeof t === "string" && t.length === ROOT_TOKEN.length &&
      crypto.timingSafeEqual(Buffer.from(t), Buffer.from(ROOT_TOKEN)))
    return { user: "root", role: "owner", via: "root-token" };
  return null;
}
function role_ok(role, need) { return (ROLE_LEVEL[role] || 0) >= (ROLE_LEVEL[need] || 9); }

// 会话清理 (每小时扫描一次过期会话)
const _cleanup = setInterval(() => {
  const now = Date.now();
  let dirty = false;
  for (const [sid, s] of Object.entries(sessions)) {
    if (now > s.expires || now - s.last > SESSION_IDLE) { delete sessions[sid]; dirty = true; }
  }
  if (dirty) save(SESSIONS_FILE, sessions);
}, 3600 * 1000);
if (_cleanup.unref) _cleanup.unref();

// ---------- HTTP ----------
function json_res(res, code, obj) {
  // 幂等保护: 任何逻辑 bug 导致的二次响应都不能让服务进程崩溃 (可用性优先)
  if (res.headersSent || res.writableEnded) { try { res.end(); } catch (e) {} return; }
  const b = JSON.stringify(obj);
  res.writeHead(code, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(b),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
  });
  res.end(b);
}
function read_body(req, res) {
  // 超过 MAX_BODY 直接回 413, 不再 req.destroy():
  // 断连会让客户端只看到 ECONNRESET, 既没有状态码也没法给用户提示, 还会诱发重试风暴。
  return new Promise((resolve) => {
    let b = "", size = 0, over = false;
    const done = (v) => { if (!over) { over = true; resolve(v); } };
    req.on("data", (c) => {
      if (over) return;
      size += c.length;
      if (size > MAX_BODY) {
        json_res(res, 413, { ok: false, msg: "请求体过大 (上限 " + (MAX_BODY / 1024) + "KB)" });
        b = "";
        done(null);           // 已经回过响应, 上层拿到 null 直接结束
        req.resume();         // 把剩余数据读掉, 避免客户端写阻塞
        return;
      }
      b += c;
    });
    req.on("error", () => done(null));
    req.on("aborted", () => done(null));
    req.on("end", () => {
      if (over) return;
      let obj;
      try { obj = JSON.parse(b || "{}"); } catch (e) { obj = {}; }
      if (!obj || typeof obj !== "object") obj = {};
      // 原始报文留在不可枚举属性上: 开放接口的签名要按"收到的字节"算,
      // JSON.parse→stringify 会改写空格/键序, 验签必失败。不可枚举 = 不影响业务代码。
      try { Object.defineProperty(obj, "$raw", { value: b, enumerable: false }); } catch (e) {}
      done(obj);
    });
  });
}

// 管理页: 每次请求重读, 改页面无需重启服务 (访问量极低, IO 可忽略)
let ADMIN_PAGE = "";
function read_admin_page() {
  try {
    const s = fs.readFileSync(path.join(__dirname, "admin.html"), "utf8");
    ADMIN_PAGE = s;
    return s;
  } catch (e) {
    return ADMIN_PAGE || "<h1>admin.html 读取失败</h1>";
  }
}
read_admin_page();

// ================= 开放接口签名 (/api/open/v1) =================
// 签名串 (换行分隔, 任何一项变化签名即失效):
//   METHOD \n PATH \n app_id \n timestamp(ms) \n nonce \n sha256hex(rawBody)
// signature = HMAC-SHA256(secret, 签名串) 十六进制小写
// 时间戳容差 5 分钟 + nonce 5 分钟内不可重复 = 抓到的请求没法重放。
const openNonces = new Map(); // "app|nonce" -> 过期时间
function open_nonce_fresh(appId, nonce) {
  const now = Date.now();
  for (const [k, exp] of openNonces) if (exp < now) openNonces.delete(k);
  const key = appId + "|" + nonce;
  if (openNonces.has(key)) return false;
  openNonces.set(key, now + OPEN_TS_SKEW);
  return true;
}
function open_sign(method, pathname, appId, ts, nonce, raw, secret) {
  const canon = method + "\n" + pathname + "\n" + appId + "\n" + ts + "\n" + nonce + "\n" +
                crypto.createHash("sha256").update(raw || "").digest("hex");
  return crypto.createHmac("sha256", secret).update(canon).digest("hex");
}
function open_ident(appId, ext) { return appId + "|" + ext; }
function ident_save() { save(IDENT_FILE, identities); }

// 真实客户端 IP: 只有在 HZ_TRUST_PROXY=1 (前面确实挂了自己的反代) 时才采信 XFF 第一跳。
// 不信任 XFF 时, 客户端伪造头无法绕过按 IP 的限流/锁定。
function client_ip(req) {
  if (TRUST_PROXY) {
    const xf = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    if (xf) return xf.replace(/^::ffff:/, "").slice(0, 45);
  }
  return (req.socket.remoteAddress || "?").replace(/^::ffff:/, "");
}

const server = http.createServer(async (req, res) => {
  const ip = client_ip(req);
  try {
    const url = new URL(req.url, "http://x");
    const p = url.pathname;

    if (req.method === "GET" && p === "/admin") {
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'",
        "Cache-Control": "no-store",
      });
      return res.end(read_admin_page());
    }
    // 健康检查: 不进限流桶 —— 否则全站被刷到限流时, 监控看到的是"服务挂了"。
    if (p === "/api/ping")
      return json_res(res, 200, { ok: true, msg: "pong", v: 2 });

    // 全局限流: 每 IP 每分钟 240 次 (防扫端口/压测)
    if (!rate_ok("g:" + ip, 240, 60000)) return json_res(res, 429, { ok: false, msg: "请求过于频繁" });

    if (req.method !== "POST" && req.method !== "GET")
      return json_res(res, 405, { ok: false, msg: "method not allowed" });

    // 管理接口一律 POST: 否则一个 <a href> 顶层导航 (SameSite=Lax 不拦) 就能借
    // 管理员的 Cookie 触发写操作 —— GET /api/admin/keys/generate 真的会生成卡密。
    if (p.startsWith("/api/admin/") && req.method !== "POST")
      return json_res(res, 405, { ok: false, msg: "管理接口仅接受 POST" });

    const body = req.method === "POST" ? await read_body(req, res) : {};
    if (body === null) return;   // 超限已回 413, 或连接已断

    // ---- 客户端 API ----
    if (p === "/api/trial" || p === "/api/heartbeat") {
      if (!rate_ok("c:" + ip, 120, 60000)) return json_res(res, 429, { ok: false, msg: "请求过于频繁" });
      const machine = clean(body.machine, 32);
      if (!RE_MACHINE.test(machine)) return json_res(res, 400, { ok: false, msg: "参数错误" });
      const remaining = trial_touch(machine);
      if (remaining <= 0) return json_res(res, 200, { ok: false, msg: "试用时长已用完, 请购买卡密" });
      return json_res(res, 200, { ok: true, remaining });
    }
    if (p === "/api/activate") {
      // 撞库防护: 激活接口更严格 (每 IP 每分钟 20 次)
      if (!rate_ok("a:" + ip, 20, 60000)) return json_res(res, 429, { ok: false, msg: "尝试过于频繁, 请稍后再试" });
      const keyStr = clean(body.key, 32).toUpperCase();
      const machine = clean(body.machine, 32);
      if (!RE_KEY.test(keyStr) || !RE_MACHINE.test(machine))
        return json_res(res, 400, { ok: false, msg: "参数错误" });
      const r = do_activate(keyStr, machine);
      // 换绑单独记一条, 便于事后核对"这张卡被换过几次、每次扣了多少时长"
      if (r.ok && r.rebound)
        audit("client", "-", "REBIND", keyStr,
              "新机器=" + machine + " 扣时=" + (r.cost_seconds / 3600) + "h 第" +
              r.rebind_count + "次 剩" + r.rebind_left + "次", ip);
      audit("client", "-", r.ok ? "ACTIVATE_OK" : "ACTIVATE_FAIL", keyStr,
            r.msg || "", ip);
      return json_res(res, 200, r);
    }
    if (p === "/api/verify") {
      if (!rate_ok("v:" + ip, 120, 60000)) return json_res(res, 429, { ok: false, msg: "请求过于频繁" });
      const keyStr = clean(body.key, 32).toUpperCase();
      const machine = clean(body.machine, 32);
      if (!RE_KEY.test(keyStr) || !RE_MACHINE.test(machine))
        return json_res(res, 400, { ok: false, msg: "参数错误" });
      return json_res(res, 200, do_verify(keyStr, machine));
    }

    // ================= v4 账号 API =================
    // 套餐表公开 (客户端购买页直接渲染, 价格以服务端为准)
    if (p === "/api/plans") {
      return json_res(res, 200, {
        ok: true,
        plans: PLANS.map((x) => ({ ...x, price_yuan: (x.price / 100).toFixed(2) })),
        pay_provider: PAY_PROVIDER,
      });
    }

    if (p === "/api/auth/register") {
      // 注册限流 (防批量注册), 默认每 IP 每分钟 6 次
      if (!rate_ok("rg:" + ip, REG_PER_MIN, 60000))
        return json_res(res, 429, { ok: false, msg: "注册过于频繁, 请稍后再试" });
      const name = clean(body.username, 24).trim();
      const pw = String(body.password || "");
      const machine = clean(body.machine, 32);
      const recovery = String(body.recovery || "");
      if (!RE_USER.test(name))
        return json_res(res, 400, { ok: false, msg: "用户名 3-24 位, 仅字母数字和 _ . -" });
      const prob = pwd_problem(pw);
      if (prob) return json_res(res, 400, { ok: false, msg: prob });
      // 安全码: 新版客户端必带; 老客户端不带也放行 (向后兼容), 登录后可在「账号安全」补设
      const rcProb = recovery ? rc_problem(recovery) : "";
      if (rcProb) return json_res(res, 400, { ok: false, msg: rcProb });
      if (recovery && recovery === pw)
        return json_res(res, 400, { ok: false, msg: "安全码不能和密码相同" });
      if (!RE_MACHINE.test(machine))
        return json_res(res, 400, { ok: false, msg: "参数错误" });
      if (users[name])
        return json_res(res, 200, { ok: false, msg: "用户名已被占用" });

      const u = await create_user(name, pw, recovery);
      bind_machine(name, u, machine);
      // 注册即送体验时长 (同一台机器只能领一次, 复用旧的试用账本)
      let bonus = 0;
      const m = machines[machine];
      if (!m || !(m.trial_used > 0)) {
        bonus = TRIAL_SECONDS;
        machines[machine] = { trial_used: bonus, first_seen: Date.now(), last_seen: Date.now() };
        save(MACHINES_FILE, machines);
        extend_user(name, u, bonus);
      }
      const token = user_session_create(name, machine, ip, req.headers["user-agent"]);
      audit(name, "user", "REGISTER", name,
            "机器=" + machine + " 赠送=" + bonus + "s 安全码=" + (recovery ? "已设" : "未设"), ip);
      return json_res(res, 200, {
        ok: true, token, bonus, ...user_public(name, u, machine),
        msg: bonus ? "注册成功, 已赠送 " + (bonus / 3600) + " 小时体验" : "注册成功",
      });
    }

    if (p === "/api/auth/login") {
      if (!rate_ok("lg:" + ip, 20, 60000))
        return json_res(res, 429, { ok: false, msg: "尝试过于频繁, 请稍后再试" });
      const name = clean(body.username, 24).trim();
      const pw = String(body.password || "");
      const machine = clean(body.machine, 32);
      if (!RE_USER.test(name) || !pw || !RE_MACHINE.test(machine))
        return json_res(res, 400, { ok: false, msg: "参数错误" });

      const r = await user_login_core(name, pw, machine, ip, req.headers["user-agent"], "LOGIN");
      if (!r.ok)
        return json_res(res, 200, {
          ok: false, msg: r.msg, ...(r.need_support ? { need_support: true } : {}),
        });
      return json_res(res, 200, {
        ok: true, token: r.token, rebound: r.rebound, cost_seconds: r.cost_seconds,
        ...user_public(name, r.u, machine),
        msg: r.rebound
          ? "登录成功, 已换绑到本机" + (r.cost_seconds ? " (扣 " + (r.cost_seconds / 3600) + " 小时)" : "")
          : "登录成功",
      });
    }

    // 会话校验 + 续期: 客户端每 60s 调一次, 同时拿到最新剩余时间
    if (p === "/api/auth/me") {
      if (!rate_ok("me:" + ip, 240, 60000))
        return json_res(res, 429, { ok: false, msg: "请求过于频繁" });
      const machine = clean(body.machine, 32);
      const a = user_auth(clean(body.token, 80));
      if (!a) return json_res(res, 200, { ok: false, msg: "登录已失效, 请重新登录" });
      if (a.s.machine !== machine)
        return json_res(res, 200, { ok: false, msg: "登录令牌与本机不符, 请重新登录" });
      // 一账号一机: 账号已在别的机器上重新绑定后, 旧机器的令牌必须立刻失效,
      // 否则"换绑"就只是换了个绑定记录, 两台机器仍能同时用。
      if (a.u.bound_machine && a.u.bound_machine !== machine)
        return json_res(res, 200, { ok: false, msg: "账号已在其他机器登录, 本机已退出" });
      return json_res(res, 200, { ok: true, ...user_public(a.name, a.u, machine) });
    }

    if (p === "/api/auth/logout") {
      const t = clean(body.token, 80);
      if (t && userSessions[t]) { delete userSessions[t]; save(USER_SESS_FILE, userSessions); }
      return json_res(res, 200, { ok: true });
    }

    if (p === "/api/auth/password") {
      const a = user_auth(clean(body.token, 80));
      if (!a) return json_res(res, 200, { ok: false, msg: "请先登录" });
      const oldPw = String(body.old || ""), newPw = String(body.new || "");
      let okOld = false;
      try { okOld = await check_password(oldPw, a.u); } catch (e) {}
      if (!okOld) return json_res(res, 200, { ok: false, msg: "原密码不正确" });
      const prob = pwd_problem(newPw);
      if (prob) return json_res(res, 200, { ok: false, msg: prob });
      const rec = await new_password(newPw);
      a.u.salt = rec.salt; a.u.hash = rec.hash;
      user_save();
      audit(a.name, "user", "PASSWORD_CHANGE", a.name, "", ip);
      return json_res(res, 200, { ok: true, msg: "密码已修改" });
    }

    // 设置 / 更换安全码: 必须已登录 + 验证密码。
    // 只要令牌就能改安全码的话, 令牌被偷的人可以把账号"永久上锁"到自己手里。
    if (p === "/api/auth/recovery_code") {
      if (!rate_ok("rc:" + ip, 10, 10 * 60000))
        return json_res(res, 429, { ok: false, msg: "操作过于频繁" });
      const a = user_auth(clean(body.token, 80));
      if (!a) return json_res(res, 200, { ok: false, msg: "请先登录" });
      const pw = String(body.password || "");
      const code = String(body.recovery || "");
      let okPw = false;
      try { okPw = await check_password(pw, a.u); } catch (e) {}
      if (!okPw) {
        audit(a.name, "user", "RC_SET_FAIL", a.name, "密码错误", ip);
        return json_res(res, 200, { ok: false, msg: "密码不正确" });
      }
      const prob = rc_problem(code);
      if (prob) return json_res(res, 200, { ok: false, msg: prob });
      if (code === pw) return json_res(res, 200, { ok: false, msg: "安全码不能和密码相同" });
      await set_recovery_code(a.u, code);
      user_save();
      audit(a.name, "user", "RC_SET", a.name, "已设置安全码", ip);
      return json_res(res, 200, { ok: true, msg: "安全码已保存, 忘记密码时可用它自助重置" });
    }

    // 忘记密码: 用户名 + 安全码 + 新密码。
    // 这是唯一不需要登录的写操作, 所以限流比登录更狠: 每 IP 每小时 20 次,
    // 同一账号连错 5 次锁 30 分钟; 账号不存在时也做等价耗时运算, 防账号枚举。
    if (p === "/api/auth/forgot") {
      if (!rate_ok("fg:" + ip, 20, 3600000))
        return json_res(res, 429, { ok: false, msg: "找回请求过于频繁, 请 1 小时后再试" });
      const name = clean(body.username, 24).trim();
      const code = String(body.recovery || "");
      const newPw = String(body.new_password || "");
      if (!RE_USER.test(name) || !code)
        return json_res(res, 400, { ok: false, msg: "参数错误" });

      // 同登录: 锁定按 (IP, 账号), 另设账号级高阈值, 避免别人把某个会员的找回入口锁死。
      const bucket = "rp:" + ip + "|" + name.toLowerCase();
      const acctBucket = "r:" + name.toLowerCase();
      const lock = Math.max(fail_locked(bucket), fail_locked(acctBucket));
      if (lock)
        return json_res(res, 200, { ok: false, msg: "安全码错误次数过多, 请 " + lock + " 秒后再试" });

      const u = users[name];
      let codeOk = false;
      try { codeOk = await check_recovery_code(u, code); } catch (e) { codeOk = false; }
      if (!u || !u.rc_hash) {
        // 账号不存在 / 没设安全码: 走一次等价 scrypt, 让响应时间不可区分
        try { await check_password(code, { salt: "0".repeat(32), hash: "0".repeat(128) }); } catch (e) {}
      }
      if (!codeOk) {
        fail_hit(bucket, RECOVER_MAX_FAILS, RECOVER_LOCK_MS);
        fail_hit(acctBucket, 25, RECOVER_LOCK_MS);
        audit(name, "-", "RECOVER_FAIL", name, u ? "安全码错误" : "账号不存在", ip);
        // 恰好触发锁定的那一次就直接告知要等多久 —— 否则用户会以为还能再试,
        // 而"账号不存在"走的是同一套计数, 不会因此暴露账号是否存在。
        const lockSec = Math.max(fail_locked(bucket), fail_locked(acctBucket));
        return json_res(res, 200, {
          ok: false,
          msg: lockSec ? "安全码错误次数过多, 请 " + lockSec + " 秒后再试" : "用户名或安全码不正确",
        });
      }
      if (u.status === "banned") {
        audit(name, "user", "RECOVER_DENY", name, "账号封禁", ip);
        return json_res(res, 200, { ok: false, msg: "账号已被封禁, 请联系客服" });
      }
      const prob = pwd_problem(newPw);
      if (prob) return json_res(res, 200, { ok: false, msg: prob });

      const rec = await new_password(newPw);
      u.salt = rec.salt; u.hash = rec.hash;
      u.pw_changed_at = Date.now();
      user_save();
      // 重置密码后必须踢掉全部旧令牌: 找密码的正当用户会重新登录,
      // 而"因为密码泄露才来重置"的用户, 这一步正是把入侵者赶出去。
      const killed = revoke_user_sessions(name);
      fail_clear(bucket); fail_clear(acctBucket);
      audit(name, "user", "RECOVER_OK", name, "新密码已生效, 踢掉会话=" + killed, ip);
      return json_res(res, 200, {
        ok: true, revoked: killed,
        msg: "密码已重置, 请用新密码重新登录",
      });
    }

    if (p === "/api/redeem") {
      if (!rate_ok("rd:" + ip, 20, 60000))
        return json_res(res, 429, { ok: false, msg: "请求过于频繁" });
      const machine = clean(body.machine, 32);
      const a = user_auth(clean(body.token, 80));
      if (!a) return json_res(res, 200, { ok: false, msg: "请先登录" });
      if (a.s.machine !== machine)
        return json_res(res, 200, { ok: false, msg: "登录令牌与本机不符, 请重新登录" });
      const keyStr = clean(body.key, 32).toUpperCase();
      if (!RE_KEY.test(keyStr)) return json_res(res, 400, { ok: false, msg: "卡密格式不正确" });
      const r = redeem_key(a.name, a.u, keyStr);
      return json_res(res, 200, { ...r, ...(r.ok ? user_public(a.name, a.u, machine) : {}) });
    }

    if (p === "/api/order/create") {
      if (!rate_ok("oc:" + ip, 30, 60000))
        return json_res(res, 429, { ok: false, msg: "请求过于频繁" });
      const machine = clean(body.machine, 32);
      const a = user_auth(clean(body.token, 80));
      if (!a) return json_res(res, 200, { ok: false, msg: "请先登录" });
      if (a.s.machine !== machine)
        return json_res(res, 200, { ok: false, msg: "登录令牌与本机不符, 请重新登录" });
      const r = order_create(a.name, clean(body.plan_id, 16));
      if (!r.ok) return json_res(res, 200, r);
      audit(a.name, "user", "ORDER_CREATE", r.order.id,
            r.order.plan_name + " ¥" + (r.order.amount / 100).toFixed(2), ip);
      return json_res(res, 200, {
        ok: true, order_id: r.order.id, amount: r.order.amount,
        amount_yuan: (r.order.amount / 100).toFixed(2),
        plan_id: r.order.plan_id, plan_name: r.order.plan_name,
        days: r.order.days, pay: r.pay,
      });
    }

    if (p === "/api/order/query") {
      const a = user_auth(clean(body.token, 80));
      if (!a) return json_res(res, 200, { ok: false, msg: "请先登录" });
      const o = orders[clean(body.order_id, 40)];
      if (!o || o.user !== a.name) return json_res(res, 200, { ok: false, msg: "订单不存在" });
      return json_res(res, 200, {
        ok: true, order_id: o.id, status: o.status, amount: o.amount,
        plan_name: o.plan_name, paid_at: o.paid_at,
        ...(o.status === "paid" ? user_public(a.name, a.u, clean(body.machine, 32)) : {}),
      });
    }

    // 测试支付: 只有 PAY_PROVIDER=mock 时开放, 真实通道下这个口子是关死的。
    // 接真实支付后请把 HZ_PAY_PROVIDER 设为 epay/wechat, 本接口自动 404。
    if (p === "/api/order/mock_pay") {
      if (PAY_PROVIDER !== "mock")
        return json_res(res, 404, { ok: false, msg: "未启用测试支付" });
      const a = user_auth(clean(body.token, 80));
      if (!a) return json_res(res, 200, { ok: false, msg: "请先登录" });
      const o = orders[clean(body.order_id, 40)];
      if (!o || o.user !== a.name) return json_res(res, 200, { ok: false, msg: "订单不存在" });
      const r = order_complete(o.id, "MOCK-" + Date.now(), "mock");
      return json_res(res, 200, {
        ...r, ...(r.ok ? user_public(a.name, a.u, clean(body.machine, 32)) : {}),
      });
    }

    // 支付回调 (预留): 真实通道在这里验签后调 order_complete。
    // 注意: 必须验签, 否则任何人 POST 一个 order_id 就能白拿时长。
    if (p === "/api/pay/notify") {
      if (PAY_PROVIDER !== "epay")
        return json_res(res, 404, "fail");
      // 易支付验签: 按参数名排序后拼接 + KEY 做 MD5
      const q = { ...body };
      const sign = String(q.sign || "");
      delete q.sign; delete q.sign_type;
      const raw = Object.keys(q).sort().map((k) => k + "=" + q[k]).join("&") + EPAY_KEY;
      const calc = crypto.createHash("md5").update(raw).digest("hex");
      if (!EPAY_KEY || calc !== sign) {
        audit("pay", "-", "NOTIFY_BADSIGN", String(q.out_trade_no || ""), "", ip);
        return json_res(res, 200, "fail");
      }
      if (String(q.trade_status) !== "TRADE_SUCCESS") return json_res(res, 200, "success");
      const r = order_complete(String(q.out_trade_no || ""), String(q.trade_no || ""), "epay");
      return json_res(res, 200, r.ok ? "success" : "fail");
    }

    // ================= 开放接口 /api/open/v1 (服务端到服务端) =================
    // 用途: 以后新开的平台不再自己存一套账号密码, 通过这里把用户同步进本站,
    // 并复用本站的登录/授权/时长体系。契约见 server/开放接口.md。
    if (p.startsWith("/api/open/v1/")) {
      if (!Object.keys(OPEN_APPS).length)
        return json_res(res, 501, { ok: false, code: "OPEN_API_DISABLED", msg: "开放接口未启用" });
      if (!rate_ok("op:" + ip, 120, 60000))
        return json_res(res, 429, { ok: false, msg: "请求过于频繁" });

      const appId = String(req.headers["x-app-id"] || "");
      const appConf = OPEN_APPS[appId];
      const secret = appConf && appConf.secret;
      const scopes = appConf ? appConf.scopes : new Set();
      const scopeAll = scopes.has("all");   // 只有显式授权 all 才允许跨应用
      const ts = String(req.headers["x-timestamp"] || "");
      const nonce = String(req.headers["x-nonce"] || "");
      const sig = String(req.headers["x-signature"] || "");
      const raw = body.$raw || "";

      const bad = (code, msg) => {
        fail_hit("oa:" + (appId || ip), 20, 5 * 60 * 1000);
        audit(appId || "-", "app", "OPEN_BADSIGN", p, code, ip);
        return json_res(res, 401, { ok: false, code, msg });
      };
      const openLock = fail_locked("oa:" + (appId || ip));
      if (openLock)
        return json_res(res, 429, { ok: false, msg: "该应用签名错误过多, 请 " + openLock + " 秒后再试" });
      if (!secret) return bad("APP_UNKNOWN", "未知应用 (x-app-id)");
      if (!/^\d{13}$/.test(ts) || Math.abs(Date.now() - Number(ts)) > OPEN_TS_SKEW)
        return bad("TS_INVALID", "时间戳无效或偏差超过 5 分钟");
      if (!/^[A-Za-z0-9_-]{8,64}$/.test(nonce)) return bad("NONCE_INVALID", "nonce 格式不正确");
      const want = open_sign(req.method, p, appId, ts, nonce, raw, secret);
      let sigOk = false;
      try {
        sigOk = sig.length === want.length &&
          crypto.timingSafeEqual(Buffer.from(sig, "utf8"), Buffer.from(want, "utf8"));
      } catch (e) { sigOk = false; }
      if (!sigOk) return bad("SIGN_BAD", "签名无效");
      if (!open_nonce_fresh(appId, nonce)) return bad("NONCE_REPLAY", "nonce 已被使用 (请求重放)");

      const extOf = (u) => {
        for (const [k, v] of Object.entries(identities)) {
          const [app, ext] = k.split("|");
          if (app === appId && v.user === u) return ext;
        }
        return "";
      };
      const extUser = (ext) => {
        const m = identities[open_ident(appId, ext)];
        return m && users[m.user] ? { name: m.user, u: users[m.user] } : null;
      };
      // 本应用"拥有"的账号集合。没有 all scope 时只能碰这些账号,
      // 否则任何一个应用的密钥都等于全站会员的读写权 (跨租户越权)。
      let _owned = null;
      const ownedUsers = () => {
        if (_owned) return _owned;
        _owned = new Set();
        for (const [k, v] of Object.entries(identities)) {
          if (k.split("|")[0] === appId && users[v.user]) _owned.add(v.user);
        }
        return _owned;
      };
      const canTouch = (name) => scopeAll || ownedUsers().has(name);
      const out_of_scope = (name) => {
        audit(appId, "app", "OPEN_OUT_OF_SCOPE", name, p, ip);
        return json_res(res, 403, { ok: false, code: "OUT_OF_SCOPE",
          msg: "该账号不属于本应用 (需要 all scope)" });
      };

      if (p === "/api/open/v1/ping")
        return json_res(res, 200, {
          ok: true, app_id: appId, api: "v1", time: Date.now(),
          endpoints: ["ping", "users/register", "users/status", "users/extend",
                      "auth/verify", "auth/login"],
        });

      // 代注册: external_id 是对方平台的用户主键, 幂等 —— 同一个 external_id
      // 无论调多少次都只会建一个账号, 重复调用返回现状 (对方重试不会造出重号)。
      if (p === "/api/open/v1/users/register") {
        const ext = clean(body.external_id, 64).trim();
        if (!ext) return json_res(res, 400, { ok: false, msg: "缺少 external_id" });
        // identities 的键是 "appId|external_id", 用 | 当分隔符;
        // 外部 ID 自带 | 会让键拆分错位 (回显被截断), 注册时直接拒掉。
        if (ext.includes("|"))
          return json_res(res, 400, { ok: false, msg: "external_id 不能包含 | 字符" });
        const exist = extUser(ext);
        if (exist)
          return json_res(res, 200, {
            ok: true, created: false, user: exist.name, external_id: ext,
            ...user_public(exist.name, exist.u, ""),
          });

        let name = clean(body.username, 24).trim();
        if (name) {
          if (!RE_USER.test(name))
            return json_res(res, 400, { ok: false, msg: "用户名 3-24 位, 仅字母数字和 _ . -" });
          if (users[name])
            return json_res(res, 409, { ok: false, code: "USERNAME_TAKEN", msg: "用户名已被占用" });
        } else {
          do { name = "u_" + crypto.randomBytes(4).toString("hex"); } while (users[name]);
        }
        let initial = "";
        const pw = String(body.password || "");
        if (pw) {
          const prob = pwd_problem(pw);
          if (prob) return json_res(res, 400, { ok: false, msg: prob });
        } else {
          initial = rand_password(14);   // 只返回这一次, 对方负责转交或强制改密
        }
        const recovery = String(body.recovery || "");
        if (recovery) {
          const rcP = rc_problem(recovery);
          if (rcP) return json_res(res, 400, { ok: false, msg: rcP });
        }
        const u = await create_user(name, pw || initial, recovery);
        u.note = clean(body.note, 50) || ("来自 " + appId);
        user_save();
        identities[open_ident(appId, ext)] = { user: name, created_at: Date.now() };
        ident_save();
        audit(appId, "app", "OPEN_REGISTER", name, "外部ID=" + ext, ip);
        return json_res(res, 200, {
          ok: true, created: true, user: name, external_id: ext,
          ...(initial ? { initial_password: initial } : {}),
          ...user_public(name, u, ""),
        });
      }

      if (p === "/api/open/v1/users/status") {
        const ext = clean(body.external_id, 64).trim();
        const hit = ext ? extUser(ext) : null;
        if (!hit) {
          const nm = clean(body.username, 24).trim();
          if (nm && users[nm]) {
            if (!canTouch(nm)) return out_of_scope(nm);
            return json_res(res, 200, { ok: true, ...user_public(nm, users[nm], "") });
          }
          return json_res(res, 200, { ok: false, code: "NOT_FOUND", msg: "账号不存在" });
        }
        return json_res(res, 200, { ok: true, external_id: ext, ...user_public(hit.name, hit.u, "") });
      }

      // 加时长: 平台把自己的订阅权益折算成秒同步过来 (补单/活动/迁移都靠它)
      if (p === "/api/open/v1/users/extend") {
        const ext = clean(body.external_id, 64).trim();
        let hit = ext ? extUser(ext) : null;
        if (!hit) {
          const nm = clean(body.username, 24).trim();
          if (nm && users[nm]) hit = { name: nm, u: users[nm] };
        }
        if (!hit) return json_res(res, 200, { ok: false, code: "NOT_FOUND", msg: "账号不存在" });
        if (!canTouch(hit.name)) return out_of_scope(hit.name);
        const secs = Math.max(0, Math.min(parseInt(body.seconds) || 0, 10 * 365 * 86400));
        if (!secs) return json_res(res, 400, { ok: false, msg: "seconds 必须是正整数" });
        const rem = extend_user(hit.name, hit.u, secs);
        audit(appId, "app", "OPEN_EXTEND", hit.name, "+" + secs + "s 剩余=" + rem + "s", ip);
        return json_res(res, 200, { ok: true, user: hit.name, remaining: rem });
      }

      // 令牌校验: 对方拿着本站发给用户的令牌, 确认"这人是谁、还有多少时长"
      if (p === "/api/open/v1/auth/verify") {
        const a = user_auth(clean(body.token, 80));
        if (!a) return json_res(res, 200, { ok: false, code: "TOKEN_INVALID", msg: "登录已失效" });
        if (!canTouch(a.name)) return out_of_scope(a.name);
        const machine = clean(body.machine, 32);
        if (machine && a.s.machine !== machine)
          return json_res(res, 200, { ok: false, code: "MACHINE_MISMATCH", msg: "令牌与本机不符" });
        if (machine && a.u.bound_machine && a.u.bound_machine !== machine)
          return json_res(res, 200, { ok: false, code: "MACHINE_MISMATCH", msg: "账号已在其他机器登录" });
        return json_res(res, 200, {
          ok: true, external_id: extOf(a.name), ...user_public(a.name, a.u, machine),
        });
      }

      // 登录: 与客户端 /api/auth/login 共用一条核心路径 (含限流/换绑/审计)
      if (p === "/api/open/v1/auth/login") {
        if (!rate_ok("olg:" + ip, 30, 60000))
          return json_res(res, 429, { ok: false, msg: "尝试过于频繁" });
        const name = clean(body.username, 24).trim();
        const pw = String(body.password || "");
        const machine = clean(body.machine, 32);
        if (!RE_USER.test(name) || !pw || !RE_MACHINE.test(machine))
          return json_res(res, 400, { ok: false, msg: "参数错误" });
        // 存在性探测也挡在 scope 外: 否则任何应用都能拿本站令牌试别家账号的口令
        if (users[name] && !canTouch(name)) return out_of_scope(name);
        const r = await user_login_core(name, pw, machine, ip, "open:" + appId, "OPEN_LOGIN");
        if (!r.ok) return json_res(res, 200, { ok: false, msg: r.msg });
        return json_res(res, 200, {
          ok: true, token: r.token, rebound: r.rebound, cost_seconds: r.cost_seconds,
          external_id: extOf(name), ...user_public(name, r.u, machine),
        });
      }

      return json_res(res, 404, { ok: false, code: "NO_SUCH_ENDPOINT", msg: "接口不存在" });
    }

    // ---- 管理: 登录 (无需鉴权) ----
    if (p === "/api/admin/login") {
      if (!rate_ok("L:" + ip, 20, 60000)) return json_res(res, 429, { ok: false, msg: "登录尝试过于频繁" });
      const username = clean(body.username, 24);
      // 锁定维度: (IP + 账号) 为主, 账号级 50 次/15 分钟兜底。
      // 原来按 IP 单独计数 —— 任何人连错 10 次就能让同 IP 的所有管理员 15 分钟进不来
      // (后台挂在反代后面时等于全家一起被锁), 现在换 IP 打不到真实管理员。
      const pairLock = fail_locked("ap:" + ip + "|" + username);
      const acctLock = fail_locked("au:" + username);
      const lock = Math.max(pairLock, acctLock);
      if (lock) return json_res(res, 429, { ok: false, msg: "失败次数过多, 请 " + lock + " 秒后再试" });
      const password = String(body.password == null ? "" : body.password);
      const a = admins[username];
      let okRec = null;
      if (a && !a.disabled) {
        try { if (await check_password(password, a)) okRec = a; } catch (e) {}
      } else if (a) {
        // 账号被禁用时也做一次等价耗时, 避免用它探测账号状态
        try { await check_password(password, a); } catch (e) {}
      } else {
        try { await check_password(password, { salt: "0".repeat(32), hash: "0".repeat(128) }); } catch (e) {}
      }
      if (!okRec) {
        fail_hit("ap:" + ip + "|" + username, 10, 15 * 60 * 1000);
        fail_hit("au:" + username, 50, 15 * 60 * 1000);
        audit(username || "?", "-", "LOGIN_FAIL", "-", "ip=" + ip, ip);
        return json_res(res, 401, { ok: false, msg: "用户名或密码错误" });
      }
      fail_clear("ap:" + ip + "|" + username); fail_clear("au:" + username);
      const sid = session_create(username, okRec.role, ip, req.headers["user-agent"]);
      okRec.last_login = Date.now();
      save_admins();
      audit(username, okRec.role, "LOGIN_OK", "-", "ip=" + ip, ip);
      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Set-Cookie": cookie_header(sid),
        "Cache-Control": "no-store",
      });
      return res.end(JSON.stringify({ ok: true, user: username, role: okRec.role, must_change: !!okRec.must_change }));
    }

    // ---- 管理 API (需鉴权) ----
    if (p.startsWith("/api/admin/")) {
      const who = auth_admin(req);
      if (!who) return json_res(res, 401, { ok: false, msg: "未登录或登录已过期", need_login: true });
      // 权限校验助手: 通过返回 null; 拒绝时已写入响应并返回 true (调用处 `if (A()) return;`)
      const A = (need, action, target, detail) => {
        if (!role_ok(who.role, need)) {
          audit(who.user, who.role, "DENIED", target || "-", (action || "") + " (权限不足)", ip);
          json_res(res, 403, { ok: false, msg: "权限不足 (需要 " + need + " 角色)" });
          return true;
        }
        return null;
      };
      // 强制改密: owner 首次登录必须先改密码
      if (admins[who.user] && admins[who.user].must_change && who.via === "session" &&
          !["/api/admin/change_password", "/api/admin/logout", "/api/admin/me"].includes(p))
        return json_res(res, 403, { ok: false, msg: "请先修改初始密码", need_change_password: true });

      if (p === "/api/admin/me")
        return json_res(res, 200, { ok: true, user: who.user, role: who.role, via: who.via });

      if (p === "/api/admin/logout") {
        const sid = parse_cookies(req).hzsid;
        if (sid) { delete sessions[sid]; save(SESSIONS_FILE, sessions); }
        audit(who.user, who.role, "LOGOUT", "-", "", ip);
        res.writeHead(200, { "Content-Type": "application/json; charset=utf-8", "Set-Cookie": cookie_header("", 0) });
        return res.end(JSON.stringify({ ok: true }));
      }

      if (p === "/api/admin/change_password") {
        const oldPw = String(body.old_password == null ? "" : body.old_password);
        const newPw = String(body.new_password == null ? "" : body.new_password);
        const a = admins[who.user];
        if (!a) return json_res(res, 400, { ok: false, msg: "账号不存在" });
        if (who.via === "session" && !(await check_password(oldPw, a))) {
          audit(who.user, who.role, "CHANGE_PASSWORD_FAIL", who.user, "原密码错误", ip);
          return json_res(res, 401, { ok: false, msg: "原密码错误" });
        }
        // 管理台与客户端账号共用同一套强度规则: 原先这里只查长度, 能把 owner 密码设成 12345678
        const prob = pwd_problem(newPw);
        if (prob) return json_res(res, 400, { ok: false, msg: prob });
        if (who.via === "session" && oldPw === newPw)
          return json_res(res, 400, { ok: false, msg: "新密码不能与原密码相同" });
        Object.assign(a, await new_password(newPw), { must_change: false });
        save_admins();
        // 改密即吊销该账号除当前会话外的全部会话: 被盗用的旧 Cookie 不能活过这次改密
        const curSid = parse_cookies(req).hzsid;
        let revoked = 0;
        for (const [sid, s] of Object.entries(sessions)) {
          if (s.user === who.user && sid !== curSid) { delete sessions[sid]; revoked++; }
        }
        if (revoked) save(SESSIONS_FILE, sessions);
        audit(who.user, who.role, "CHANGE_PASSWORD", who.user,
              "吊销其他会话 " + revoked + " 个", ip);
        return json_res(res, 200, { ok: true, msg: "密码已修改", revoked_sessions: revoked });
      }

      // ---- 卡密: 生成 ----
      if (p === "/api/admin/keys/generate") {
        const d = A("admin", "generate"); if (d) return d;
        const type = CARD_TYPES[body.type] ? body.type : "day";
        const count = Math.min(Math.max(parseInt(body.count) || 1, 1), 100);
        const note = clean(body.note, 50);
        const made = [];
        for (let i = 0; i < count; i++) {
          const keyStr = gen_key();
          keys[keyStr] = {
            type, status: "unused", banned: false, note,
            bound_machine: "", activated_at: 0, expires_at: 0,
            created_at: Date.now(), pending_extend: 0, extend_total: 0,
            created_by: who.user,
          };
          made.push(keyStr);
        }
        save(KEYS_FILE, keys);
        audit(who.user, who.role, "GENERATE", made.length + "张", type + " note=" + note, ip);
        return json_res(res, 200, { ok: true, keys: made, card_type: CARD_TYPES[type].name });
      }

      // ---- 卡密: 列表 (搜索/筛选/分页) ----
      if (p === "/api/admin/keys") {
        const d = A("viewer", "list"); if (d) return d;
        const q = clean(body.q, 40).toUpperCase();
        const ftype = clean(body.type, 12);
        const fstate = clean(body.state, 12);
        const page = Math.min(Math.max(parseInt(body.page) || 1, 1), 9999);
        const size = Math.min(Math.max(parseInt(body.size) || 50, 1), 200);
        let list = Object.entries(keys).map(([keyStr, k]) => {
          const st = key_state(k);
          return {
            key: keyStr, type: k.type, type_name: CARD_TYPES[k.type].name,
            status: k.status, state: st, banned: k.banned, note: k.note || "",
            machine: k.bound_machine || "", expires_at: k.expires_at,
            expires: k.expires_at ? new Date(k.expires_at).toLocaleString("zh-CN") : "-",
            remaining: k.status === "active" ? key_remaining(k) : null,
            pending_extend: k.pending_extend || 0,
            // 换绑次数: used/max, 让管理员一眼看出这张卡被换过几台机器
            rebind_used: k.rebind_count || 0,
            rebind_max: REBIND_MAX_TIMES,
            rebind_left: Math.max(0, REBIND_MAX_TIMES - (k.rebind_count || 0)),
            rebind_cost_total: k.rebind_cost_total || 0,
            created: k.created_at ? new Date(k.created_at).toLocaleString("zh-CN") : "-",
          };
        });
        if (q) list = list.filter((r) => r.key.includes(q) || r.note.toUpperCase().includes(q) || r.machine.toUpperCase().includes(q));
        if (ftype && CARD_TYPES[ftype]) list = list.filter((r) => r.type === ftype);
        if (fstate) list = list.filter((r) => r.state === fstate);
        list.sort((a, b) => (b.expires_at || 0) - (a.expires_at || 0) || b.key.localeCompare(a.key));
        const total = list.length;
        const slice = list.slice((page - 1) * size, page * size);
        const stats = { total: Object.keys(keys).length, unused: 0, active: 0, expired: 0, banned: 0 };
        for (const k of Object.values(keys)) { const st = key_state(k); if (stats[st] !== undefined) stats[st]++; }
        return json_res(res, 200, { ok: true, keys: slice, total, page, size, stats });
      }

      // ---- 卡密: 加时长 (核心新功能) ----
      if (p === "/api/admin/keys/extend") {
        const d = A("admin", "extend"); if (d) return d;
        const keyStr = clean(body.key, 32).toUpperCase();
        const k = RE_KEY.test(keyStr) ? keys[keyStr] : null;
        if (!k) return json_res(res, 200, { ok: false, msg: "卡密不存在" });
        const unit = clean(body.unit, 8);
        const amount = parseInt(body.amount);
        const UNIT_SEC = { hour: 3600, day: 86400, week: 604800, month: 2592000, year: 31536000 };
        if (!UNIT_SEC[unit] || !(amount >= 1 && amount <= 999))
          return json_res(res, 400, { ok: false, msg: "时长参数错误 (unit: hour/day/week/month/year, amount: 1-999)" });
        const delta = UNIT_SEC[unit] * amount;
        if (k.status === "active") {
          // 已激活: 从"当前到期时间"或"现在"起算, 取较晚者 (已过期则从现在起算)
          const base = Math.max(k.expires_at || 0, Date.now());
          k.expires_at = base + delta * 1000;
          k.extend_total = (k.extend_total || 0) + delta;
          // 已过期卡续期后解除过期状态
          k.status = "active";
        } else {
          // 未激活: 记入待生效时长, 首次激活时一并加上
          k.pending_extend = (k.pending_extend || 0) + delta;
          k.extend_total = (k.extend_total || 0) + delta;
        }
        save(KEYS_FILE, keys);
        audit(who.user, who.role, "EXTEND", keyStr, "+" + amount + unit + " 到期=" +
          (k.expires_at ? new Date(k.expires_at).toLocaleString("zh-CN") : "激活后生效"), ip);
        return json_res(res, 200, {
          ok: true, msg: k.status === "active"
            ? "已续期至 " + new Date(k.expires_at).toLocaleString("zh-CN")
            : "已记录 +" + amount + unit + ", 用户激活时生效",
          expires: k.expires_at ? new Date(k.expires_at).toLocaleString("zh-CN") : "-",
          remaining: k.status === "active" ? key_remaining(k) : null,
        });
      }

      // ---- 卡密: 封禁/解封 ----
      if (p === "/api/admin/ban") {
        const d = A("admin", "ban"); if (d) return d;
        const keyStr = clean(body.key, 32).toUpperCase();
        const k = RE_KEY.test(keyStr) ? keys[keyStr] : null;
        if (!k) return json_res(res, 200, { ok: false, msg: "卡密不存在" });
        k.banned = !!body.banned;
        save(KEYS_FILE, keys);
        audit(who.user, who.role, k.banned ? "BAN" : "UNBAN", keyStr, "", ip);
        return json_res(res, 200, { ok: true, banned: k.banned });
      }

      // ---- 卡密: 解绑机器 (客户换电脑) ----
      if (p === "/api/admin/keys/unbind") {
        const d = A("admin", "unbind"); if (d) return d;
        const keyStr = clean(body.key, 32).toUpperCase();
        const k = RE_KEY.test(keyStr) ? keys[keyStr] : null;
        if (!k) return json_res(res, 200, { ok: false, msg: "卡密不存在" });
        const old = k.bound_machine;
        // 剩余时长转入 pending, 换机后不损失时间
        if (k.status === "active") k.pending_extend = (k.pending_extend || 0) + key_remaining(k);
        k.bound_machine = "";
        k.status = "unused";
        k.expires_at = 0;
        save(KEYS_FILE, keys);
        audit(who.user, who.role, "UNBIND", keyStr, "原机器=" + old, ip);
        return json_res(res, 200, { ok: true, msg: "已解绑, 可在新机器重新激活(时长保留)" });
      }

      // ---- 卡密: 改备注 ----
      if (p === "/api/admin/keys/note") {
        const d = A("admin", "note"); if (d) return d;
        const keyStr = clean(body.key, 32).toUpperCase();
        const k = RE_KEY.test(keyStr) ? keys[keyStr] : null;
        if (!k) return json_res(res, 200, { ok: false, msg: "卡密不存在" });
        k.note = clean(body.note, 50);
        save(KEYS_FILE, keys);
        audit(who.user, who.role, "NOTE", keyStr, k.note, ip);
        return json_res(res, 200, { ok: true });
      }

      // ---- 卡密: 删除 (仅 owner) ----
      if (p === "/api/admin/keys/delete") {
        const d = A("owner", "delete"); if (d) return d;
        const keyStr = clean(body.key, 32).toUpperCase();
        if (!RE_KEY.test(keyStr) || !keys[keyStr]) return json_res(res, 200, { ok: false, msg: "卡密不存在" });
        delete keys[keyStr];
        save(KEYS_FILE, keys);
        audit(who.user, who.role, "DELETE", keyStr, "", ip);
        return json_res(res, 200, { ok: true });
      }

      // ---- 统计 ----
      if (p === "/api/admin/stats") {
        const d = A("viewer", "stats"); if (d) return d;
        const stats = { total: 0, unused: 0, active: 0, expired: 0, banned: 0, machines: Object.keys(machines).length, by_type: {} };
        for (const k of Object.values(keys)) {
          stats.total++;
          const st = key_state(k);
          if (stats[st] !== undefined) stats[st]++;
          stats.by_type[k.type] = (stats.by_type[k.type] || 0) + 1;
        }
        return json_res(res, 200, { ok: true, stats });
      }

      // ---- 会员管理 (终端用户, 与上面的"管理员账号"是两套完全独立的体系) ----
      if (p === "/api/admin/members") {
        const d = A("viewer", "members"); if (d) return d;
        const q = clean(body.q, 40);
        const fstate = clean(body.state, 12);
        const page = Math.min(Math.max(parseInt(body.page) || 1, 1), 9999);
        const size = Math.min(Math.max(parseInt(body.size) || 50, 1), 200);
        let list = Object.entries(users).map(([name, u]) => ({
          user: name,
          state: user_state(u),
          plan_id: u.plan_id || "",
          plan_name: (PLAN_MAP[u.plan_id] || {}).name || "-",
          remaining: user_remaining(u),
          expires: u.expires_at ? new Date(u.expires_at).toLocaleString("zh-CN") : "-",
          expires_at: u.expires_at || 0,
          machine: u.bound_machine || "",
          rebind_used: u.rebind_count || 0,
          rebind_left: Math.max(0, REBIND_MAX_TIMES - (u.rebind_count || 0)),
          total_paid: u.total_paid || 0,
          status: u.status || "active",
          note: u.note || "",
          created: u.created_at ? new Date(u.created_at).toLocaleString("zh-CN") : "-",
          last_login: u.last_login ? new Date(u.last_login).toLocaleString("zh-CN") : "-",
          rc_set: !!u.rc_hash,
        }));
        if (q) list = list.filter((r) => r.user.includes(q) || r.machine.includes(q));
        if (fstate) list = list.filter((r) => r.state === fstate);
        list.sort((a, b) => (b.expires_at || 0) - (a.expires_at || 0));
        const total = list.length;
        const stats = { total: 0, active: 0, expired: 0, banned: 0, revenue: 0 };
        for (const u of Object.values(users)) {
          stats.total++;
          const st = user_state(u);
          if (stats[st] !== undefined) stats[st]++;
          stats.revenue += u.total_paid || 0;
        }
        return json_res(res, 200, {
          ok: true, members: list.slice((page - 1) * size, page * size),
          total, page, size, stats,
        });
      }
      if (p === "/api/admin/members/ban") {
        const d = A("admin", "member_ban"); if (d) return d;
        const name = clean(body.user, 24);
        const u = users[name];
        if (!u) return json_res(res, 200, { ok: false, msg: "会员不存在" });
        u.status = body.banned ? "banned" : "active";
        user_save();
        if (body.banned) {   // 封禁即踢下线
          for (const [t, s] of Object.entries(userSessions))
            if (s.user === name) delete userSessions[t];
          save(USER_SESS_FILE, userSessions);
        }
        audit(who.user, who.role, body.banned ? "MEMBER_BAN" : "MEMBER_UNBAN", name, "", ip);
        return json_res(res, 200, { ok: true, status: u.status });
      }
      if (p === "/api/admin/members/extend") {
        const d = A("admin", "member_extend"); if (d) return d;
        const name = clean(body.user, 24);
        const u = users[name];
        if (!u) return json_res(res, 200, { ok: false, msg: "会员不存在" });
        const unit = clean(body.unit, 8);
        const amount = Math.max(0, Math.min(parseInt(body.amount) || 0, 3650));
        const mult = { hour: 3600, day: 86400, week: 604800, month: 2592000, year: 31536000 }[unit];
        if (!mult || !amount) return json_res(res, 400, { ok: false, msg: "参数错误" });
        const rem = extend_user(name, u, amount * mult);
        audit(who.user, who.role, "MEMBER_EXTEND", name,
              "+" + amount + unit + " 剩余=" + rem + "s", ip);
        return json_res(res, 200, { ok: true, remaining: rem });
      }
      if (p === "/api/admin/members/unbind") {
        const d = A("admin", "member_unbind"); if (d) return d;
        const name = clean(body.user, 24);
        const u = users[name];
        if (!u) return json_res(res, 200, { ok: false, msg: "会员不存在" });
        const old = u.bound_machine;
        u.bound_machine = "";       // 下次登录在新机器上自动绑定, 不扣时不计次
        user_save();
        audit(who.user, who.role, "MEMBER_UNBIND", name, "原机器=" + old, ip);
        return json_res(res, 200, { ok: true, msg: "已解绑, 下次登录自动绑定新机器" });
      }
      if (p === "/api/admin/orders") {
        const d = A("viewer", "orders"); if (d) return d;
        const page = Math.min(Math.max(parseInt(body.page) || 1, 1), 9999);
        const size = Math.min(Math.max(parseInt(body.size) || 50, 1), 200);
        const fst = clean(body.status, 12);
        // q 同时匹配会员名 / 订单号; user 是明确按会员筛。客服对账不再靠翻页。
        const qRaw = clean(body.q, 40).trim();
        const fUser = clean(body.user, 24).trim();
        const fId = qRaw.toUpperCase();
        let list = Object.values(orders).map((o) => ({
          ...o,
          amount_yuan: (o.amount / 100).toFixed(2),
          created: new Date(o.created_at).toLocaleString("zh-CN"),
          paid: o.paid_at ? new Date(o.paid_at).toLocaleString("zh-CN") : "-",
        }));
        if (fst) list = list.filter((o) => o.status === fst);
        if (fUser) list = list.filter((o) => o.user === fUser);
        if (qRaw) {
          const ql = qRaw.toLowerCase();
          list = list.filter((o) => o.user.toLowerCase().includes(ql) ||
            String(o.id).toUpperCase().includes(fId) ||
            String(o.plan_name).includes(qRaw));
        }
        list.sort((a, b) => b.created_at - a.created_at);
        return json_res(res, 200, {
          ok: true, orders: list.slice((page - 1) * size, page * size),
          total: list.length, page, size,
        });
      }
      if (p === "/api/admin/orders/confirm") {
        // 线下转账/测试支付的兜底入口: 管理员确认收款后开通
        const d = A("admin", "order_confirm"); if (d) return d;
        const r = order_complete(clean(body.order_id, 40), "MANUAL-" + who.user, "manual");
        return json_res(res, 200, r);
      }

      // ---- 账号管理 (仅 owner) ----
      if (p === "/api/admin/users") {
        const d = A("owner", "users"); if (d) return d;
        const list = Object.entries(admins).map(([u, a]) => ({
          user: u, role: a.role, disabled: !!a.disabled, note: a.note || "",
          created: new Date(a.created_at || 0).toLocaleString("zh-CN"),
          last_login: a.last_login ? new Date(a.last_login).toLocaleString("zh-CN") : "-",
          must_change: !!a.must_change,
        }));
        return json_res(res, 200, { ok: true, users: list });
      }
      if (p === "/api/admin/users/create") {
        const d = A("owner", "user_create"); if (d) return d;
        const u = clean(body.username, 24);
        const pw = String(body.password == null ? "" : body.password);
        const role = ROLE_LEVEL[body.role] ? body.role : "admin";
        if (!RE_USER.test(u)) return json_res(res, 400, { ok: false, msg: "用户名需 3-24 位字母数字_.-" });
        if (admins[u]) return json_res(res, 400, { ok: false, msg: "用户名已存在" });
        if (!["admin", "viewer"].includes(role)) return json_res(res, 400, { ok: false, msg: "只能创建 admin/viewer 账号" });
        const prob = pwd_problem(pw);
        if (prob) return json_res(res, 400, { ok: false, msg: prob });
        admins[u] = { ...(await new_password(pw)), role, created_at: Date.now(), disabled: false,
                      must_change: true, last_login: 0, note: clean(body.note, 50), created_by: who.user };
        save_admins();
        audit(who.user, who.role, "USER_CREATE", u, "role=" + role, ip);
        return json_res(res, 200, { ok: true, msg: "账号已创建 (首次登录需改密码)" });
      }
      if (p === "/api/admin/users/disable") {
        const d = A("owner", "user_disable"); if (d) return d;
        const u = clean(body.username, 24);
        if (!admins[u]) return json_res(res, 400, { ok: false, msg: "账号不存在" });
        if (u === who.user) return json_res(res, 400, { ok: false, msg: "不能禁用自己" });
        admins[u].disabled = !!body.disabled;
        if (admins[u].disabled) for (const [sid, s] of Object.entries(sessions)) if (s.user === u) delete sessions[sid];
        save_admins(); save(SESSIONS_FILE, sessions);
        audit(who.user, who.role, admins[u].disabled ? "USER_DISABLE" : "USER_ENABLE", u, "", ip);
        return json_res(res, 200, { ok: true });
      }
      if (p === "/api/admin/users/reset_password") {
        const d = A("owner", "user_reset"); if (d) return d;
        const u = clean(body.username, 24);
        const pw = String(body.password == null ? "" : body.password);
        if (!admins[u]) return json_res(res, 400, { ok: false, msg: "账号不存在" });
        const prob = pwd_problem(pw);
        if (prob) return json_res(res, 400, { ok: false, msg: prob });
        if (u === who.user) return json_res(res, 400, { ok: false, msg: "改自己的密码请用「修改密码」并验证原密码" });
        Object.assign(admins[u], await new_password(pw), { must_change: true });
        for (const [sid, s] of Object.entries(sessions)) if (s.user === u) delete sessions[sid];
        save_admins(); save(SESSIONS_FILE, sessions);
        audit(who.user, who.role, "USER_RESET_PW", u, "", ip);
        return json_res(res, 200, { ok: true, msg: "密码已重置, 该账号下次登录需改密码" });
      }
      if (p === "/api/admin/users/delete") {
        const d = A("owner", "user_delete"); if (d) return d;
        const u = clean(body.username, 24);
        if (!admins[u]) return json_res(res, 400, { ok: false, msg: "账号不存在" });
        if (u === who.user) return json_res(res, 400, { ok: false, msg: "不能删除自己" });
        if (admins[u].role === "owner") return json_res(res, 400, { ok: false, msg: "不能删除 owner" });
        delete admins[u];
        for (const [sid, s] of Object.entries(sessions)) if (s.user === u) delete sessions[sid];
        save_admins(); save(SESSIONS_FILE, sessions);
        audit(who.user, who.role, "USER_DELETE", u, "", ip);
        return json_res(res, 200, { ok: true });
      }

      // ---- 审计日志 ----
      if (p === "/api/admin/audit") {
        const d = A("admin", "audit"); if (d) return d;
        let lines = [];
        try { lines = fs.readFileSync(AUDIT_FILE, "utf8").trim().split("\n").filter(Boolean); } catch (e) {}
        const n = Math.min(Math.max(parseInt(body.limit) || 100, 1), 500);
        // 先按条件筛, 再截取最近 n 条 —— 否则"翻 30 天前某个人做过什么"永远筛不到。
        const fUser = clean(body.user, 24).trim();
        const fAction = clean(body.action, 24).trim().toUpperCase();
        const q = clean(body.q, 60).trim().toLowerCase();
        let parsed = lines.map((l) => { try { return JSON.parse(l); } catch (e) { return { t: "-", action: l }; } });
        if (fUser) parsed = parsed.filter((x) => String(x.user || "") === fUser || String(x.target || "") === fUser);
        if (fAction) parsed = parsed.filter((x) => String(x.action || "").toUpperCase() === fAction);
        if (q) parsed = parsed.filter((x) => JSON.stringify(x).toLowerCase().includes(q));
        const out = parsed.slice(-n).reverse();
        return json_res(res, 200, { ok: true, logs: out, total: parsed.length });
      }
      return json_res(res, 404, { ok: false, msg: "not found" });
    }

    return json_res(res, 404, { ok: false, msg: "not found" });
  } catch (e) {
    // 不向客户端泄露堆栈
    try { fs.appendFileSync(path.join(DATA_DIR, "error.log"), new Date().toISOString() + " " + (e && e.stack) + "\n"); } catch (x) {}
    return json_res(res, 500, { ok: false, msg: "服务器内部错误" });
  }
});

// 监听地址: 默认全网卡 (生产/LAN 用); 本地演示或只挂反代时可设 HZ_HOST=127.0.0.1
const HOST = process.env.HZ_HOST || "0.0.0.0";
server.listen(PORT, HOST, () => {
  console.log("[阿信KEY后台 v2] listening on %s:%d", HOST, PORT);
  console.log("[阿信KEY后台 v2] admin: http://localhost:%d/admin", PORT);
  console.log("[阿信KEY后台 v2] 根令牌(自动化用): %s", ROOT_TOKEN);
});

process.on("SIGTERM", () => { save(SESSIONS_FILE, sessions); flush_throttle(); process.exit(0); });

// 兜底: 任何漏网异常只记录不退出 (授权服务中断 = 全体用户掉线, 可用性优先)
process.on("uncaughtException", (e) => {
  try { fs.appendFileSync(path.join(DATA_DIR, "error.log"), new Date().toISOString() + " UNCAUGHT " + (e && e.stack) + "\n"); } catch (x) {}
});
process.on("unhandledRejection", (e) => {
  try { fs.appendFileSync(path.join(DATA_DIR, "error.log"), new Date().toISOString() + " UNHANDLED " + (e && e.stack) + "\n"); } catch (x) {}
});
