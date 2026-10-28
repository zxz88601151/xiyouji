// -*- coding: utf-8 -*-
// 阿信电脑同步器 KEY 后台 · 管理员账号离线维护工具 (零依赖, Node >= 14)
//
// 解决的实际问题: owner 密码忘了、或账号被自己的爆破防护锁住时, 后台唯一的恢复入口。
//
// 必须在服务停止时运行: server.js 把 admins.json 读在内存里, 服务运行期间改盘会在
// 下一次写盘时被内存覆盖, 改动凭空消失。所以这里主动检测 pidfile 并拒绝。
//
// 用法:
//   node reset_admin.js --list
//   node reset_admin.js --reset --user admin --generate
//   node reset_admin.js --reset --user admin --password 'NewPass2026'
//   node reset_admin.js --rename --user admin --to axin
//   node reset_admin.js --create --user axin2 --role owner --generate
//   通用开关: --dry-run  --data-dir <路径>  --force  --out <凭据文件>
//   --reset 附加: --enable (解除禁用)  --force-change (下次登录强制改密)
//   --create 附加: --note <备注>
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DATA_DIR = path.resolve(process.argv.includes("--data-dir")
  ? process.argv[process.argv.indexOf("--data-dir") + 1]
  : (process.env.HZ_DATA_DIR || path.join(__dirname, "data")));
const ADMINS_FILE = path.join(DATA_DIR, "admins.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");
const PID_FILE = path.join(DATA_DIR, "hzkey.pid");

const ROLES = ["owner", "admin", "viewer"];
const PWD_MIN = 8, PWD_MAX = 64;
const RE_USER = /^[A-Za-z0-9_.-]{3,24}$/;

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i > -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--")
    ? process.argv[i + 1] : def;
}
function has(name) { return process.argv.includes(name); }
function die(msg) { console.error("✗ " + msg); process.exit(1); }

// ---------- 与 server.js 保持一致的哈希参数, 否则改完登录不上 ----------
function hash_password(pw, salt) {
  return crypto.scryptSync(String(pw), salt, 64).toString("hex");
}
function new_password(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return { salt, hash: hash_password(pw, salt) };
}
// 强度规则与 server.js 的 pwd_problem() 逐条对齐
function pwd_problem(pw) {
  pw = String(pw || "");
  if (pw.length < PWD_MIN) return "密码至少 " + PWD_MIN + " 位";
  if (pw.length > PWD_MAX) return "密码过长";
  if (!/[A-Za-z]/.test(pw) || !/[0-9]/.test(pw)) return "密码需同时包含字母和数字";
  if (/^\s|\s$/.test(pw)) return "密码首尾不能是空格";
  return "";
}
// 去掉 0/O/1/l/I 等易混淆字符, 随机串要能手抄
function gen_password(len) {
  const n = len || 12;
  const ALL = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  for (let t = 0; t < 50; t++) {
    const s = Array.from({ length: n }, () => ALL[crypto.randomInt(ALL.length)]).join("");
    if (/[A-Za-z]/.test(s) && /[0-9]/.test(s)) return s;
  }
  die("随机密码生成失败, 请改用 --password 指定");
}

// ---------- 载入 ----------
if (!fs.existsSync(ADMINS_FILE)) die("找不到 " + ADMINS_FILE + " (确认 --data-dir / HZ_DATA_DIR)");
let admins;
try { admins = JSON.parse(fs.readFileSync(ADMINS_FILE, "utf8")); }
catch (e) { die("admins.json 解析失败: " + e.message); }
let sessions = {};
try { sessions = JSON.parse(fs.readFileSync(SESSIONS_FILE, "utf8")); } catch (e) {}

const dry = has("--dry-run");
const ownerCount = () => Object.values(admins)
  .filter((a) => a.role === "owner" && !a.disabled).length;

// ---------- 备份 (改动前必做, 且不留空手) ----------
function backup() {
  if (dry) return;
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  for (const f of [ADMINS_FILE, SESSIONS_FILE]) {
    if (!fs.existsSync(f)) continue;
    fs.copyFileSync(f, f + ".pre-reset-" + ts + ".bak");
  }
  console.log("· 已备份: admins.json / sessions.json → *.pre-reset-" + ts + ".bak");
}

function write_out(name, pw) {
  const out = arg("--out");
  if (!out) return;
  fs.writeFileSync(out, "管理员账号: " + name + "\n密码: " + pw + "\n", { mode: 0o600 });
  console.log("· 凭据已写入 " + out + " (0600, 用完即删)");
}

function show_list() {
  const rows = Object.entries(admins);
  console.log("数据目录: " + DATA_DIR);
  console.log("共 " + rows.length + " 个管理账号, 可用 owner " + ownerCount() + " 个:\n");
  for (const [u, a] of rows) {
    console.log("  " + u.padEnd(16) + a.role.padEnd(7) +
      (a.disabled ? "已禁用" : "正常") + "  " +
      (a.must_change ? "待强制改密  " : "") +
      "最近登录 " + (a.last_login ? new Date(a.last_login).toLocaleString("zh-CN") : "从未"));
  }
}

function main() {
  const mode = ["--list", "--reset", "--rename", "--create"].filter(has);
  if (mode.length > 1) die("--list / --reset / --rename / --create 只能选一个");
  if (!mode.length) die("缺少操作, 见文件头用法说明");
  if (mode[0] !== "--list" && !has("--force") && fs.existsSync(PID_FILE)) {
    try {
      process.kill(parseInt(fs.readFileSync(PID_FILE, "utf8").trim(), 10), 0);
      die("服务正在运行 (pidfile " + PID_FILE + ")。运行中的进程会把内存里的旧账号表写回盘, " +
        "覆盖本次改动。请先 hzkey.sh stop, 或直接用 hzkey.sh reset");
    } catch (e) { /* pid 不存在 = 残留 pidfile, 可继续 */ }
  }

  if (mode[0] === "--list") return show_list();

  const user = arg("--user");

  if (mode[0] === "--create") {
    if (!user) die("--create 需要 --user");
    if (!RE_USER.test(user)) die("登录名 3-24 位, 仅字母数字和 _ . -");
    if (admins[user]) die("账号 " + user + " 已存在");
    const role = arg("--role", "owner");
    if (!ROLES.includes(role)) die("--role 只能是 owner / admin / viewer");
    const pw = arg("--password") || gen_password(12);
    const prob = pwd_problem(pw);
    if (prob) die(prob);
    if (role !== "owner" && ownerCount() === 0)
      console.log("! 提示: 当前没有可用 owner, 而你在建 " + role + " 账号");
    const rec = Object.assign(new_password(pw), {
      role, created_at: Date.now(), disabled: false,
      must_change: true, last_login: 0, note: arg("--note", "命令行创建"),
    });
    console.log("· 新建账号 " + user + " 角色=" + role + " 密码=" + pw + " (首次登录强制改密)");
    if (dry) return console.log("!! dry-run, 未写入");
    backup();
    admins[user] = rec;
    fs.writeFileSync(ADMINS_FILE, JSON.stringify(admins, null, 1));
    write_out(user, pw);
    return;
  }

  if (!user) die(mode[0] + " 需要 --user");
  if (!admins[user]) die("账号 " + user + " 不存在; 现有: " + Object.keys(admins).join(", "));

  if (mode[0] === "--rename") {
    const to = arg("--to");
    if (!to) die("--rename 需要 --to");
    if (!RE_USER.test(to)) die("新登录名 3-24 位, 仅字母数字和 _ . -");
    if (admins[to]) die("新登录名 " + to + " 已被占用");
    console.log("· 登录名 " + user + " → " + to);
    let kicked = 0;
    for (const [sid, s] of Object.entries(sessions)) if (s.user === user) { delete sessions[sid]; kicked++; }
    if (kicked) console.log("· 吊销 " + kicked + " 个会话 (改名后需重新登录)");
    if (dry) return console.log("!! dry-run, 未写入");
    backup();
    // 保持原有键顺序, 只换键名
    const rebuilt = {};
    for (const [u, a] of Object.entries(admins)) rebuilt[u === user ? to : u] = a;
    admins = rebuilt;
    fs.writeFileSync(ADMINS_FILE, JSON.stringify(admins, null, 1));
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions, null, 1));
    console.log("· 完成。以后用 " + to + " 登录 (审计日志里的历史条目仍记旧名)");
    return;
  }

  // ---- --reset ----
  const pw = has("--generate") ? gen_password(12) : arg("--password");
  if (!pw) die("--reset 需要 --generate 或 --password <新密码>");
  const prob = pwd_problem(pw);
  if (prob) die(prob);
  if (admins[user].disabled && !has("--enable"))
    console.log("! 注意: 账号 " + user + " 当前是禁用状态, 光改密码仍登不上; 需要一并启用请加 --enable");
  let kicked = 0;
  for (const [sid, s] of Object.entries(sessions)) if (s.user === user) { delete sessions[sid]; kicked++; }
  console.log("· 重置账号 " + user + " (" + admins[user].role + ") 密码=" + pw);
  console.log("· 吊销 " + kicked + " 个在线会话, 该管理员需重新登录");
  if (has("--enable")) console.log("· 一并解除禁用");
  if (has("--force-change")) console.log("· 置为首次登录必须改密");
  if (dry) return console.log("!! dry-run, 未写入");
  backup();
  Object.assign(admins[user], new_password(pw),
    { must_change: has("--force-change"), disabled: has("--enable") ? false : admins[user].disabled });
  fs.writeFileSync(ADMINS_FILE, JSON.stringify(admins, null, 1));
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions, null, 1));
  write_out(user, pw);
  console.log("· 已落盘。启动服务后即可用新密码登录");
}

main();
