// S1 验收脚本：headless Chrome + CDP 驱动 vite 预览页，真实渲染截图 + 走通账号链路。
// 只打本机隔离后台（vite 代理 → 127.0.0.1:3012），不碰生产 .123。
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const CHROME = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const PORT = 9444;
const URL = process.env.E2E_URL || "http://localhost:1421/";
const OUT = resolve(process.env.E2E_OUT || "../../audit");
const USER = "s1uitest";
const PASS = "Test1234pass";
const CODE = "Recover1234";

mkdirSync(OUT, { recursive: true });
const profile = join(tmpdir(), `s1-cdp-${Date.now()}`);
const chrome = spawn(CHROME, [
  "--headless=new",
  `--remote-debugging-port=${PORT}`,
  `--user-data-dir=${profile}`,
  "--no-first-run",
  "--disable-gpu",
  "--hide-scrollbars",
  "about:blank",
], { stdio: "ignore" });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function target() {
  for (let i = 0; i < 50; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      const page = list.find((t) => t.type === "page");
      if (page) return page.webSocketDebuggerUrl;
    } catch { /* not up yet */ }
    await sleep(200);
  }
  throw new Error("chrome devtools 未就绪");
}

const ws = new WebSocket(await target());
let seq = 0;
const pending = new Map();
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) {
    pending.get(m.id)(m);
    pending.delete(m.id);
  }
};
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
const send = (method, params = {}) =>
  new Promise((res) => {
    const id = ++seq;
    pending.set(id, res);
    ws.send(JSON.stringify({ id, method, params }));
  });

const evalJs = async (expression) => {
  const r = await send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (r.result?.exceptionDetails) {
    throw new Error(r.result.exceptionDetails.exception?.description || "JS 异常");
  }
  return r.result?.result?.value;
};

const shot = async (name) => {
  const r = await send("Page.captureScreenshot", { format: "png" });
  const file = join(OUT, name);
  writeFileSync(file, Buffer.from(r.result.data, "base64"));
  console.log("SHOT", file);
};

const results = [];
const note = (step, value) => {
  results.push({ step, value });
  console.log("STEP", step, "=>", JSON.stringify(value));
};

await send("Page.enable");
await send("Runtime.enable");
await send("Emulation.setDeviceMetricsOverride", {
  width: 620,
  height: 760,
  deviceScaleFactor: 2,
  mobile: false,
});
await send("Page.navigate", { url: URL });
await sleep(1800);

note("boot", await evalJs(`document.querySelector('.brand')?.textContent || ''`));
note("tabs", await evalJs(`[...document.querySelectorAll('.tab')].map(t=>t.textContent.trim())`));
await shot("s1_login_gate_20261028.png");

const setVal = (sel, v) => `(() => {
  const el = document.querySelector(${JSON.stringify(sel)});
  if (!el) return 'NO_EL';
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  setter.call(el, ${JSON.stringify(v)});
  el.dispatchEvent(new Event('input', { bubbles: true }));
  return el.value;
})()`;
const clickText = (text) => `(() => {
  const b = [...document.querySelectorAll('button')].find(x => x.textContent.trim() === ${JSON.stringify(text)});
  if (!b) return 'NO_BTN';
  b.click();
  return 'OK';
})()`;
const status = `document.querySelector('.status')?.textContent || ''`;

// 注册页
await evalJs(clickText("注册"));
await sleep(250);
await shot("s1_register_tab_20261028.png");
const inputs = await evalJs(`[...document.querySelectorAll('input')].map(i=>i.placeholder)`);
note("register_fields", inputs);

let regOk = false;
for (const [sel, val] of [
  ['input[placeholder^="用户名"]', USER],
  ['input[placeholder^="密码"]', PASS],
  ['input[placeholder="再输一次密码"]', PASS],
  ['input[placeholder^="安全码"]', CODE],
  ['input[placeholder="再输一次安全码"]', CODE],
]) {
  const r = await evalJs(setVal(sel, val));
  if (r === "NO_EL") note("missing_field", sel);
}

await evalJs(clickText("注册并登录"));
await sleep(2600);
const regMsg = await evalJs(status);
note("register_msg", regMsg);
if (/成功|已登录|注册/.test(regMsg) && !/失败|错误|已存在/.test(regMsg)) regOk = true;

if (!regOk) {
  // 账号已存在时改为登录，保证脚本可重复运行
  await evalJs(`(() => { const t=[...document.querySelectorAll('.tab')].find(x=>x.textContent.trim()==='登录'); t?.click(); return 'OK'; })()`);
  await sleep(200);
  await evalJs(setVal('input[placeholder="用户名"]', USER));
  await evalJs(setVal('input[placeholder="密码"]', PASS));
  await evalJs(`document.querySelector("button.btn.green")?.click() || "OK"`);
  await sleep(2600);
  note("login_msg", await evalJs(status));
} else {
  note("login_msg", "(注册即登录)");
}

const homeUser = await evalJs(`document.querySelector('.account-user')?.textContent || ''`);
note("home_user", homeUser);
await shot("s1_home_20261028.png");

// 找回密码视图（不提交，只验渲染与返回）
await evalJs(clickText("账号安全"));
await sleep(300);
note("security_title", await evalJs(`document.querySelector('.account-user')?.textContent || ''`));
note("security_groups", await evalJs(`[...document.querySelectorAll('.group-title')].map(x=>x.textContent)`));
await shot("s1_security_20261028.png");
await evalJs(clickText("关闭"));
await sleep(250);

await evalJs(clickText("退出登录"));
await sleep(900);
await evalJs(`(() => { const b=[...document.querySelectorAll('button.btn.link')].find(x=>x.textContent.trim()==='忘记密码'); b?.click(); return 'OK'; })()`);
await sleep(350);
note("forgot_tip", await evalJs(`document.querySelector('.tip')?.textContent || ''`));
await shot("s1_forgot_20261028.png");

writeFileSync(join(OUT, "s1_e2e_20261028.json"), JSON.stringify(results, null, 2));
console.log("DONE", results.length, "steps");

ws.close();
chrome.kill();
await sleep(300);
try { rmSync(profile, { recursive: true, force: true }); } catch { /* chrome 句柄未释放时忽略 */ }
process.exit(0);
