// S1 找回密码链路：错安全码 → 正确安全码 → 用新密码登录，全走本机隔离后台。
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const CHROME = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const PORT = 9445;
const URL = process.env.E2E_URL || "http://localhost:1421/";
const OUT = resolve(process.env.E2E_OUT || "../../audit");
const USER = process.env.E2E_USER || "s1uitest";
const OLD_PASS = process.env.E2E_PASS || "Test1234pass";
const NEW_PASS = process.env.E2E_NEW_PASS || "New1234pass";
const CODE = process.env.E2E_CODE || "Recover1234";

mkdirSync(OUT, { recursive: true });
const profile = join(tmpdir(), `s1f-cdp-${Date.now()}`);
const chrome = spawn(CHROME, [
  "--headless=new", `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`,
  "--no-first-run", "--disable-gpu", "--hide-scrollbars", "about:blank",
], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function target() {
  for (let i = 0; i < 50; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      const page = list.find((t) => t.type === "page");
      if (page) return page.webSocketDebuggerUrl;
    } catch { /* 等 chrome */ }
    await sleep(200);
  }
  throw new Error("chrome devtools 未就绪");
}

const ws = new WebSocket(await target());
let seq = 0;
const pending = new Map();
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
};
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
const send = (method, params = {}) => new Promise((res) => {
  const id = ++seq; pending.set(id, res); ws.send(JSON.stringify({ id, method, params }));
});
const evalJs = async (expression) => {
  const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (r.result?.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || "JS 异常");
  return r.result?.result?.value;
};
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

await send("Page.enable");
await send("Runtime.enable");
await send("Emulation.setDeviceMetricsOverride", { width: 620, height: 760, deviceScaleFactor: 2, mobile: false });
await send("Page.navigate", { url: URL });
await sleep(1600);

const results = [];
const note = (step, value) => { results.push({ step, value }); console.log("STEP", step, "=>", JSON.stringify(value)); };

await evalJs(`(() => { const b=[...document.querySelectorAll('button.btn.link')].find(x=>x.textContent.trim()==='忘记密码'); b?.click(); return 'OK'; })()`);
await sleep(300);

// 负例：错误安全码
await evalJs(setVal('input[placeholder="用户名"]', USER));
await evalJs(setVal('input[placeholder^="安全码"]', "Wrong1234"));
await evalJs(setVal('input[placeholder^="新密码"]', NEW_PASS));
await evalJs(setVal('input[placeholder="再输一次新密码"]', NEW_PASS));
await evalJs(clickText("重置密码"));
await sleep(2200);
note("forgot_wrong_code", await evalJs(status));

// 正例：正确安全码
await evalJs(setVal('input[placeholder^="安全码"]', CODE));
await evalJs(clickText("重置密码"));
await sleep(2400);
note("forgot_ok", await evalJs(status));
await shot("s1_forgot_done_20261028.png");

// 回登录页用新密码登录
await evalJs(setVal('input[placeholder="用户名"]', USER));
await evalJs(setVal('input[placeholder="密码"]', NEW_PASS));
await evalJs(`document.querySelector("button.btn.green")?.click() || "OK"`);
await sleep(2500);
note("login_with_new_pass", await evalJs(`document.querySelector('.kv dd')?.textContent || ''`));
note("login_status", await evalJs(status));
await shot("s1_login_newpass_20261028.png");

writeFileSync(join(OUT, "s1_forgot_e2e_20261028.json"), JSON.stringify(results, null, 2));
console.log("DONE", results.length, "steps");
ws.close(); chrome.kill(); await sleep(300);
try { rmSync(profile, { recursive: true, force: true }); } catch { /* ignore */ }
process.exit(0);

async function shot(name) {
  const r = await send("Page.captureScreenshot", { format: "png" });
  const file = join(OUT, name);
  writeFileSync(file, Buffer.from(r.result.data, "base64"));
  console.log("SHOT", file);
}
