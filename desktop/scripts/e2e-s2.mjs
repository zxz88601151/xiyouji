// S2 验收脚本：headless Chrome + CDP 驱动主界面壳（FakeEngine）。
// 账号会话用桩：localStorage 预置令牌 + 仅拦截 /api/auth/me 返回有效会话。
// 这只验证 S2 界面与交互；登录/鉴权链路已由 S1 对真实隔离后台验证过，这里不重复。
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const CHROME = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const PORT = 9446;
const URL = process.env.E2E_URL || "http://localhost:1421/";
const OUT = resolve(process.env.E2E_OUT || "../../audit");
const TAG = process.env.E2E_TAG || "s2";

mkdirSync(OUT, { recursive: true });
const profile = join(tmpdir(), `s2-cdp-${Date.now()}`);
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

await send("Page.addScriptToEvaluateOnNewDocument", {
  source: `(() => {
    try {
      const now = Date.now();
      localStorage.setItem("hz.dev.account", JSON.stringify({
        token: "e2e-stub", user: "s2uitest", machine: "WEBBROWSER000000",
        expires_at: Math.floor(now / 1000) + 3600, saved_at: Math.floor(now / 1000),
      }));
    } catch (e) {}
    const realFetch = window.fetch.bind(window);
    window.fetch = (input, init) => {
      const url = typeof input === "string" ? input : (input && input.url) || "";
      if (url.indexOf("/api/auth/me") >= 0) {
        const now = Date.now();
        return Promise.resolve(new Response(JSON.stringify({
          ok: true, user: "s2uitest", state: "active", plan_id: "trial",
          plan_name: "体验(桩)", remaining: 3600, expires_at: now + 3600000,
          rebind_left: 3, rc_set: true, machine: "WEBBROWSER000000", machine_ok: true,
        }), { status: 200, headers: { "Content-Type": "application/json" } }));
      }
      return realFetch(input, init);
    };
  })();`,
});

await send("Page.navigate", { url: URL });
await sleep(1600);

note("main_mounted", await evalJs(`!!document.querySelector('.main')`));
note("acct", await evalJs(`document.querySelector('.acct')?.textContent || ''`));
note("buttons", await evalJs(`[...document.querySelectorAll('.main button')].map(b=>b.textContent.trim())`));
await shot(TAG + "_main_empty_20261028.png");

const setSelect = (v) => `(() => {
  const el = document.querySelector('.row > select.select');
  if (!el) return 'NO_EL';
  const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set;
  setter.call(el, ${JSON.stringify(String(v))});
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return el.value;
})()`;
const clickText = (text) => `(() => {
  const b = [...document.querySelectorAll('button')].find(x => x.textContent.trim() === ${JSON.stringify(text)});
  if (!b) return 'NO_BTN';
  b.click();
  return 'OK';
})()`;
const status = `document.querySelector('.status')?.textContent || ''`;
const statusKind = `document.querySelector('.status')?.className || ''`;
const rows = `[...document.querySelectorAll('.win-table tbody tr')].map(tr => ({
  hwnd: tr.children[0]?.textContent ?? '',
  title: tr.children[1]?.textContent ?? '',
  role: tr.children[2]?.textContent ?? '',
  deliver: tr.children[3]?.textContent ?? '',
  optin: tr.children[4]?.querySelector('input')?.checked ?? null,
  cls: tr.className,
}))`;

const addSub = async (hwnd) => {
  await evalJs(setSelect(hwnd));
  await sleep(120);
  await evalJs(clickText("添加为次窗口"));
  await sleep(220);
  return await evalJs(status);
};

// 1) 普通窗口加入
note("add_101", await addSub(101));

// 2) 自绘窗口 → 必须显式确认
await evalJs(setSelect(103));
await sleep(120);
await evalJs(clickText("添加为次窗口"));
await sleep(250);
note("optin_title", await evalJs(`document.querySelector('.modal .modal-title')?.textContent || ''`));
await shot(TAG + "_optin_20261028.png");
await evalJs(clickText("确认放行"));
await sleep(250);
note("add_103", await evalJs(status));
note("add_103_optin", await evalJs(`document.querySelector('.win-table tbody tr:nth-child(2) input[type=checkbox]')?.checked ?? null`));

// 3) 含密码控件 → 拒绝
note("add_104", await addSub(104));
note("add_104_kind", await evalJs(statusKind));

// 4) 无法核实且非自绘 → 拒绝
note("add_107", await addSub(107));

// 5) 主窗口
await evalJs(setSelect(102));
await sleep(120);
await evalJs(clickText("设为主窗口"));
await sleep(220);
note("set_main", await evalJs(status));

// 6) 再补两个次窗口
note("add_105", await addSub(105));
note("add_106", await addSub(106));
note("rows_before_start", await evalJs(rows));
await shot(TAG + "_main_configured_20261028.png");

// 7) 开始 → 等过校准窗口期，看状态列分支
await evalJs(`document.querySelector('.btn.start')?.click()`);
await sleep(4650);
note("start_status", await evalJs(status));
note("rows_running", await evalJs(rows));
await shot(TAG + "_main_running_20261028.png");

// 8) 按键规则弹层
await evalJs(`[...document.querySelectorAll('button')].find(b=>b.textContent.includes('按键规则'))?.click()`);
await sleep(300);
note("rules_rows", await evalJs(`document.querySelectorAll('.rule-table tbody tr').length`));
note("rules_first", await evalJs(`(() => {
  const tr = document.querySelector('.rule-table tbody tr');
  if (!tr) return null;
  return {
    on: tr.querySelector('input[type=checkbox]')?.checked,
    keys: [...tr.querySelectorAll('select')].map(s => s.options[s.selectedIndex]?.textContent),
    nums: [...tr.querySelectorAll('input.num')].map(i => i.value),
  };
})()`));
await shot(TAG + "_rules_20261028.png");
await evalJs(`[...document.querySelectorAll('.modal button')].find(b=>b.textContent.trim()==='取消')?.click()`);
await sleep(250);

// 9) 停止
await evalJs(`document.querySelector('.btn.start')?.click()`);
await sleep(300);
note("stop_status", await evalJs(status));
await shot(TAG + "_main_stopped_20261028.png");

// 10) 配置持久化（放行确认不随配置保存，重载后勾选应消失）
await send("Page.reload");
await sleep(1500);
note("rows_after_reload", await evalJs(rows));

writeFileSync(join(OUT, TAG + "_e2e_20261028.json"), JSON.stringify(results, null, 2));
console.log("DONE", results.length, "steps");

ws.close();
chrome.kill();
await sleep(300);
try { rmSync(profile, { recursive: true, force: true }); } catch { /* chrome 句柄未释放时忽略 */ }
process.exit(0);
