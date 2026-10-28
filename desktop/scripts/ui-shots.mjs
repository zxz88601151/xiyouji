// 外观巡检截图：登录门 / 注册 / 忘记密码 / 账号安全 / 主界面，各取 620x760 与 520x640。
// 纯前端渲染，不登录后台：主界面用 localStorage 令牌 + /api/auth/me 桩。
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const CHROME = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const PORT = 9448;
const URL = process.env.E2E_URL || "http://localhost:1421/";
const OUT = resolve(process.env.E2E_OUT || "../../audit");
const TAG = process.env.SHOT_TAG || "ui";
const DATE = "20261028";

mkdirSync(OUT, { recursive: true });
const profile = join(tmpdir(), `ui-cdp-${Date.now()}`);
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

const viewport = async (width, height) => {
  await send("Emulation.setDeviceMetricsOverride", {
    width,
    height,
    deviceScaleFactor: 2,
    mobile: false,
  });
  await sleep(220);
};

const shot = async (name) => {
  const r = await send("Page.captureScreenshot", { format: "png" });
  const file = join(OUT, `${TAG}_${name}_${DATE}.png`);
  writeFileSync(file, Buffer.from(r.result.data, "base64"));
  console.log("SHOT", file);
};

// 溢出检查：任一滚动容器的 scrollWidth 超过 clientWidth 即视为横向溢出
const overflow = `(() => {
  const bad = [];
  for (const el of document.querySelectorAll('.main, .card, .opts, .row, .topbar')) {
    if (el.scrollWidth > el.clientWidth + 1) bad.push(el.className + " " + el.scrollWidth + ">" + el.clientWidth);
  }
  return { body: document.body.scrollWidth, view: innerWidth, bad };
})()`;

const clickText = (text) => `(() => {
  const b = [...document.querySelectorAll('button')].find(x => x.textContent.trim() === ${JSON.stringify(text)});
  if (!b) return 'NO_BTN';
  b.click();
  return 'OK';
})()`;

await send("Page.enable");
await send("Runtime.enable");

const report = [];
const note = (step, value) => {
  report.push({ step, value });
  console.log("STEP", step, "=>", JSON.stringify(value));
};

await viewport(620, 760);
await send("Page.navigate", { url: URL });
await sleep(1500);

note("gate", await evalJs(`document.querySelector('.brand')?.textContent || ''`));
note("overflow_gate", await evalJs(overflow));
await shot("gate");

await evalJs(clickText("注册"));
await sleep(250);
await shot("register");

await evalJs(clickText("登录"));
await sleep(200);
await evalJs(clickText("忘记密码"));
await sleep(250);
await shot("forgot");
await evalJs(clickText("取消"));
await sleep(250);

await viewport(520, 640);
note("overflow_gate_min", await evalJs(overflow));
await shot("gate_min");

await viewport(620, 760);
await send("Page.addScriptToEvaluateOnNewDocument", {
  source: `(() => {
    try {
      const now = Date.now();
      localStorage.setItem("hz.dev.account", JSON.stringify({
        token: "ui-stub", user: "zxzjxx", machine: "WEBBROWSER000000",
        expires_at: Math.floor(now / 1000) + 31536000, saved_at: Math.floor(now / 1000),
      }));
    } catch (e) {}
    const realFetch = window.fetch.bind(window);
    window.fetch = (input, init) => {
      const url = typeof input === "string" ? input : (input && input.url) || "";
      if (url.indexOf("/api/auth/me") >= 0) {
        const now = Date.now();
        return Promise.resolve(new Response(JSON.stringify({
          ok: true, user: "zxzjxx", state: "active", plan_id: "pro",
          plan_name: "专业版(桩)", remaining: 31536000, expires_at: now + 31536000000,
          rebind_left: 3, rc_set: true, machine: "WEBBROWSER000000", machine_ok: true,
        }), { status: 200, headers: { "Content-Type": "application/json" } }));
      }
      return realFetch(input, init);
    };
  })();`,
});
await send("Page.reload");
await sleep(1600);

note("main", await evalJs(`!!document.querySelector('.main')`));
note("overflow_main", await evalJs(overflow));
await shot("main");

await evalJs(clickText("账号安全"));
await sleep(350);
note("security", await evalJs(`!!document.querySelector('.account-head')`));
note("overflow_security", await evalJs(overflow));
await shot("security");
await evalJs(clickText("关闭"));
await sleep(250);

await viewport(520, 640);
note("overflow_main_min", await evalJs(overflow));
await shot("main_min");
await evalJs(clickText("账号安全"));
await sleep(300);
note("overflow_security_min", await evalJs(overflow));
await shot("security_min");
await evalJs(clickText("关闭"));
await sleep(200);

writeFileSync(join(OUT, `${TAG}_shots_${DATE}.json`), JSON.stringify(report, null, 2));
console.log("DONE", report.length, "steps");

ws.close();
chrome.kill();
await sleep(300);
try { rmSync(profile, { recursive: true, force: true }); } catch { /* 句柄未释放时忽略 */ }
process.exit(0);
