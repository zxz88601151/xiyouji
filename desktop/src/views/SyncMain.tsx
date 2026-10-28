/**
 * S2 主界面壳：窗口列表 / 角色 / 投递状态 / 同步选项 / 开始停止 / 按键规则。
 * 结构与 multisync.py MainWindow._build_ui 对齐，引擎换成 FakeEngine（S3 接 sidecar）。
 */
import { useEffect, useMemo, useReducer, useState } from "react";
import type { MouseEvent } from "react";
import { AccountClient, fmtSecs, stateText } from "../api/account";
import {
  KB_REASON_ALL,
  MAX_TARGETS,
  type DeliveryState,
  type SyncCfg,
  type SyncEngineApi,
} from "../engine/api";
import { FakeEngine } from "../engine/fakeEngine";
import { KbRules } from "./KbRules";

interface Props {
  client: AccountClient;
  onSecurity: () => void;
  onLogout: () => void;
  onSessionLost: (reason: string) => void;
}

type MsgKind = "" | "warn" | "err";

const READY_TEXT =
  "就绪: 开2个目标窗口 → 刷新 → 设主窗口/次窗口 → 开始 (键盘需把每个次窗口切到前台校准一次)";

export function SyncMain({ client, onSecurity, onLogout, onSessionLost }: Props) {
  const engine = useMemo<SyncEngineApi>(() => new FakeEngine(), []);
  const [, force] = useReducer((n: number) => n + 1, 0);

  const [wins, setWins] = useState(() => engine.enumWindows());
  const [comboHwnd, setComboHwnd] = useState<number | null>(
    () => engine.enumWindows()[0]?.hwnd ?? null
  );
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [cfg, setCfg] = useState<SyncCfg>({
    syncMouse: true,
    syncKb: true,
    sendChar: false,
    followF5: false,
    mode: 1,
  });
  const [msg, setMsg] = useState<{ text: string; kind: MsgKind }>({
    text: READY_TEXT,
    kind: "",
  });
  const [running, setRunning] = useState(false);
  const [deliveries, setDeliveries] = useState<Record<number, DeliveryState>>({});
  const [rulesOpen, setRulesOpen] = useState(false);
  const [optin, setOptin] = useState<number | null>(null);
  const [now, setNow] = useState(Date.now());

  function say(text: string, kind: MsgKind = "") {
    setMsg({ text, kind });
  }

  // 1s 刷新投递状态（只读引擎快照，不做网络/阻塞操作）
  useEffect(() => {
    const t = window.setInterval(() => {
      setNow(Date.now());
      setDeliveries(engine.states());
    }, 1000);
    return () => window.clearInterval(t);
  }, [engine]);

  // 关窗即停：心跳失效 / 紧急停止等路径不经过界面，引擎必须能自己收敛
  useEffect(() => () => engine.stop(), [engine]);

  // 60s 心跳：剩余时间以服务端为准；令牌被清掉说明会话真的失效 → 回登录门
  useEffect(() => {
    let alive = true;
    const hb = window.setInterval(async () => {
      const [ok, txt] = await client.me();
      if (!alive) return;
      if (!ok && !client.token) onSessionLost(txt);
      else if (!ok) say(txt, "err");
      else setNow(Date.now());
    }, 60000);
    return () => {
      alive = false;
      window.clearInterval(hb);
    };
  }, [client, onSessionLost]);

  const liveRemaining = () =>
    client.expiresAt > 0
      ? Math.max(0, Math.floor(client.expiresAt - now / 1000))
      : client.remaining;
  const remain = liveRemaining();

  const rows: { hwnd: number; role: string; isMain: boolean }[] = [];
  if (engine.main) rows.push({ hwnd: engine.main, role: "★ 主窗口", isMain: true });
  for (const h of engine.targets) {
    if (h !== engine.main) rows.push({ hwnd: h, role: "次窗口", isMain: false });
  }

  function refreshWindows() {
    const list = engine.enumWindows();
    setWins(list);
    if (!list.some((w) => w.hwnd === comboHwnd)) setComboHwnd(list[0]?.hwnd ?? null);
    say(`已刷新, 共 ${list.length} 个窗口`);
  }

  function toggleRow(hwnd: number, e: MouseEvent) {
    setSelected((s) => {
      const n = new Set(s);
      if (e.ctrlKey || e.metaKey || e.shiftKey) {
        if (n.has(hwnd)) n.delete(hwnd);
        else n.add(hwnd);
      } else if (n.size === 1 && n.has(hwnd)) {
        n.clear();
      } else {
        n.clear();
        n.add(hwnd);
      }
      return n;
    });
  }

  function doSetMain() {
    const h = comboHwnd;
    if (!h) return;
    if (!engine.titleOf(h)) {
      say("该窗口已关闭, 请刷新后重新选择", "warn");
      return;
    }
    engine.setMain(h);
    void client.audit("SET_MAIN", `hwnd=${h}`);
    say(`主窗口: ${engine.titleOf(h).slice(0, 30)}`);
    force();
  }

  function addSubNow(h: number, allow: boolean) {
    engine.addTarget(h);
    if (allow) engine.setAllowOpaque(h, true);
    void client.audit("ADD_SUB", `hwnd=${h}`);
    say(`次窗口 +1, 共 ${engine.targets.length} 个`);
    force();
  }

  function doAddSub() {
    const h = comboHwnd;
    if (!h) return;
    if (!engine.titleOf(h)) {
      say("该窗口已关闭, 请刷新后重新选择", "warn");
      return;
    }
    if (h === engine.main) {
      say("该窗口已是主窗口", "warn");
      return;
    }
    if (engine.targets.includes(h)) {
      say("该窗口已在次窗口列表中", "warn");
      return;
    }
    if (engine.targets.length >= MAX_TARGETS) {
      say(`次窗口数量已达上限 (${MAX_TARGETS} 个)`, "warn");
      return;
    }
    // 三态判定：确定命中 → 拒绝；自绘宿主无法核实 → 用户显式确认后放行；其它 → 拒绝
    const st = engine.pwState(h);
    if (st === "sensitive") {
      void client.audit("ADD_SUB_DENY", `hwnd=${h} 含密码输入控件`);
      say(
        "已拒绝: 该窗口内含密码/口令输入框 —— 为避免同步的按键内容落进密码框, 不允许把它设为次窗口",
        "err"
      );
      return;
    }
    if (st === "unknown") {
      if (!engine.isOpaque(h)) {
        void client.audit("ADD_SUB_DENY", `hwnd=${h} 无法确认(非自绘宿主)`);
        say("已拒绝: 无法确认该窗口是否含密码控件, 请稍后重试或换用其他窗口", "err");
        return;
      }
      setOptin(h);
      return;
    }
    addSubNow(h, false);
  }

  function confirmOptin() {
    const h = optin;
    if (h === null) return;
    setOptin(null);
    addSubNow(h, true);
    say(
      `次窗口 +1, 共 ${engine.targets.length} 个 · 已勾选"自绘窗口放行" (按你的确认视为无密码框, 未做检测)`,
      "warn"
    );
  }

  function cancelOptin() {
    const h = optin;
    setOptin(null);
    if (h !== null) void client.audit("ADD_SUB_DENY", `hwnd=${h} 用户取消自绘窗口放行`);
    say("已取消: 未确认该窗口无密码输入", "warn");
  }

  function removeSelected() {
    if (!selected.size) return;
    for (const h of selected) {
      if (h === engine.main) engine.setMain(null);
      engine.removeTarget(h);
      engine.forget(h); // INV-6: 手动移除也要回收键盘校准状态
      void client.audit("REMOVE", `hwnd=${h}`);
    }
    setSelected(new Set());
    say("已移除选中项");
    setDeliveries(engine.states());
    force();
  }

  function toggleAllow(hwnd: number, on: boolean) {
    engine.setAllowOpaque(hwnd, on);
    if (on) say(`目标 ${hwnd} 已放行: 按你的确认视为无密码框 (未做检测)`, "warn");
    else say(`目标 ${hwnd} 已收回放行; 该目标的键盘同步将按'无法确认'拒绝`, "warn");
    setDeliveries(engine.states());
    force();
  }

  function toggleStart() {
    if (running) {
      engine.stop();
      setRunning(false);
      setDeliveries(engine.states());
      say("已停止");
      return;
    }
    // 授权闸口：剩余时长 0（未开通/已到期）不许启动；权威判定仍在服务端
    if (remain <= 0) {
      void client.audit("DENY_EXPIRED", "剩余时长 0, 拒绝启动");
      say(
        "套餐未开通或已到期, 请先购买套餐或兑换卡密 —— 「套餐 / 充值」入口在 S3 接入",
        "err"
      );
      return;
    }
    const [ok, text] = engine.start(cfg);
    if (!ok) {
      say(text, "err");
      return;
    }
    setRunning(true);
    setDeliveries(engine.states());
    force();
    const active = engine.rules.filter((r) => r.on);
    if (!cfg.syncKb && active.length) {
      void client.audit("KB_RULE_IDLE", `规则 ${active.length} 条因未勾选键盘同步而未生效`);
      say(
        `${text}\n提示: 按键规则共 ${active.length} 条, 但未勾选「键盘同步」 → 不会生效`,
        "warn"
      );
    } else {
      say(text);
    }
  }

  function stateCell(hwnd: number, isMain: boolean): { text: string; cls: string } {
    if (isMain) return { text: "—", cls: "" };
    const d = deliveries[hwnd];
    if (!d || d.state === "—") return { text: "—", cls: "" };
    if (d.state.startsWith("正常")) return { text: d.state, cls: "st-ok" };
    if (KB_REASON_ALL.includes(d.state)) {
      return { text: `键盘未转发:${d.state}`, cls: "st-warn" };
    }
    return { text: `失败×${d.consec} ${d.err}`, cls: "st-fail" };
  }

  const activeRules = engine.rules.filter((r) => r.on).length;

  return (
    <div className="main">
      <div className="topbar">
        <div className="acct" title={client.planName ? `套餐: ${client.planName}` : ""}>
          账号 {client.user} ·{" "}
          {remain > 0
            ? `剩余 ${fmtSecs(remain)}`
            : client.state === "banned"
              ? `已封禁 (${stateText(client.state)})`
              : "已到期, 请续费"}
        </div>
        <button className="btn ghost" onClick={onSecurity}>
          账号安全
        </button>
        <button className="btn ghost" onClick={onLogout}>
          退出登录
        </button>
      </div>

      <div className="row">
        <select
          className="select grow"
          value={comboHwnd ?? ""}
          onChange={(e) => setComboHwnd(Number(e.target.value))}
        >
          {wins.map((w) => (
            <option key={w.hwnd} value={w.hwnd}>
              {w.hwnd} ─ {w.title.slice(0, 40)}
            </option>
          ))}
        </select>
        <button className="btn" onClick={refreshWindows}>
          刷新
        </button>
        <button className="btn" onClick={doSetMain}>
          设为主窗口
        </button>
        <button className="btn" onClick={doAddSub}>
          添加为次窗口
        </button>
      </div>

      <div className="table-wrap">
        <table className="win-table">
          <colgroup>
            <col className="c-hwnd" />
            <col />
            <col className="c-role" />
            <col className="c-st" />
            <col className="c-allow" />
          </colgroup>
          <thead>
            <tr>
              <th>句柄</th>
              <th>标题</th>
              <th>角色</th>
              <th title="仅代表投递 API 是否接受该消息, 不代表目标内部已接收或已处理">
                投递(API层)
              </th>
              <th title="仅自绘窗口(浏览器/Electron/UWP)可勾选">自绘窗口放行</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={5} className="empty">
                  尚未选择窗口 · 从上方下拉里选一个 → 设为主窗口 / 添加为次窗口
                </td>
              </tr>
            )}
            {rows.map(({ hwnd, role, isMain }) => {
              const st = stateCell(hwnd, isMain);
              return (
                <tr
                  key={hwnd}
                  className={selected.has(hwnd) ? "sel" : ""}
                  onClick={(e) => toggleRow(hwnd, e)}
                >
                  <td>{hwnd}</td>
                  <td title={engine.titleOf(hwnd)}>
                    {engine.titleOf(hwnd) || "(无标题)"}
                  </td>
                  <td className={isMain ? "role-main" : ""}>
                    <span className={"badge" + (isMain ? " badge-main" : "")}>{role}</span>
                  </td>
                  <td className={st.cls} title={st.text}>
                    {st.text}
                  </td>
                  <td style={{ textAlign: "center" }} onClick={(e) => e.stopPropagation()}>
                    {engine.isOpaque(hwnd) ? (
                      <input
                        type="checkbox"
                        checked={engine.allowOpaque(hwnd)}
                        onChange={(e) => toggleAllow(hwnd, e.target.checked)}
                      />
                    ) : (
                      <span className="muted" title="该窗口不涉及自绘输入宿主, 此项不适用">
                        —
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <button className="btn block" onClick={removeSelected}>
        移除选中项
      </button>

      <div className="opts">
        <label>
          <input
            type="checkbox"
            checked={cfg.syncMouse}
            onChange={(e) => setCfg({ ...cfg, syncMouse: e.target.checked })}
          />{" "}
          鼠标同步
        </label>
        <label title="只有主窗口在前台时, 键盘输入才会被转发; 每个次窗口需先切到前台校准一次">
          <input
            type="checkbox"
            checked={cfg.syncKb}
            onChange={(e) => setCfg({ ...cfg, syncKb: e.target.checked })}
          />{" "}
          键盘同步
        </label>
        <label title="游戏完全收不到打字内容时再勾选, 普通程序勾了会重复输入">
          <input
            type="checkbox"
            checked={cfg.sendChar}
            onChange={(e) => setCfg({ ...cfg, sendChar: e.target.checked })}
          />{" "}
          补发字符(双字时开)
        </label>
        <label title="开始后每 1 秒向所有次窗口各补发一次 F5; 仍受与键盘同步相同的安全闸口">
          <input
            type="checkbox"
            checked={cfg.followF5}
            onChange={(e) => setCfg({ ...cfg, followF5: e.target.checked })}
          />{" "}
          次窗口持续F5
        </label>
        <span className="mode-group">
          <span className="muted">转发模式:</span>
          <select
            className="select mode"
            value={cfg.mode}
            onChange={(e) => setCfg({ ...cfg, mode: Number(e.target.value) })}
          >
            <option value={1}>模式1 - PostMessage (异步)</option>
            <option value={2}>模式2 - SendMessage (同步)</option>
          </select>
        </span>
      </div>

      <div className="row">
        <button
          className={"btn start " + (running ? "running" : "green")}
          onClick={toggleStart}
        >
          {running ? "停止" : "开始"} (紧急停止快捷键: Ctrl+Alt+Q)
        </button>
        <button className="btn rules" onClick={() => setRulesOpen(true)}>
          按键规则 ({activeRules})…
        </button>
      </div>

      <div className={"status " + msg.kind}>{msg.text}</div>
      <div className="fake-note">
        S2 壳内为假引擎: 窗口列表 / 状态列均为模拟, 不会真的转发按键或鼠标; 真引擎在 S3 接入。
      </div>

      {rulesOpen && (
        <KbRules
          rules={engine.rules}
          onClose={() => setRulesOpen(false)}
          onApply={(rs) => {
            engine.setRules(rs);
            setRulesOpen(false);
            const n = rs.filter((r) => r.on).length;
            void client.audit("KB_RULES", `规则 ${rs.length} 条, 生效 ${n} 条`);
            say(`按键规则已更新: ${n} 条生效 (表内键由规则接管, 表外键仍全量转发)`);
            force();
          }}
        />
      )}

      {optin !== null && (
        <div className="overlay">
          <div className="modal narrow">
            <div className="modal-title">该窗口无法检测密码框</div>
            <div className="tip" style={{ marginTop: 0 }}>
              该窗口使用自绘界面(浏览器 / Electron / UWP 等), 工具无法检测其中是否有密码输入框。
              {"\n\n"}
              仅当你确认【这个窗口里没有密码 / 口令输入】时才可继续。
              {"\n"}
              加入后该窗口会出现在列表里, 并勾选“自绘窗口放行”。
              {"\n"}
              每次投递前仍会复检; 一旦发现真正的密码框会立即收回放行。
              {"\n\n"}
              是否继续?
            </div>
            <div className="row end" style={{ marginTop: 10 }}>
              <button className="btn" onClick={cancelOptin}>
                取消
              </button>
              <button className="btn green" onClick={confirmOptin}>
                确认放行
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
