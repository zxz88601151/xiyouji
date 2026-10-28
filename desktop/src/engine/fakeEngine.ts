/**
 * S2 假引擎：把窗口列表 / 角色 / 敏感与自绘判定 / 投递状态全部模拟出来，
 * 但【不投递任何真实按键或鼠标】，也不安装任何钩子。
 *
 * 用途：先把主界面壳与交互流程跑通（S2），S3 再用 Tauri sidecar 调真引擎。
 * 与真引擎保持同语义的关键点：
 *  - 敏感窗口（pwState=sensitive）拒绝加入次窗口，且不提供放行开关；
 *  - 自绘窗口（isOpaque）加入前需用户显式确认，加入后勾选"自绘窗口放行"，
 *    状态显示为"正常(自绘窗口,未检测密码框)"；
 *  - 无法核实且非自绘（unknown 且 !opaque）一律拒绝；
 *  - 未启动时没有任何投递可观测 → 状态列显示 "—"，不谎报"正常"。
 */
import {
  DEFAULT_KB_RULES,
  KB_REASON_TEXT,
  MAX_TARGETS,
  OPAQUE_OK_TEXT,
  RULE_MAX_DELAY_MS,
  RULE_MAX_TIMES,
  type DeliveryState,
  type KbRule,
  type PwState,
  type SyncCfg,
  type SyncEngineApi,
  type WinInfo,
} from "./api";

const CONFIG_KEY = "s2.fake.config";
const CALIBRATE_MS = 2000;
const FAIL_ALERT = 20;

interface Stored {
  main: number | null;
  targets: number[];
  rules: KbRule[];
}

export class FakeEngine implements SyncEngineApi {
  main: number | null = null;
  targets: number[] = [];
  rules: KbRule[] = DEFAULT_KB_RULES.map((r) => ({ ...r }));
  active = false;

  private wins: WinInfo[] = [
    { hwnd: 101, title: "记事本 - 未命名" },
    { hwnd: 102, title: "微信" },
    { hwnd: 103, title: "Google Chrome - 工作台" },
    { hwnd: 104, title: "网上银行 - 登录" },
    { hwnd: 105, title: "计算器" },
    { hwnd: 106, title: "Trae - 复刻版" },
    { hwnd: 107, title: "受保护窗口 (无法枚举控件)" },
  ];
  private pw: Record<number, PwState> = {
    // 自绘宿主(浏览器/Electron/UWP)的密码框无法核实 → unknown + opaque，走用户显式确认
    103: "unknown",
    104: "sensitive",
    107: "unknown",
  };
  private opaque = new Set<number>([103]);
  private allow = new Set<number>();

  private cfg: SyncCfg | null = null;
  private startedAt = 0;

  constructor() {
    this.load();
  }

  enumWindows(): WinInfo[] {
    return this.wins.map((w) => ({ ...w }));
  }

  titleOf(hwnd: number): string {
    return this.wins.find((w) => w.hwnd === hwnd)?.title ?? "";
  }

  pwState(hwnd: number): PwState {
    return this.pw[hwnd] ?? "safe";
  }

  isOpaque(hwnd: number): boolean {
    return this.opaque.has(hwnd);
  }

  allowOpaque(hwnd: number): boolean {
    return this.allow.has(hwnd);
  }

  setAllowOpaque(hwnd: number, on: boolean): void {
    if (on) this.allow.add(hwnd);
    else this.allow.delete(hwnd);
  }

  setMain(hwnd: number | null): void {
    this.main = hwnd;
    if (hwnd !== null) this.targets = this.targets.filter((h) => h !== hwnd);
    this.persist();
  }

  addTarget(hwnd: number): void {
    if (this.targets.includes(hwnd) || this.targets.length >= MAX_TARGETS) return;
    this.targets.push(hwnd);
    this.persist();
  }

  removeTarget(hwnd: number): void {
    this.targets = this.targets.filter((h) => h !== hwnd);
    this.allow.delete(hwnd);
    this.persist();
  }

  forget(hwnd: number): void {
    // INV-6：回收该目标的一切运行期状态（假引擎没有持久状态，仅收回放行）
    this.allow.delete(hwnd);
  }

  setRules(rules: KbRule[]): void {
    this.rules = rules.map((r) => ({ ...r }));
    this.persist();
  }

  start(cfg: SyncCfg): [boolean, string] {
    if (this.active) return [true, "已在同步中"];
    if (!this.main || !this.titleOf(this.main)) return [false, "请先选择主窗口"];
    this.targets = this.targets
      .filter((h) => h !== this.main && !!this.titleOf(h))
      .slice(0, MAX_TARGETS);
    if (!this.targets.length) return [false, "请先添加至少一个次窗口"];

    this.cfg = cfg;
    this.active = true;
    this.startedAt = Date.now();

    const title = this.titleOf(this.main).slice(0, 20);
    let msg =
      `同步中: 主窗口 ${title} → ${this.targets.length} 个次窗口 (模式${cfg.mode})` +
      (cfg.syncKb ? " · 键盘仅在主窗口前台时转发" : "");
    if (cfg.syncKb) {
      const unlearned = this.targets.filter(
        (t) => !this.allow.has(t) && this.pwState(t) !== "sensitive"
      );
      if (unlearned.length) {
        msg += `\n键盘提示: ${unlearned.length} 个未校准 → 请把每个窗口切到前台一次(点一下输入区)`;
      }
    }
    return [true, msg];
  }

  stop(): void {
    this.active = false;
    this.cfg = null;
    this.startedAt = 0;
  }

  states(): Record<number, DeliveryState> {
    const out: Record<number, DeliveryState> = {};
    const idle: DeliveryState = { state: "—", consec: 0, err: "" };
    const el = this.active ? Date.now() - this.startedAt : 0;

    for (const t of this.targets) {
      if (!this.active) {
        out[t] = { ...idle };
        continue;
      }
      if (this.allow.has(t)) {
        out[t] = { state: OPAQUE_OK_TEXT, consec: 0, err: "" };
        continue;
      }
      if (el < CALIBRATE_MS) {
        out[t] = { state: KB_REASON_TEXT.unlearned, consec: 0, err: "" };
        continue;
      }
      if (t === 106) {
        // 模拟控件重建导致校准失效：键盘被拒（INV-8 必须可见）
        out[t] = { state: KB_REASON_TEXT.stale, consec: 0, err: "" };
        continue;
      }
      if (t === 105) {
        // 模拟鼠标投递失败：连续失败达到阈值才显示"失败"，与真引擎一致
        const consec = Math.min(
          FAIL_ALERT,
          Math.floor((el - CALIBRATE_MS) / 100) + 1
        );
        out[t] =
          consec >= FAIL_ALERT
            ? {
                state: "失败",
                consec,
                err: "权限不足/UIPI: 目标可能是管理员权限运行",
              }
            : { state: "正常", consec: 0, err: "" };
        continue;
      }
      out[t] = { state: "正常", consec: 0, err: "" };
    }
    return out;
  }

  /** 供界面显示"当前配置的模式"（仅展示，不参与投递） */
  currentMode(): number {
    return this.cfg?.mode ?? 0;
  }

  private load(): void {
    try {
      const raw = localStorage.getItem(CONFIG_KEY);
      if (!raw) return;
      const d = JSON.parse(raw) as Partial<Stored>;
      const hwnds = new Set(this.wins.map((w) => w.hwnd));
      if (typeof d.main === "number" && hwnds.has(d.main)) this.main = d.main;
      if (Array.isArray(d.targets)) {
        this.targets = d.targets
          .filter((h): h is number => typeof h === "number" && hwnds.has(h))
          .filter((h) => h !== this.main)
          .slice(0, MAX_TARGETS);
      }
      if (Array.isArray(d.rules) && d.rules.length) {
        this.rules = d.rules
          .slice(0, 32)
          .filter(
            (r): r is KbRule =>
              !!r &&
              typeof r.src === "number" &&
              typeof r.dst === "number" &&
              r.src > 0 &&
              r.src < 256 &&
              r.dst > 0 &&
              r.dst < 256
          )
          .map((r) => ({
            on: r.on !== false,
            src: r.src,
            dst: r.dst,
            delay: Math.max(0, Math.min(RULE_MAX_DELAY_MS, r.delay || 0)),
            times: Math.max(1, Math.min(RULE_MAX_TIMES, r.times || 1)),
          }));
      }
    } catch {
      /* 配置损坏直接忽略，按默认值重建 */
    }
  }

  private persist(): void {
    try {
      const d: Stored = {
        main: this.main,
        targets: this.targets.slice(0, MAX_TARGETS),
        rules: this.rules,
      };
      localStorage.setItem(CONFIG_KEY, JSON.stringify(d));
    } catch {
      /* 落盘失败不影响本次使用 */
    }
  }
}
