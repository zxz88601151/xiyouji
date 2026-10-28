/**
 * 同步引擎接口（S2）：与 multisync.py 的 SyncEngine 公共面一一对应。
 *
 * S2 只接 FakeEngine（假窗口，不投递任何真实按键/鼠标）；
 * S3 换成 Tauri sidecar 时保持本接口不变，界面层零改动。
 */
export const MAX_TARGETS = 16;
export const RULE_MAX_TIMES = 10;
export const RULE_MAX_DELAY_MS = 2000;

export type PwState = "sensitive" | "safe" | "unknown";

/** 拒绝原因码 → 界面文案（与 multisync.py KB_REASON_TEXT 同源，INV-8：拒绝必须可见） */
export const KB_REASON_TEXT = {
  unlearned: "未校准",
  stale: "控件失效",
  sensitive: "敏感控件",
  unknown: "无法确认",
} as const;

export const KB_REASON_ALL: readonly string[] = Object.values(KB_REASON_TEXT);

/** 已显式放行的自绘窗口，状态不得与通过检测的目标显示成同一个词（B 方案） */
export const OPAQUE_OK_TEXT = "正常(自绘窗口,未检测密码框)";

export interface WinInfo {
  hwnd: number;
  title: string;
}

export interface KbRule {
  on: boolean;
  src: number;
  dst: number;
  delay: number;
  times: number;
}

export interface SyncCfg {
  syncMouse: boolean;
  syncKb: boolean;
  sendChar: boolean;
  followF5: boolean;
  /** 1 = PostMessage(异步) / 2 = SendMessage(同步) */
  mode: number;
}

export interface DeliveryState {
  /** "正常" / "正常(自绘窗口…)" / 未校准 / 控件失效 / 失败 等 */
  state: string;
  consec: number;
  /** 供界面直接展示的失败原因（S2 假引擎给人类可读文案） */
  err: string;
}

/** 默认规则与 Python DEFAULT_KB_RULES 同源：1/2/3/4/5 + TAB，全部 1:1 直通 */
export const DEFAULT_KB_RULES: KbRule[] = [
  ...[1, 2, 3, 4, 5].map((n) => ({
    on: true,
    src: 0x30 + n,
    dst: 0x30 + n,
    delay: 0,
    times: 1,
  })),
  { on: true, src: 0x09, dst: 0x09, delay: 0, times: 1 },
];

const VK_NAMES: Record<number, string> = {
  0x09: "TAB",
  0x0d: "Enter",
  0x1b: "Esc",
  0x20: "Space",
  0x08: "Backspace",
  0x14: "CapsLock",
  0x2d: "Insert",
  0x2e: "Delete",
  0x24: "Home",
  0x23: "End",
  0x21: "PgUp",
  0x22: "PgDn",
  0x25: "Left",
  0x26: "Up",
  0x27: "Right",
  0x28: "Down",
  0x10: "Shift",
  0x11: "Ctrl",
  0x12: "Alt",
};

export function vkName(vk: number): string {
  const v = Math.trunc(vk || 0);
  if (v <= 0) return "未设置";
  if ((v >= 0x30 && v <= 0x39) || (v >= 0x41 && v <= 0x5a)) {
    return String.fromCharCode(v);
  }
  if (v >= 0x60 && v <= 0x69) return `Num${v - 0x60}`;
  if (v >= 0x70 && v <= 0x87) return `F${v - 0x6f}`;
  return VK_NAMES[v] ?? `0x${v.toString(16).toUpperCase().padStart(2, "0")}`;
}

/** 规则编辑器里可选的主号/次号键位（S2 用下拉替代 Python 的按键捕获，S3 接钩子后再换回捕获） */
export const VK_CHOICES: number[] = [
  ...Array.from({ length: 10 }, (_, i) => 0x30 + i),
  ...Array.from({ length: 26 }, (_, i) => 0x41 + i),
  0x09, 0x0d, 0x1b, 0x20, 0x08, 0x14, 0x2d, 0x2e,
  0x24, 0x23, 0x21, 0x22, 0x25, 0x26, 0x27, 0x28,
  0x10, 0x11, 0x12,
  ...Array.from({ length: 12 }, (_, i) => 0x70 + i),
  ...Array.from({ length: 10 }, (_, i) => 0x60 + i),
];

export interface SyncEngineApi {
  main: number | null;
  targets: number[];
  rules: KbRule[];
  active: boolean;

  enumWindows(): WinInfo[];
  titleOf(hwnd: number): string;
  /** 三态：sensitive=确定命中密码控件；unknown=无法核实；safe=未发现 */
  pwState(hwnd: number): PwState;
  isOpaque(hwnd: number): boolean;
  allowOpaque(hwnd: number): boolean;
  setAllowOpaque(hwnd: number, on: boolean): void;

  setMain(hwnd: number | null): void;
  addTarget(hwnd: number): void;
  removeTarget(hwnd: number): void;
  forget(hwnd: number): void;
  setRules(rules: KbRule[]): void;

  /** 与 SyncEngine.start() 同语义：返回 [是否启动, 状态文案] */
  start(cfg: SyncCfg): [boolean, string];
  stop(): void;
  states(): Record<number, DeliveryState>;
}
