# -*- coding: utf-8 -*-
"""
阿信电脑同步器 (Windows 多窗口键鼠同步)
原理: 全局低级钩子捕获主窗口内的鼠标/键盘操作,
      按比例换算坐标后用 PostMessage/SendMessage 转发给后台窗口。
仅供个人学习/自有程序/允许多开的场景使用。
"""
import sys
import ctypes
from ctypes import wintypes

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    pass

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QComboBox, QPushButton, QLabel, QCheckBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox, QAbstractItemView,
    QSpinBox, QTabWidget
)
from PySide6.QtCore import Qt, QTimer, Signal, QEvent
import threading as _threading
from PySide6.QtWidgets import QDialog, QLineEdit, QGroupBox
import win32con
import win32api
import win32gui
import win32process
from license_client import AccountClient, HEARTBEAT_MS, _fmt_secs

user32 = ctypes.WinDLL("user32", use_last_error=True)

import time as _time
import os as _os
import json as _json

# ---- 运行环境与审计 ----
APP_DIR = (_os.path.dirname(sys.executable) if getattr(sys, "frozen", False)
           else _os.path.dirname(_os.path.abspath(__file__)))
MAX_TARGETS = 16  # 次窗口数量上限 (防无限制放大队列阻塞)

# ---- 阶段25: 录制与回放 ----
# 录制: 自装低级钩子只记录不转发; 回放: 定时器驱动把事件重放给全部次窗口。
# 互斥铁律 (业主决策 2026-10-28): 录制 / 回放 / 实时同步三者两两互斥, 由 UI 层强制。
REC_MOVE_MIN_MS = 15   # 鼠标移动采样节流(ms): 控制脚本体积, 时序误差 ≤15ms
SCRIPTS_DIR = _os.path.join(APP_DIR, "scripts")
SCRIPT_MAX_EVENTS = 100000  # 脚本文件事件数上限, 超过视为损坏拒绝加载


class AuditLog:
    """操作审计日志: 只记元事件。
    红线: 绝不记录按键内容/窗口完整标题; 1MB 滚动; 过滤控制字符防日志伪造。"""

    def __init__(self, path):
        self.path = path

    def _sanitize(self, s):
        return "".join(ch for ch in str(s) if ord(ch) >= 32)[:60]

    def write(self, event, detail=""):
        try:
            if _os.path.exists(self.path) and _os.path.getsize(self.path) > 1024 * 1024:
                _os.replace(self.path, self.path + ".old")
            line = "%s [%s] %s\n" % (
                _time.strftime("%Y-%m-%d %H:%M:%S"), event, self._sanitize(detail))
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass


AUDIT = AuditLog(_os.path.join(APP_DIR, "audit.log"))

LRESULT = ctypes.c_ssize_t
HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)

# [N-4] 低级钩子回调用 CallNextHookEx 把事件交还给系统, 交还失败 = 吞掉用户输入。
# user32 是裸 WinDLL (未声明 argtypes), 默认按 C int 转换实参; 而回调的 lParam
# 是 64 位 LPARAM (实测值 243942746664), 超过 int32 范围 → 抛 OverflowError。
# 该异常从 Python 回调穿出 pywin32 thunk, 回调等价于"返回 0", 而低级钩子返回 0
# 的语义正是"丢弃这次事件" → 点击"开始同步"后整机鼠标/键盘失去响应 (阶段20 实测)。
# 这里显式声明签名 (仅这一个函数, 不影响 user32 其余约 30 处调用):
#   LRESULT CallNextHookEx(HHOOK, int, WPARAM, LPARAM)
# 第 4 参声明为 c_void_p 而不是 c_ssize_t: 两者 ABI 相同(指针宽度), 但 c_void_p
# 同时接受"整数"、"c_void_p 实例"和"byref 对象"三种形态。真实回调传整数;
# 而内部测试夹具习惯直接调 _on_kb/_on_mouse 并传 ctypes 指针对象, 用 c_ssize_t
# 会让那些调用抛 ArgumentError (实测 3 处夹具受影响), 属于不必要的接口收紧。
# restype 仍为 c_ssize_t, 保证返回值是整数而不是 None。
user32.CallNextHookEx.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                  ctypes.c_size_t, ctypes.c_void_p]
user32.CallNextHookEx.restype = ctypes.c_ssize_t

WH_MOUSE_LL = 14
WH_KEYBOARD_LL = 13
LLMHF_INJECTED = 0x1
LLKHF_INJECTED = 0x10
SMTO_ABORTIFHUNG = 0x0002

WM_MOUSEMOVE = 0x0200
WM_LBUTTONDOWN = 0x0201
WM_LBUTTONUP = 0x0202
WM_RBUTTONDOWN = 0x0204
WM_RBUTTONUP = 0x0205
WM_MBUTTONDOWN = 0x0207
WM_MBUTTONUP = 0x0208
WM_MOUSEWHEEL = 0x020A
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_SYSKEYDOWN = 0x0104
WM_SYSKEYUP = 0x0105
WM_CHAR = 0x0102

MOUSE_MSGS = {
    WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_LBUTTONUP,
    WM_RBUTTONDOWN, WM_RBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP, WM_MOUSEWHEEL,
}
KEY_MSGS = {WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP}

# ---- 投递结果分类 (F-01 可观测性 / F-07 权限受限识别) ----
ERROR_ACCESS_DENIED = 5            # UIPI: 目标进程完整性级别更高, 消息被系统静默丢弃
ERROR_INVALID_WINDOW_HANDLE = 1400  # 窗口已销毁/句柄失效
ERROR_NOT_ENOUGH_QUOTA = 1816       # 目标消息队列已满
ERROR_TIMEOUT = 1460                # SendMessageTimeout 超时: 目标无响应(可能卡死)
GA_ROOTOWNER = 3                    # GetAncestor: 取根所有者 (穿透子窗口与归属弹窗)

DELIVERY_FAIL_ALERT = 20            # 连续失败达此数 → 目标标记为失败 (可观察)
DELIVERY_LOG_INTERVAL = 60.0        # 同一目标的失败日志节流间隔(秒), 防高频刷日志

# ---- S1/S2: 键盘投递目标 学习-缓存-校验-拒绝 ----
# 安全不变量: 只有"已学习且当次校验通过"的控件才可接收键盘消息;
#            无法确认身份/安全性时一律拒绝, 绝不退化到未经验证的顶层窗口。
KB_REFUSE = 0                       # 哨兵: 明确拒绝 (≠ 任何合法句柄) (INV-2)
GA_ROOT = 2                         # GetAncestor: 取根窗口(顶层)
ES_PASSWORD = 0x0020                # Edit 控件样式: 密码输入
EM_GETPASSWORDCHAR = 0x00D2         # 查询实际掩码字符(0=非密码) —— 不只依赖样式位
KB_REFUSE_LOG_INTERVAL = 60.0       # 同一目标同类拒绝的日志节流间隔(秒)
PWD_SCAN_LIMIT = 2000               # 子树密码扫描的控件上限; 超限视为无法确认(拒绝)
# N-2: 投递期即时复检 —— 每次投递都查控件自身; 顶层投递【每次都】复扫子树。
# B1-fix3 (R-1): 原实现用 1 秒节流跳过后面的子树复扫, 于是这段时间内新增、
# 由隐藏变为显示、样式被改成密码、或运行期设置了掩码的子控件全部漏检
# (时间为旧的安全结论续命)。现已取消节流, 每次投递都做完整扫描。
# 代价实测: 8 目标单键约 0.73ms (见阶段16报告 §7), 仍在输入预算内。
KB_RESCAN_INTERVAL = 1.0            # 已不用于放行决策; 保留供历史探针与诊断引用

# 拒绝原因码 -> 界面文案 (INV-8: 拒绝必须可见, 不得静默)
KB_REASON_TEXT = {
    "unlearned": "未校准",
    "stale": "控件失效",
    "sensitive": "敏感控件",
    "unknown": "无法确认",
}
KB_REASON_ALL = frozenset(KB_REASON_TEXT.values())

# 类名启发式: 这些是编辑类控件, 才可能承载密码输入
_EDIT_CLASS_HINTS = ("edit", "richedit", "richtext", "textbox", "memo")
# 类名里出现这些词, 直接按敏感处理 (不用管样式位)
_PWD_CLASS_HINTS = ("password", "passwd", "pwd")

# K-3: "自绘内容宿主" —— 内部文本输入不是 Win32 子窗口, 三条判据(类名/ES_PASSWORD/
# EM_GETPASSWORDCHAR)全部看不到它。这类宿主里必须给出"无法确认", 不能给出"不敏感":
#   · Chromium 系 (Chrome/Edge/Electron/CEF/WebView2): 顶层 Chrome_WidgetWin_*,
#     内容宿主 Chrome_RenderWidgetHostHWND, GPU 合成面 Intermediate D3D Window;
#   · MSHTML 宿主 (IE 及内嵌 WebBrowser 控件): Internet Explorer_Server;
#   · Gecko (Firefox 内容区): MozillaWindowClass;
#   · UWP/XAML 跨进程合成: Windows.UI.Core.CoreWindow;
#   · 其它 WebView 宿主。
# 用子串匹配而非全等: 类名带版本/后缀变体 (Chrome_WidgetWin_0/1) 都要命中。
# 已知不覆盖 (残余风险, 见阶段18设计稿 §7): DirectUIHWND、Qt 自绘、游戏自研 UI、
# 未列入本表的浏览器 —— 因此对外仍不得宣称"密码框全面保护"。
_OPAQUE_HOST_HINTS = ("chrome_widgetwin", "renderwidgethost", "intermediate d3d",
                      "internet explorer_server", "mozilla", "corewindow",
                      "webview")


def _is_opaque_host(cls):
    """类名是否属于"自绘/外源渲染树"宿主: 其内部输入控件没有独立 HWND。
    只回答"这类宿主我们看不见内部", 不回答"里面一定有密码框"。"""
    c = (cls or "").strip().lower()
    return any(k in c for k in _OPAQUE_HOST_HINTS)


class MSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("pt", wintypes.POINT), ("mouseData", wintypes.DWORD),
                ("flags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.c_size_t)]


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", wintypes.DWORD), ("scanCode", wintypes.DWORD),
                ("flags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.c_size_t)]


class GUITHREADINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("flags", wintypes.DWORD),
                ("hwndActive", wintypes.HWND), ("hwndFocus", wintypes.HWND),
                ("hwndCapture", wintypes.HWND), ("hwndMenuOwner", wintypes.HWND),
                ("hwndMoveSize", wintypes.HWND), ("hwndCaret", wintypes.HWND),
                ("rcCaret", wintypes.RECT)]


# 紧急停止快捷键: Ctrl + Alt + Q
HOTKEY_VK = 0x51
VK_SHIFT, VK_CONTROL, VK_MENU = 0x10, 0x11, 0x12
# 持续跟随键: 开始同步后按固定间隔向每个次窗口补发一次 (纯工具侧造键, 非转发)
VK_FOLLOW = 0x74          # F5
FOLLOW_INTERVAL_MS = 1000  # 默认间隔, 界面上可关不可调 (保持最小改动)

# ---- 阶段24: 按键规则表 (主号按下 → 次窗口执行) ----
# 每条规则: {"on": bool, "src": 主号vk, "dst": 次号vk, "delay": ms, "times": 连发次数}
# 语义: 表内键【接管】—— 不再进入 _pressed 配对表, 由本通道自己发一对 down+up,
#       因此与全量转发不会重复投递; 表外的键仍按原样全量转发 (WASD 等照旧)。
RULE_REPEAT_GAP_MS = 60    # 连发间隔 (仅 times>1 时使用)
RULE_MAX_TIMES = 10        # 单条连发上限, 防止误配成刷屏
RULE_MAX_DELAY_MS = 2000   # 延迟上限, 防止误配成"按了没反应"
# 扩展键: lParam 第 24 位必须置位, 否则目标端可能不认 (方向键/Delete 等)
_VK_EXTENDED = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                0x2D, 0x2E, 0x90, 0x6F, 0xA3, 0xA5}
# 默认规则: 刷副本常用的 1-5 技能键 + TAB 切目标, 全部 1:1 直通
DEFAULT_KB_RULES = ([{"on": True, "src": 0x31 + i, "dst": 0x31 + i,
                      "delay": 0, "times": 1} for i in range(5)]
                    + [{"on": True, "src": 0x09, "dst": 0x09,
                        "delay": 0, "times": 1}])

_VK_NAMES = {0x09: "TAB", 0x0D: "Enter", 0x1B: "Esc", 0x20: "Space",
             0x08: "Backspace", 0x14: "CapsLock", 0x2D: "Insert",
             0x2E: "Delete", 0x24: "Home", 0x23: "End", 0x21: "PgUp",
             0x22: "PgDn", 0x25: "Left", 0x26: "Up", 0x27: "Right",
             0x28: "Down", 0x10: "Shift", 0x11: "Ctrl", 0x12: "Alt"}


def _vk_name(vk):
    """VK 码 → 界面显示名 (未设置返回"未设置")"""
    vk = int(vk or 0)
    if vk <= 0:
        return "未设置"
    if 0x30 <= vk <= 0x39 or 0x41 <= vk <= 0x5A:
        return chr(vk)
    if 0x60 <= vk <= 0x69:
        return "Num%d" % (vk - 0x60)
    if 0x70 <= vk <= 0x87:
        return "F%d" % (vk - 0x6F)
    return _VK_NAMES.get(vk, "0x%02X" % vk)

user32.ChildWindowFromPoint.argtypes = [wintypes.HWND, wintypes.POINT]
user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
user32.GetAncestor.restype = wintypes.HWND


def _err_text(err):
    """将投递失败的 GetLastError 映射为人类可读原因 (F-07 错误分类)"""
    if err == ERROR_ACCESS_DENIED:
        return "权限不足/UIPI: 目标可能是管理员权限运行"
    if err == ERROR_INVALID_WINDOW_HANDLE:
        return "窗口已失效"
    if err == ERROR_NOT_ENOUGH_QUOTA:
        return "目标消息队列已满"
    if err == ERROR_TIMEOUT:
        return "目标无响应(可能已卡死)"
    return "错误码 %s" % err


# ---- S2: 敏感(密码)输入控件检测 ----
# 设计约束: 不只依赖 ES_PASSWORD 样式位; 无法判断时按敏感处理(拒绝)。
def _is_edit_like(cls):
    """类名是否属于编辑类控件 (只有编辑类才可能是密码输入框)"""
    c = (cls or "").strip().lower()
    return any(k in c for k in _EDIT_CLASS_HINTS)


SENS_YES, SENS_NO, SENS_UNKNOWN = "sensitive", "safe", "unknown"


def _sensitive_state(h):
    """三态判断控件是否可能承载密码输入。
    返回 SENS_YES / SENS_NO / SENS_UNKNOWN。

    为什么必须三态: 原实现把 EM_GETPASSWORDCHAR 查询超时(目标正忙)当成"非敏感",
    等于在"无法确认"时选择放行 —— 与"不确定即拒绝"的安全策略相冲突。
    拆成三态后, 调用方可以:
      · 选窗/校准路径把 UNKNOWN 当作"不安全"处理 (fail-closed);
      · 投递路径把 UNKNOWN 当作"本次拒绝"但不永久拉黑该目标
        (避免一次瞬时超时就把目标整个会话废掉)。

    判定顺序 (任一命中即为 YES):
      1) 类名含 password/passwd/pwd
      2) 编辑类控件 GWL_STYLE & ES_PASSWORD
      3) 编辑类控件 EM_GETPASSWORDCHAR != 0  (捕获运行期 SetPasswordChar)
    另外 (K-3, 优先于其它判据):
      0) 类名属于"自绘内容宿主"(_is_opaque_host) → UNKNOWN
         浏览器/Electron/UWP 的输入框不是子窗口, 上面三条全部失效, 只能判"无法确认"。
    在纯 Win32 控件树上, 非编辑类控件不承载文本输入 → NO。
    但"类名不在编辑类"并不等于"该窗口没有文本输入" —— 这正是第 0 条存在的理由。
    只做只读查询, 不修改控件状态。"""
    try:
        if not h or not user32.IsWindow(h):
            return SENS_UNKNOWN
        cls = win32gui.GetClassName(h) or ""
        if any(k in cls.lower() for k in _PWD_CLASS_HINTS):
            return SENS_YES
        if _is_opaque_host(cls):
            # K-3: 该宿主内部的输入控件不是子窗口, 类名/样式位/掩码三条判据都查不到。
            # 因此只能返回 UNKNOWN (不确定即拒绝), 绝不能落到下面的 SENS_NO ——
            # 那等于"我看不见, 就当作没有密码框"。
            # 选 UNKNOWN 而不是 YES: YES 是终局结论(会粘性拉黑并清缓存), 而这个
            # 判断只说明"无法验证"; 用 UNKNOWN 让上层只做本次拒绝, 不把目标废掉。
            return SENS_UNKNOWN
        if not _is_edit_like(cls):
            return SENS_NO
        style = win32gui.GetWindowLong(h, win32con.GWL_STYLE)
        if style & ES_PASSWORD:
            return SENS_YES
        res = ctypes.c_size_t(0)
        ok = user32.SendMessageTimeoutW(h, EM_GETPASSWORDCHAR, 0, 0,
                                        SMTO_ABORTIFHUNG, 20, ctypes.byref(res))
        if not ok:
            return SENS_UNKNOWN          # 超时/被 UIPI 拦截: 无法确认
        return SENS_YES if res.value else SENS_NO
    except Exception:
        return SENS_UNKNOWN


def _is_sensitive_ctrl(h):
    """布尔化的敏感性判断。True = 敏感【或无法确认】(fail-closed)。
    高代价/低容忍的入口(选窗、校准、学习)用它; 需要区分"确认敏感"与
    "无法确认"的投递路径用 _sensitive_state(), 以便采用不同的粘性策略。"""
    return _sensitive_state(h) != SENS_NO


def _window_password_state(hwnd, limit=PWD_SCAN_LIMIT):
    """扫描窗口子树中【可见】的密码输入控件, 返回三态。
      SENS_YES     : 确认存在密码控件
      SENS_NO      : 确认枚举完成且无密码控件
      SENS_UNKNOWN : 超限/枚举异常/控件查询超时 —— 无法确认
    只在选窗/校准/学习/投递(顶层)路径调用。"""
    hit = [False]
    uncertain = [False]
    seen = [0]

    def cb(h, _):
        seen[0] += 1
        if seen[0] > limit:
            uncertain[0] = True
            return False
        try:
            if win32gui.IsWindowVisible(h):
                st = _sensitive_state(h)
                if st == SENS_YES:
                    hit[0] = True
                    return False
                if st == SENS_UNKNOWN:
                    uncertain[0] = True
        except Exception:
            uncertain[0] = True
        return True

    try:
        if not hwnd or not user32.IsWindow(hwnd):
            return SENS_UNKNOWN
        win32gui.EnumChildWindows(hwnd, cb, None)
    except Exception:
        return SENS_UNKNOWN
    if hit[0]:
        return SENS_YES
    return SENS_UNKNOWN if uncertain[0] else SENS_NO


def _window_has_password(hwnd, limit=PWD_SCAN_LIMIT):
    """扫描窗口子树中【可见】的密码输入控件。
    返回 True = 发现密码控件, 或无法确认(超限/枚举异常/查询超时) → 一律按敏感处理。
    返回 False 仅在"确认枚举完成且无密码控件"时给出。
    只在选窗/校准/学习路径调用, 不在按键路径上。"""
    return _window_password_state(hwnd, limit) != SENS_NO


# ---- F-07 完整性级别探测 (只读, 不提权, 不绕过 UIPI) ----
TokenIntegrityLevel = 25          # TOKEN_INFORMATION_CLASS
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
SECURITY_MANDATORY_MEDIUM_RID = 0x2000
SECURITY_MANDATORY_HIGH_RID = 0x3000

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    """GetTokenInformation(TokenIntegrityLevel) 返回的头部结构; SID 数据紧随其后"""
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


def _token_integrity_rid(hwnd):
    """读取窗口所属进程的完整性级别 RID。
    只读操作: OpenProcess(QUERY_LIMITED_INFORMATION) + OpenProcessToken + GetTokenInformation,
    不修改任何状态、不请求提权、不绕过 UIPI。
    RID: 0x1000=低 0x2000=中(普通) 0x3000=高(管理员) 0x4000=系统
    返回 None 表示无法获取 (权限不足/进程已退出)。"""
    try:
        pid = win32process.GetWindowThreadProcessId(hwnd)[1]
        if not pid:
            return None
        hp = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
        if not hp:
            return None
        try:
            tok = wintypes.HANDLE()
            if not _advapi32.OpenProcessToken(hp, TOKEN_QUERY, ctypes.byref(tok)):
                return None
            try:
                need = wintypes.DWORD(0)
                _advapi32.GetTokenInformation(tok, TokenIntegrityLevel, None, 0,
                                              ctypes.byref(need))
                if not need.value:
                    return None
                buf = ctypes.create_string_buffer(need.value)
                if not _advapi32.GetTokenInformation(tok, TokenIntegrityLevel, buf,
                                                     need, ctypes.byref(need)):
                    return None
                raw = buf.raw
                # 布局: TOKEN_MANDATORY_LABEL (含对齐) + SID 数据
                off = ctypes.sizeof(TOKEN_MANDATORY_LABEL)
                count = raw[off + 1]          # SID.SubAuthorityCount
                if not count:
                    return None
                # SID 头 8 字节, 其后是 count 个 4 字节 SubAuthority, 末位即 RID
                rid_at = off + 8 + 4 * (count - 1)
                if rid_at + 4 > len(raw):
                    return None
                return int.from_bytes(raw[rid_at:rid_at + 4], "little")
            finally:
                _kernel32.CloseHandle(tok)
        finally:
            _kernel32.CloseHandle(hp)
    except Exception:
        return None


def enum_windows(include_sensitive=False):
    """枚举可见的有标题的顶层窗口。
    S2/T-11d: 默认排除【含密码输入控件】的窗口, 从源头杜绝误选
    (选错目标 = 向其注入键鼠事件, 键内容可能落入密码框)。
    include_sensitive=True 仅供诊断/测试, 正常 UI 不要用。"""
    result = []
    me = win32api.GetCurrentProcessId()

    def cb(hwnd, _):
        if not win32gui.IsWindowVisible(hwnd):
            return True
        if win32proc_pid(hwnd) == me:
            return True
        title = win32gui.GetWindowText(hwnd)
        if not title.strip():
            return True
        # 排除透明穿透窗口
        if win32api.GetWindowLong(hwnd, win32con.GWL_EXSTYLE) & win32con.WS_EX_TRANSPARENT:
            return True
        if not include_sensitive and _window_has_password(hwnd):
            return True  # 含密码框 → 不可选 (T-11d)
        result.append((hwnd, title))
        return True

    win32gui.EnumWindows(cb, None)
    return result


def win32proc_pid(hwnd):
    """取窗口所属进程 pid (异常返回 0)"""
    try:
        return win32process.GetWindowThreadProcessId(hwnd)[1]
    except Exception:
        return 0


class SyncEngine:
    """核心同步引擎: 低级钩子捕获 + 消息转发"""

    def __init__(self, own_hwnd_provider, status_cb=None):
        self.main_hwnd = None
        self.targets = []
        self.sync_mouse = True
        self.sync_kb = True
        self.mode = 1
        self.active = False
        self._own_hwnd_provider = own_hwnd_provider
        self.status_cb = status_cb
        self._mouse_proc = None
        self._kb_proc = None
        self._mouse_hook = None
        self._kb_hook = None
        self._btn_flags = 0  # 跟踪主窗口当前按下的鼠标键 (MK_* 常量)
        self.send_char = False  # 补发 WM_CHAR (默认关: 正常程序会双重输入, 仅游戏吃不到字符时开)
        # ---- 加固状态 ----
        self._bindings = {}       # hwnd -> (pid, 类名) 句柄身份指纹, 防句柄回收误投
        self._budget_until = 0.0  # 模式2 单事件投递预算截止时间
        self._err_times = []      # 钩子回调异常时间戳 (熔断用)
        self._last_prune = 0.0    # 上次目标有效性检查时间
        # ---- F-01 投递可观测性: 每个目标独立记账 ----
        # N-1: 键盘与鼠标【分通道记账】, 互不覆盖。结构:
        #   _delivery[t] = {
        #       "ok"/"fail"/"consec"/"err"/"t"/"state"   <- 键盘通道(扁平字段, 沿用原键名)
        #       "refuse"/"rkey"/"rt"/"last"              <- 键盘拒绝计数与节流状态
        #       "mouse": {同名字段}                       <- 鼠标通道, 独立槽位
        #   }
        # 为什么键盘用扁平字段: 既有测试与 UI 都按 _delivery[t]["state"] / ["refuse"] 读键盘,
        # 保持键名不变可避免改动断言; 鼠标另开子槽, 因此鼠标成功无法再清掉键盘拒绝状态。
        self._delivery = {}
        # ---- F-02/F-04 键盘门控与按键状态表 ----
        self._pressed = {}        # vk -> {"res": {target: 控件hwnd}, "sig": {...}, "up_lp": lParam}
        self.kb_scope_main_only = True  # True=仅主窗口为前台时转发键盘 (保守门控)
        # ---- 持续跟随键 (F5) ----
        # 与"转发用户按键"是两条独立路径: 前者受 kb_scope_main_only 门控,
        # 后者是工具自己造键, 不受前台限制 —— 但两者共用同一套敏感/校准闸口。
        self.follow_f5 = False        # 是否启用 (由界面勾选框决定)
        self._follow_sent = 0         # 累计成功投递次数 (诊断用, 不代表目标已响应)
        self._follow_skip = 0         # 累计被闸口拒绝次数
        # ---- 阶段24: 按键规则表 (主号按下 → 次窗口执行) ----
        # 与全量转发的关系: 表内键【接管】(不进入 _pressed), 表外键仍全量转发。
        # 与 F5 的关系: 同为"工具造键", 但触发源是用户按键, 因此【保留前台门控】
        #   —— 否则在浏览器地址栏打 "1" 也会让所有游戏角色放技能。
        self.kb_rules = [dict(r) for r in DEFAULT_KB_RULES]
        self._rule_down = set()       # 已被规则表接管且仍按住的主号 vk (过滤自动重复)
        self._rule_sent = 0           # 累计成功投递组数 (诊断用)
        self._rule_skip = 0           # 累计被闸口拒绝的目标次数
        # ---- 阶段25: 录制回放 (工具造键 → 全部次窗口执行) ----
        # 语义: 回放与 F5 跟随同类, 是【工具自己造键】, 不要求主窗口前台;
        #       但每个目标必须过与实时同步同一套闸口 (_kb_target_for: 校准/敏感/指纹),
        #       未校准的次窗口收不到键盘回放 (业主决策: 必须已校准)。
        # 回放期间引擎不处于 active 态, 因此这组方法不依赖 self.active。
        self._replay_pressed = {}     # vk -> {target: (控件hwnd, sig)}: 回放侧按下配对表
        self._replay_btn_flags = 0    # 回放侧按下的鼠标键 (MK_*), 中止时补发 UP 防粘键
        self._replay_last_pt = {}     # target -> (tx, ty): 最后一次点击的客户区坐标
        # ---- S1/S2: 键盘目标 学习-缓存-校验-拒绝 ----
        # _kb_ctrl[t] = {"hwnd": 控件句柄, "sig": 控件签名, "kind": "top"/"child"}
        #   只有"目标当时确为前台 + 焦点控件归属校验通过 + 敏感检测通过"才会写入。
        self._kb_ctrl = {}
        self._kb_safe_scan = {}   # t -> bool: 是否已确证该目标子树【无】密码控件
        self._target_opts = {}    # t -> {"compat_top": bool 兼容模式, "allow_opaque": bool 自绘窗口放行}; 均默认关, 且都不绕过确定敏感
        # 墓碑: 目标被摘除后短时间保留其最终状态, 使 UI 仍能显示"控件失效"而不是静默消失
        self._tombstones = {}     # hwnd -> (state, 记录时间)
        self._learn_ts = {}       # t -> 上次学习尝试时间 (防"目标常驻前台学不到"时反复扫描)
        self._kb_rescan_ts = {}   # t -> 最后一次【成功确认安全】的时刻 (仅诊断, 不参与放行)
        self._log_ts = {}         # (event, t) -> 上次落盘时间 (R-19-1 热路径写盘节流)

    # ---------- 加固辅助 ----------
    def _fingerprint(self, hwnd):
        """取窗口身份指纹 (pid, 类名)"""
        try:
            pid = win32process.GetWindowThreadProcessId(hwnd)[1]
            return (pid, win32gui.GetClassName(hwnd))
        except Exception:
            return None

    def _prune_dead_targets(self):
        """句柄回收防护: 指纹不符的窗口立即摘除, 绝不盲投。首次见到自动登记; 至多每3秒全检一次"""
        now = _time.monotonic()
        if now - self._last_prune < 3.0:
            return
        self._last_prune = now
        alive, dropped = [], []
        for h in self.targets:
            fp = self._fingerprint(h)
            if not fp:
                dropped.append(h)
                continue
            recorded = self._bindings.get(h)
            if recorded is None:
                self._bindings[h] = fp  # 首次见到: 登记指纹 (信任起点)
                alive.append(h)
            elif recorded == fp:
                alive.append(h)  # 指纹一致: 正常
            else:
                self._bindings.pop(h, None)
                dropped.append(h)  # 指纹变化 = 句柄已被系统复用给别的窗口
        if dropped:
            self.targets = alive
            for h in dropped:
                # 先立墓碑, 再清状态 —— 否则 UI 上该行会静默停在旧文本(可能还是"正常")
                self._tombstones[h] = ("控件失效", _time.monotonic())
                self._forget_target(h)
            AUDIT.write("BINDING_DROP", "摘除失效窗口 %d 个" % len(dropped))
            self._status("已自动移除 %d 个失效窗口 (句柄校验失败)" % len(dropped))

    def _hook_error(self):
        """钩子回调异常计数熔断: 60秒内超50次自动停止"""
        now = _time.monotonic()
        self._err_times = [t for t in self._err_times if now - t < 60]
        self._err_times.append(now)
        if len(self._err_times) >= 50:
            self.stop()
            AUDIT.write("CIRCUIT_BREAK", "60秒内异常 %d 次" % len(self._err_times))
            self._status("转发异常过多, 已自动停止 (详见 audit.log)")

    # ---------- F-01: 投递结果记账 ----------
    # N-1: 记账按通道隔离 (chan = "kb" / "mouse")
    #   键盘槽 = _delivery[owner] 的扁平字段; 鼠标槽 = _delivery[owner]["mouse"]
    #   任一通道的成功只清【自己通道】的失败/拒绝状态, 绝不清另一通道。
    _SLOT_FIELDS = ("ok", "fail", "consec", "err", "t", "state")

    @staticmethod
    def _new_slot():
        return {"ok": 0, "fail": 0, "consec": 0, "err": 0,
                "t": 0.0, "state": "正常"}

    def _slot(self, owner, chan):
        """取某目标某通道的记账槽 (不存在则创建)。键盘为扁平, 鼠标为子槽。"""
        st = self._delivery.setdefault(owner, self._new_slot())
        if chan == "mouse":
            m = st.get("mouse")
            if not isinstance(m, dict):
                m = self._new_slot()
                st["mouse"] = m
            return m
        return st

    def _record_delivery(self, owner, ok, err, chan="kb"):
        """记录一次投递结果 (按通道隔离)。
        语义约定: ok 仅代表"投递 API 接受了该消息", 不等于目标已接收, 更不等于目标已处理
                  (后两者无法从发送侧确认, 故不得据此宣称同步成功)。
        高频失败时节流输出日志, 避免拖慢输入处理。
        chan: "kb" = 键盘通道, "mouse" = 鼠标通道。缺省 "kb" 以兼容旧调用。"""
        if not owner:
            return
        st = self._slot(owner, chan)
        now = _time.monotonic()
        if ok:
            st["ok"] += 1
            st["consec"] = 0
            st["err"] = 0
            st["state"] = "正常"
            st["last"] = "ok"
        else:
            st["fail"] += 1
            st["consec"] += 1
            st["err"] = err
            if st["consec"] >= DELIVERY_FAIL_ALERT and now - st["t"] > DELIVERY_LOG_INTERVAL:
                st["t"] = now
                st["state"] = "失败"
                AUDIT.write("DELIVERY_FAIL", "目标=%d 通道=%s 连续失败=%d err=%d(%s)"
                            % (owner, chan, st["consec"], err, _err_text(err)))
                self._status("目标 %d 投递失败 (%s), 连续 %d 次"
                             % (owner, _err_text(err), st["consec"]))

    # ---------- B1/S1: 键盘目标 学习-缓存-校验-拒绝 ----------
    def _ctrl_sig(self, h, t):
        """控件身份签名 —— 用于检测句柄复用/控件重建。
        组成: pid + 类名 + 控件ID + 父窗口句柄。
        为什么不用句柄本身: 句柄值会被系统回收再分配, 单靠句柄无法识别"换了窗口"。
        为什么不用屏幕几何: 窗口移动/最小化/DPI 变化会改变绝对矩形,
        用几何做身份会造成大量误拒(实测: 目标最小化后签名即失效)。
        已知局限(如实记录): 若同一进程内以相同 ID、相同类名重建控件, 签名不变,
        缓存会被视为有效 —— 但此时落点仍是【该目标的同一用途控件】,
        风险等级等同"目标自己换了输入框", 不构成跨目标误投。
        """
        try:
            if not h or not t or not user32.IsWindow(h) or not user32.IsWindow(t):
                return None
            pid = win32process.GetWindowThreadProcessId(h)[1]
            cls = win32gui.GetClassName(h) or ""
            cid = win32gui.GetWindowLong(h, win32con.GWL_ID)
            parent = int(user32.GetParent(h) or 0)
            return (int(pid), str(cls), int(cid), parent)
        except Exception:
            return None

    def _ctrl_valid(self, h, t, sig):
        """校验候选控件此刻仍可作为目标 t 的键盘投递口 (INV-1)。
        三条同时成立才算通过:
          身份: h 句柄存活;
          归属: GetAncestor(h, GA_ROOT) == t (必须归属于该目标顶层窗口);
          一致性: 控件签名与学习时记录相同 (防句柄复用/控件重建)。
        任一条件无法确认 → False (失败即拒绝, 不猜)。"""
        if not h or not t:
            return False
        try:
            if not user32.IsWindow(h) or not user32.IsWindow(t):
                return False
            root = user32.GetAncestor(h, GA_ROOT)
            if not root or int(root) != int(t):
                return False
            if not sig:
                return False
            return self._ctrl_sig(h, t) == tuple(sig)
        except Exception:
            return False

    def _kb_delivery_check(self, t, h, sig):
        """投递前【即时】校验 (N-2)。返回 (True, "") 或 (False, 原因码)。

        为什么必须有这一层: 学习期做过敏感检测, 但控件可能在运行期改变用途
        (例如同一 Edit 先做搜索框、后被 EM_SETPASSWORDCHAR 改成密码框)。
        缓存命中的旧结论不能代表"此刻"的安全性, 所以每次投递都重查。

        检查项 (任一无法确认 → 拒绝, fail-closed):
          1) 目标与控件句柄都还活着;
          2) 控件仍归属于该目标、签名一致 (_ctrl_valid: 存活/归属/身份);
          3) 该目标的安全结论必须为"已确证无密码控件"(_kb_safe_scan is True);
             False 或从未扫描(None) 一律拒绝;
          4) 控件【此刻】不是敏感控件 —— 重新执行类名 + ES_PASSWORD + EM_GETPASSWORDCHAR;
          5) 若投递对象就是顶层窗口本身(h == t), 额外对该窗口子树做【完整】复扫,
             且【每次投递都做】(B1-fix3 起取消时间节流, 因为可见性/样式位/
             运行期掩码都能在 hwnd 与类名不变的前提下翻转结论)。
        检测到敏感立即把 _kb_safe_scan 置 False 并清缓存, 保证后续所有入口一致拒绝。
        """
        try:
            if not t or not h:
                return False, "stale"
            if not user32.IsWindow(t) or not user32.IsWindow(h):
                return False, "stale"
            if not self._ctrl_valid(h, t, sig):
                return False, "stale"
            scan = self._kb_safe_scan.get(t)
            if scan is not True:
                if scan is False:
                    return False, "sensitive"
                # [B 方案] scan 为 None = "从未确证无密码控件"。自绘窗口的性质决定了
                # 它永远拿不到 True (扫描只能得 UNKNOWN), 所以这里必须先给显式放行
                # 一条通路, 否则 opt-in 在第一道闸口放行后会被第二道闸口原样拒绝。
                if self._opaque_optin(t, h) != "pass":
                    return False, "unknown"
            # 控件级敏感性: 每次投递都查 (N-2 的直接封堵点, 不节流)
            st = _sensitive_state(h)
            if st == SENS_YES:
                self._kb_safe_scan[t] = False
                self._kb_ctrl.pop(t, None)
                AUDIT.write("KB_SENSITIVE", "目标=%d 投递前复检命中敏感控件=%d, 已拒绝"
                            % (t, h))
                return False, "sensitive"
            if st != SENS_NO:
                # 超时/受限/自绘宿主 → 本次无法在控件级确认。默认拒绝; 唯一例外是
                # 用户已显式放行且成因是自绘宿主 —— 此时 _opaque_optin 内部已经做过
                # 整窗确定性复检 (含子树), 因此可以直接放行, 不必再扫一遍。
                verdict = self._opaque_optin(t, h)
                if verdict == "pass":
                    return True, ""
                if verdict == "sensitive":
                    return False, "sensitive"
                return False, "unknown"          # 超时/受限 → 本次无法确认安全性 → 拒绝
            if int(h) == int(t):
                # B1-fix3 (R-1): 每次投递都必须重新扫描子树, 不得用"距上次扫描多久"
                # 代替"此刻的树状态"。原实现用 KB_RESCAN_INTERVAL 跳过这段时间内的
                # 扫描, 于是新增、由隐藏变为显示、样式被改成密码、或运行期被
                # EM_SETPASSWORDCHAR 设置了掩码的子控件全部漏检 —— 时间给"旧的
                # 安全结论"续了命, 违反"只有明确 NO 才放行"。
                #
                # 为什么不能改成"结构指纹缓存": 安全判定依赖的属性不只是
                # (hwnd, 类名)。可见性(IsWindowVisible)、样式位(ES_PASSWORD)、
                # 运行期掩码(EM_GETPASSWORDCHAR) 都能在 hwnd 与类名完全不变的
                # 前提下把结论从 NO 翻成 YES; 任何不覆盖这三项的指纹都会造出
                # 新的漏检面, 因此这里每次做完整扫描。
                #
                # 注: SENS_NO 的判定对【可见】控件成立 (见 _window_password_state)。
                # 不可见控件不构成输入落点; 一旦它变为可见, 本次及后续扫描即会
                # 命中它, 因为这里没有任何跳过逻辑。
                wst = _window_password_state(t)
                if wst == SENS_YES:
                    self._kb_safe_scan[t] = False
                    self._kb_ctrl.pop(t, None)
                    AUDIT.write("KB_SENSITIVE",
                                "目标=%d 投递前子树复扫命中密码控件, 已拒绝" % t)
                    return False, "sensitive"
                if wst != SENS_NO:
                    verdict = self._opaque_optin(t, h, wst)
                    if verdict == "pass":
                        self._kb_rescan_ts[t] = _time.monotonic()
                        return True, ""
                    if verdict == "sensitive":
                        return False, "sensitive"
                    # 不写 _kb_safe_scan: 避免一次瞬时超时把目标永久封禁
                    self._log_throttled(("KB_RESCAN_UNKNOWN", t), "KB_RESCAN_UNKNOWN",
                                        "目标=%d 投递前子树复扫无法确认, 本次拒绝" % t)
                    return False, "unknown"
                # 仅用于诊断: 记录"最后一次成功确认安全"的时刻。
                # 它不参与任何放行判断 (B1-fix3 起), 供 _kb_delivery_check 的
                # 调用方与排查工具观察扫描新鲜度。
                self._kb_rescan_ts[t] = _time.monotonic()
            return True, ""
        except Exception:
            return False, "unknown"          # 校验过程异常 = 无法确认 → 拒绝

    def has_sensitive_ctrl(self, hwnd):
        """目标窗口子树内是否存在密码输入控件 (S2/T-11d 选窗期拦截)。
        返回 True = 存在或无法确认 → 不应作为目标。"""
        return _window_has_password(hwnd)

    def scan_targets_safety(self):
        """对当前目标各做一次敏感控件扫描并缓存结论。
        只在启动/刷新时调用, 不在按键路径上 —— 目的是让"敏感控件"这个拒绝原因
        在目标从未被前台校准过时也能被准确报告, 而不是笼统报"未校准"。
        返回 {target: True(安全) / False(含密码控件)}"""
        out = {}
        for t in list(self.targets):
            if t not in self._kb_safe_scan:
                try:
                    st = _window_password_state(t)
                except Exception:
                    st = SENS_UNKNOWN
                if st == SENS_NO:
                    self._kb_safe_scan[t] = True
                elif st == SENS_YES:
                    self._kb_safe_scan[t] = False   # 确认敏感 → 可缓存
                # SENS_UNKNOWN: 不写缓存, 下次调用重新扫描 (避免瞬时超时永久拒绝)
            out[t] = self._kb_safe_scan.get(t) is True
        return out

    def _learn_kb_target(self, t):
        """在目标【当前确实处于前台】时学习其焦点控件, 建立缓存。
        这是唯一写入 _kb_ctrl 的入口。返回 (hwnd, reason); 未通过则 (KB_REFUSE, 原因)。
        拒绝学习的情形: 目标不在前台 / 焦点为空 / 归属校验失败 / 命中敏感控件。"""
        try:
            fg = user32.GetForegroundWindow()
            if not fg or not self._fg_belongs_to(fg, t):
                return KB_REFUSE, "unlearned"      # 后台: 焦点信息不可靠, 不学
        except Exception:
            return KB_REFUSE, "unlearned"

        # 敏感检测先于一切: 子树里有密码框就整窗拒绝 (INV-3)
        wst = _window_password_state(t)
        if wst == SENS_YES:
            self._kb_ctrl.pop(t, None)
            self._kb_safe_scan[t] = False      # 确认敏感 → 记住, 避免每秒重复扫描
            return KB_REFUSE, "sensitive"
        if wst != SENS_NO:
            # 无法确认(查询超时/子树超限): 本次拒绝学习, 但不写死"已判敏感" ——
            # 否则一次瞬时超时会让该目标整个会话都不可用
            return KB_REFUSE, "unknown"
        self._kb_safe_scan[t] = True
        self._kb_rescan_ts[t] = _time.monotonic()   # 诊断: 最后一次成功确认安全的时刻

        try:
            tid = user32.GetWindowThreadProcessId(t, None)
            gti = GUITHREADINFO()
            gti.cbSize = ctypes.sizeof(GUITHREADINFO)
            if not tid or not user32.GetGUIThreadInfo(tid, ctypes.byref(gti)) \
                    or not gti.hwndFocus:
                return KB_REFUSE, "unlearned"      # 目标自身没有焦点控件
            f = int(gti.hwndFocus)
        except Exception:
            return KB_REFUSE, "unlearned"

        fp = self._ctrl_sig(f, t)
        if not self._ctrl_valid(f, t, fp):
            return KB_REFUSE, "unknown"            # 焦点控件不归属该目标 → 不可信
        fst = _sensitive_state(f)
        if fst == SENS_YES:
            return KB_REFUSE, "sensitive"          # 焦点正落在密码框 → 拒绝
        if fst != SENS_NO:
            # [B 方案] 无法确认时, 只有"用户已显式确认此窗口无密码输入 + 成因确实是
            # 自绘内容宿主"才允许继续学习; 超时/UIPI 等瞬时原因一律不受 opt-in 影响。
            verdict = self._opaque_optin(t, f)
            if verdict == "sensitive":
                return KB_REFUSE, "sensitive"
            if verdict != "pass":
                return KB_REFUSE, "unknown"        # 无法确认 → 拒绝 (不猜)

        kind = "top" if f == int(t) else "child"
        self._kb_ctrl[t] = {"hwnd": f, "sig": fp, "kind": kind}
        AUDIT.write("KB_LEARN", "目标=%d 控件=%d 类型=%s" % (t, f, kind))
        return f, ("OK_TOP" if kind == "top" else "OK")

    def _fg_belongs_to(self, fg, t):
        """前台窗口是否就是目标 t (或属于 t 的子树)"""
        try:
            if int(fg) == int(t):
                return True
            root = user32.GetAncestor(fg, GA_ROOT)
            return bool(root) and int(root) == int(t)
        except Exception:
            return False

    def _is_opaque_target(self, t, h=None):
        """该目标"无法确认"的成因是否为自绘内容宿主 (结构性不可核实)。
        t 自身命中宿主族, 或 t 的子树里存在宿主, 或本次待投递的控件 h 就是宿主,
        三者任一成立即视为结构性原因。"""
        try:
            if t and _is_opaque_host(win32gui.GetClassName(t)):
                return True
            if h and _is_opaque_host(win32gui.GetClassName(h)):
                return True
        except Exception:
            return False
        hit = [False]

        def cb(w, _):
            try:
                if _is_opaque_host(win32gui.GetClassName(w)):
                    hit[0] = True
                    return False
            except Exception:
                pass
            return True

        try:
            win32gui.EnumChildWindows(t, cb, None)
        except Exception:
            return False
        return hit[0]

    def _opaque_optin(self, t, h, wst=None):
        """[B 方案 / 显式 opt-in] 用户确认"此窗口无密码输入"后, 可否覆盖本次 UNKNOWN。

        返回三态, 供调用方区分"拒绝原因":
          "pass"      —— 用户已确认 + 成因是自绘宿主 → 允许本次投递
          "sensitive" —— 复检【确定】命中密码控件 → 必须拒绝, 并收回放行
          "deny"      —— 未确认, 或成因不是自绘宿主 (超时/UIPI/控件不归属) → 拒绝

        三条不可越过的边界:
          1) 未显式确认一律 deny —— opt-in 不是"检测失败就放行";
          2) 超时/权限受限不属于"结构性不可核实", 不受 opt-in 影响 (否则等于用
             用户的确认给一次偶发故障背书);
          3) 每次调用都重做一次确定性复检。原因: _kb_delivery_check 在
             `_sensitive_state(h) != NO` 时就提前返回了, 子树扫描根本没跑;
             而"宿主 + 真密码框"可以共存 (浏览器窗口里既有渲染宿主又有原生密码框),
             若不复检, opt-in 就会给密码框背书。命中即置 _kb_safe_scan=False,
             后续所有入口 (含兼容模式) 一致拒绝。"""
        opts = self._target_opts.get(t) or {}
        if not opts.get("allow_opaque"):
            return "deny"
        if not self._is_opaque_target(t, h):
            return "deny"
        if wst is None:
            wst = _window_password_state(t)
        if wst == SENS_YES:
            self._kb_safe_scan[t] = False
            self._kb_ctrl.pop(t, None)
            AUDIT.write("KB_SENSITIVE",
                        "目标=%d 已放行的自绘窗口内检出密码控件, 已收回放行" % t)
            return "sensitive"
        self._log_throttled(("KB_OPAQUE_PASS", t), "KB_OPAQUE_PASS",
                            "目标=%d 自绘窗口按用户确认放行(未做密码检测)" % t)
        return "pass"

    def _kb_target_for(self, t):
        """解析键盘投递目标。返回 (hwnd, reason)。
        拒绝时 hwnd == KB_REFUSE(0) —— 绝不返回未经验证的顶层窗口 (INV-2)。
        reason: OK / OK_TOP / OK_OPAQUE / OK_COMPAT / unlearned / stale / sensitive / unknown"""
        if not t or not win32gui.IsWindow(t):
            return KB_REFUSE, "stale"
        # 已确证含密码控件 → 直接拒绝 (零成本, 且便于给出准确原因)
        if self._kb_safe_scan.get(t) is False:
            return KB_REFUSE, "sensitive"
        rec = self._kb_ctrl.get(t)
        stale = False
        if rec:
            okc, why = self._kb_delivery_check(t, rec["hwnd"], rec["sig"])
            if okc:
                return rec["hwnd"], ("OK_TOP" if rec["kind"] == "top" else "OK")
            if why == "unknown":
                # K-3: "无法确认"不等于"控件失效" —— 控件可能完全正常, 只是它所在的
                # 窗口是自绘内容宿主(或本次查询超时)。因此这里必须:
                #   1) 保留缓存, 不改报 stale (否则用户看到"控件失效", 与事实不符);
                #   2) 直接拒绝本轮, 【不落到下面的兼容模式出口】—— 兼容模式会
                #      把消息投给未经验证的顶层窗口, 那正是 K-3 要关掉的口子。
                # [B 方案] 唯一例外: 用户对该目标显式确认过"此窗口无密码输入", 且
                # 本次无法确认的成因确实是自绘宿主 (_opaque_optin 内含确定性复检)。
                verdict = self._opaque_optin(t, rec["hwnd"])
                if verdict == "pass":
                    return rec["hwnd"], ("OK_TOP" if rec["kind"] == "top"
                                         else "OK_OPAQUE")
                if verdict == "sensitive":
                    return KB_REFUSE, "sensitive"
                return KB_REFUSE, "unknown"
            # 缓存校验失败: 控件销毁 / 句柄被复用 / 运行期变为敏感控件
            self._kb_ctrl.pop(t, None)
            if why == "sensitive":
                # 敏感是终局结论: 直接拒绝, 不重新学习, 也不给兼容模式留口子 (INV-3)
                return KB_REFUSE, "sensitive"
            stale = True
            AUDIT.write("KB_STALE", "目标=%d 旧控件=%d 校验失败(%s), 已丢弃"
                        % (t, rec["hwnd"], why))
        h, why = self._learn_kb_target(t)
        if h:
            return h, why
        # 兼容模式出口: 仅当该目标已被确证【无密码控件】且用户显式开启才生效。
        # 这不是"盲猜顶层"——它要求目标至少被前台校准过一次; 且敏感检测优先 (INV-3)。
        opts = self._target_opts.get(t) or {}
        if opts.get("compat_top") and self._kb_safe_scan.get(t) and why != "sensitive":
            return t, "OK_COMPAT"
        # 缓存失效比"未校准"更具体, 优先报给用户 (便于判断是窗口关了还是没校准)
        if stale:
            return KB_REFUSE, "stale"
        return KB_REFUSE, why

    def set_compat(self, t, on):
        """开启/关闭某目标的兼容模式(未学到控件时投顶层)。默认关闭。
        即使开启, 命中敏感控件仍拒绝 —— 不允许用兼容模式绕过 S2 保护。"""
        opts = self._target_opts.setdefault(t, {})
        opts["compat_top"] = bool(on)
        AUDIT.write("COMPAT_MODE", "目标=%d 兼容模式=%s" % (t, "开" if on else "关"))

    def _poll_learn_kb(self):
        """被动校准: 若有目标此刻正处前台, 借机学习其焦点控件。
        不抢前台、不注入输入、不改变任何窗口状态 —— 只是读取。
        同一目标的失败尝试 2 秒内不重复, 避免"目标常驻前台但学不到"时
        每个按键都触发子树扫描(会拖慢输入)。"""
        try:
            fg = user32.GetForegroundWindow()
            if not fg:
                return
            now = _time.monotonic()
            for t in list(self.targets):
                if not self._fg_belongs_to(fg, t):
                    continue
                rec = self._kb_ctrl.get(t)
                if rec and self._ctrl_valid(rec["hwnd"], t, rec["sig"]):
                    continue                      # 已校准且有效, 不必重复扫描
                if self._kb_safe_scan.get(t) is False:
                    continue                      # 已确证含密码控件, 不再重复扫描
                if now - self._learn_ts.get(t, 0.0) < 2.0:
                    continue                      # 学习节流
                self._learn_ts[t] = now
                self._learn_kb_target(t)
        except Exception:
            pass

    def _log_throttled(self, key, event, detail):
        """[R-19-1] 热路径审计写盘节流。返回本次是否真的落盘。

        为什么必须节流: AuditLog.write 每次 open+write+close(外加两次 stat),
        实测单次 2.18–2.42ms。而"拒绝投递"是【每键每目标】发生的 —— 8 个目标
        的普通一次按键就会有 16 次拒绝判定, 未节流时实测 37.7–52.6ms/键全是
        文件 I/O, 并且以 16 行/键 (约 1.7KB/键) 的速率把 1MB 日志刷到滚动。
        在低级钩子回调里做这个, 等于让每一次按键都去等磁盘。

        节流粒度: (事件, 目标) + KB_REFUSE_LOG_INTERVAL 窗口。同类拒绝在窗口内
        只留一条 —— 用户可见的拒绝状态不受影响 (计数与文案仍每次更新, 见
        _record_refusal), 因此不是"静默": 拒绝本身仍上报, 只是不重复写盘。"""
        now = _time.monotonic()
        if now - self._log_ts.get(key, 0.0) < KB_REFUSE_LOG_INTERVAL:
            return False
        self._log_ts[key] = now
        AUDIT.write(event, detail)
        return True

    def _record_refusal(self, owner, reason, detail=""):
        """记录一次【拒绝投递】(不是投递失败) (INV-8: 不得静默)。
        同一目标同类原因按 KB_REFUSE_LOG_INTERVAL 节流写审计, 避免刷屏。
        N-1: 拒绝只写键盘通道槽。鼠标成功投递不得把这里写的状态刷回"正常"。"""
        if not owner:
            return
        st = self._slot(owner, "kb")
        st["refuse"] = st.get("refuse", 0) + 1
        st["last"] = reason
        st["state"] = KB_REASON_TEXT.get(reason, "已拒绝")
        now = _time.monotonic()
        if st.get("rkey") != reason or now - st.get("rt", 0.0) > KB_REFUSE_LOG_INTERVAL:
            st["rkey"] = reason
            st["rt"] = now
            AUDIT.write("KB_REFUSE", "目标=%d 原因=%s %s"
                        % (owner, reason, detail[:40]))
            self._status("目标 %d 键盘未转发: %s%s"
                         % (owner, KB_REASON_TEXT.get(reason, reason),
                            (" (" + detail + ")") if detail else ""))

    def _forget_target(self, hwnd):
        """目标被摘除时清理其所有关联状态 (投递账本 + 按键表 + 键盘校准) (INV-6)"""
        self._delivery.pop(hwnd, None)
        self._bindings.pop(hwnd, None)
        self._kb_ctrl.pop(hwnd, None)
        self._kb_safe_scan.pop(hwnd, None)
        self._target_opts.pop(hwnd, None)
        self._kb_rescan_ts.pop(hwnd, None)
        self._learn_ts.pop(hwnd, None)
        for k in [k for k in self._log_ts if k[1] == hwnd]:
            self._log_ts.pop(k, None)
        for rec in self._pressed.values():
            rec["res"].pop(hwnd, None)
            rec.get("sig", {}).pop(hwnd, None)

    def _ok_state_text(self, t):
        """"正常"的措辞必须区分两种目标: 真正通过检测的, 与用户确认放行但未检测的。"""
        if (self._target_opts.get(t) or {}).get("allow_opaque"):
            return "正常(自绘窗口,未检测密码框)"
        return "正常"

    def target_states(self):
        """返回 {target: (状态, 连续失败数, 最近错误码)} 供 UI 展示。
        含近期被摘除的目标(墓碑): 让"控件失效/目标已关闭"这类结论仍然可见 (INV-8)。

        N-1 汇总规则 (单列显示, 必须无歧义):
          1) 键盘通道非"正常" → 显示键盘状态 (键盘是唯一会【静默失败】的通道:
             鼠标还能看到光标动, 键盘被拒则目标一个字符都不进);
          2) 否则鼠标通道非"正常" → 显示鼠标状态;
          3) 两者均正常 → "正常"。
        该规则只影响【显示】, 不影响各自通道的计数: 键盘的 ok/fail/refuse 与鼠标的分开累计。
        """
        now = _time.monotonic()
        for h, (_st, ts) in list(self._tombstones.items()):
            if now - ts > 60.0:
                self._tombstones.pop(h, None)
        out = {}
        for t in self.targets:
            st = self._delivery.get(t)
            if not isinstance(st, dict):
                out[t] = (self._ok_state_text(t), 0, 0)
                continue
            kb_state = st.get("state", "正常")
            m = st.get("mouse")
            m_state = (m.get("state", "正常") if isinstance(m, dict) else "正常")
            if kb_state != "正常":
                out[t] = (kb_state, st.get("consec", 0), st.get("err", 0))
            elif m_state != "正常":
                out[t] = (m_state, m.get("consec", 0), m.get("err", 0))
            else:
                # [B 方案] 已显式放行的自绘窗口, 状态不得显示为与普通窗口相同的"正常":
                # 它只是"用户确认过", 并没有通过密码检测。
                out[t] = (self._ok_state_text(t), 0, 0)
        for h, (st, _ts) in self._tombstones.items():
            out.setdefault(h, (st, 0, 0))
        return out

    def channel_states(self, t):
        """返回 (键盘槽, 鼠标槽) 原始副本, 供测试/诊断区分通道 (N-1)。"""
        st = self._delivery.get(t) or {}
        kb = {k: st.get(k) for k in self._SLOT_FIELDS}
        kb["refuse"] = st.get("refuse", 0)
        m = st.get("mouse")
        mouse = {k: (m.get(k) if isinstance(m, dict) else None) for k in self._SLOT_FIELDS}
        return kb, mouse

    def set_allow_opaque(self, t, on):
        """[B 方案] 显式 opt-in: 用户确认"此窗口无密码输入", 允许对自绘宿主窗口投递
        键盘。默认关闭; 关闭时同时清掉校准缓存, 让下一次投递立即按"无法确认"拒绝。

        与兼容模式 (compat_top) 的区别: 兼容模式解决"学不到控件", 本项解决
        "学得到但无法判断它是不是密码框"。两者都不会覆盖确定命中 (SENS_YES)。

        不写入 config.json 是有意为之: opt-in 是对【此刻这个窗口内容】的确认,
        同一浏览器窗口可能从网页游戏切到网银登录页。持久化等于让昨天的确认
        给今天的密码页背书 —— 与 B1-fix3 "时间不是状态"是同一条原则。"""
        opts = self._target_opts.setdefault(t, {})
        opts["allow_opaque"] = bool(on)
        if not on:
            self._kb_ctrl.pop(t, None)
            self._kb_safe_scan.pop(t, None)
            self._learn_ts.pop(t, None)
        for k in [k for k in self._log_ts if k[1] == t]:
            self._log_ts.pop(k, None)
        AUDIT.write("KB_OPAQUE_OPTIN", "目标=%d 自绘窗口放行=%s"
                    % (t, "开" if on else "关"))
        return bool(on)

    def allow_opaque(self, t):
        """查询某目标是否已显式放行 (供 UI 回显)"""
        return bool((self._target_opts.get(t) or {}).get("allow_opaque"))

    # ---------- F-02: 键盘输入门控 ----------
    def _kb_gate_open(self):
        """判定当前键盘输入是否归属主窗口。
        低级键盘钩子不携带目标窗口信息, 因此采用"前台窗口链归属"判定:
          前台窗口 == 主窗口 → 放行;
          二者根所有者相同 → 放行 (子控件/归属弹窗持有焦点时仍属该程序);
          主窗口失效或前台为空 → 一律关闭。
        """
        main = self.main_hwnd
        if not main or not win32gui.IsWindow(main):
            return False
        fg = user32.GetForegroundWindow()
        if not fg:
            return False
        if fg == main:
            return True
        try:
            return (user32.GetAncestor(fg, GA_ROOTOWNER)
                    == user32.GetAncestor(main, GA_ROOTOWNER))
        except Exception:
            return False

    def _status(self, text):
        if self.status_cb:
            self.status_cb(text)

    # ---------- 钩子安装 ----------
    def start(self):
        if self.active:
            return
        if not self.main_hwnd or not win32gui.IsWindow(self.main_hwnd):
            self._status("请先选择主窗口")
            return False
        # 目标校验: 有效性 + 上限 + 建立句柄指纹
        valid = []
        for h in self.targets:
            fp = self._fingerprint(h)
            if fp and win32gui.IsWindow(h) and h != self.main_hwnd and h not in valid:
                self._bindings[h] = fp
                valid.append(h)
        self.targets = valid[:MAX_TARGETS]
        if not self.targets:
            self._status("请先添加至少一个次窗口")
            return False

        self._mouse_proc = HOOKPROC(self._on_mouse)
        self._kb_proc = HOOKPROC(self._on_kb)
        self._mouse_hook = user32.SetWindowsHookExW(WH_MOUSE_LL, self._mouse_proc, None, 0)
        self._kb_hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, self._kb_proc, None, 0)
        if not self._mouse_hook or not self._kb_hook:
            self.stop()
            AUDIT.write("HOOK_FAIL", "错误码 %d" % ctypes.get_last_error())
            self._status("钩子安装失败 (错误码 %d)" % ctypes.get_last_error())
            return False
        self.active = True
        self._last_prune = 0.0
        AUDIT.write("START", "主=%s 次=%d 模式%d" % (
            win32gui.GetWindowText(self.main_hwnd)[:20], len(self.targets), self.mode))
        # B1/S1: 启动时先尝试一次被动校准 (若目标恰在前台), 再据实提示
        if self.sync_kb:
            self.scan_targets_safety()   # 先判敏感, 保证拒绝原因准确
            self._poll_learn_kb()
        # 措辞边界: 只说"已启动同步", 不说"已同步成功" —— 送达无法从发送侧确认
        kb_hint = " · 键盘仅在主窗口前台时转发" if self.sync_kb else ""
        self._status("同步中: 主窗口 %s → %d 个次窗口 (模式%d)%s, 投递状态见表"
                     % (win32gui.GetWindowText(self.main_hwnd)[:20],
                        len(self.targets), self.mode, kb_hint))
        # INV-8: 未校准 / 敏感目标必须显式告知, 不得静默不工作
        if self.sync_kb:
            unsafe = [t for t in self.targets if self._kb_safe_scan.get(t) is False]
            unlearned = [t for t in self.targets
                         if t not in unsafe and not self._kb_ctrl.get(t)]
            parts = []
            if unsafe:
                parts.append("%d 个含密码输入控件 → 键盘同步已禁用" % len(unsafe))
                AUDIT.write("KB_SENSITIVE", "敏感目标 %d 个" % len(unsafe))
            if unlearned:
                parts.append("%d 个未校准 → 请把每个窗口切到前台一次(点一下输入区)"
                             % len(unlearned))
                AUDIT.write("KB_UNCALIBRATED", "未校准目标 %d 个" % len(unlearned))
            if parts:
                self._status("键盘提示: " + "; ".join(parts))
        # F-07 权限预检: UIPI 会静默丢弃"低完整性 → 高完整性"的投递, 提前告知用户
        uipi = self._uipi_warning()
        if uipi:
            AUDIT.write("UIPI_WARN", uipi)
            self._status(uipi)
        return True

    def _uipi_warning(self):
        """UIPI 风险提示。只做只读探测与告知, 不尝试绕过 UIPI, 不请求提权。
        返回 '' 表示未发现风险 (含探测失败)。"""
        try:
            own = self._own_hwnd_provider() if self._own_hwnd_provider else None
            own_rid = _token_integrity_rid(own) if own else None
            if not own_rid:
                return ""
            blocked = 0
            for h in self.targets:
                rid = _token_integrity_rid(h)
                if rid is not None and rid > own_rid:
                    blocked += 1
            if not blocked:
                return ""
            return ("权限提示: %d 个目标以更高权限运行, 消息会被系统拦截 → "
                    "请以管理员身份运行本工具, 或改为普通权限运行目标程序" % blocked)
        except Exception:
            return ""

    def stop(self):
        if self._mouse_hook:
            user32.UnhookWindowsHookEx(self._mouse_hook)
            self._mouse_hook = None
        if self._kb_hook:
            user32.UnhookWindowsHookEx(self._kb_hook)
            self._kb_hook = None
        self._mouse_proc = None
        self._kb_proc = None
        self._release_pressed_keys()  # 停止时释放仍按着的键, 防目标端永久卡键
        # 阶段24: 规则表没有"未释放"问题 (每次触发都发完整的一对), 但仍要清掉
        # 按住标记 —— 否则下次启动会把"停止前按住不放的键"误判为仍在按住,
        # 从而吞掉它的首次按下。
        self._rule_down.clear()
        self._btn_flags = 0  # 清按键状态, 防止停止后残留半按标志
        self._err_times = []
        was_active = self.active
        self.active = False
        # 跟随键必须随停止一起关: 否则 UI 定时器停掉后若被其它路径重新启用,
        # 会在"已停止"状态下继续造键。
        self.follow_f5 = False
        if was_active:
            AUDIT.write("STOP", "正常停止")
        self._status("已停止")

    def _release_pressed_keys(self):
        """同步停止时, 向用户选定的目标补发 KEYUP (INV-5)。
        必要性: 用户可能在按住某键时停止同步, 目标端此后收不到释放 → 永远以为键还按着。
        边界: 只发给按下时记录的、且仍在次窗口列表中的目标;
              投递前再做一次身份校验 —— 控件已失效/句柄被复用则跳过,
              绝不改投顶层, 也绝不向无关窗口注入释放事件。"""
        if not self._pressed:
            return
        sent = 0
        skipped = 0
        for _vk, rec in list(self._pressed.items()):
            for t, kb in list(rec["res"].items()):
                if t not in self.targets:
                    continue
                # N-2: 停止补发同样走即时校验, 不在敏感/失效控件上补释放
                okc, why = self._kb_delivery_check(t, kb, rec.get("sig", {}).get(t))
                if not okc:
                    skipped += 1
                    self._record_refusal(t, why, "停止补发前复检失败, 已跳过")
                    continue
                self._post(kb, WM_KEYUP, _vk, rec["up_lp"], owner=t)
                sent += 1
        if sent:
            AUDIT.write("KEY_RELEASE", "停止时补发 KEYUP %d 条" % sent)
        if skipped:
            AUDIT.write("KEY_RELEASE_SKIP", "控件校验失败跳过 %d 条" % skipped)
        self._pressed.clear()

    # ---------- 鼠标 ----------
    def _on_mouse(self, nCode, wParam, lParam):
        try:
            if nCode == 0 and self.active and self.sync_mouse and wParam in MOUSE_MSGS:
                info = ctypes.cast(lParam, ctypes.POINTER(MSLLHOOKSTRUCT)).contents
                if not (info.flags & LLMHF_INJECTED):
                    self._forward_mouse(wParam, info)
        except Exception:
            self._hook_error()
        # 无论如何都返回 CallNextHookEx, 绝不吞掉真实输入
        return user32.CallNextHookEx(None, nCode, wParam, lParam)

    def _forward_mouse(self, msg, info):
        self._budget_until = _time.monotonic() + 0.03  # 模式2 投递预算: 单事件 30ms
        MK_L, MK_R, MK_M = 0x0001, 0x0002, 0x0010
        if msg == WM_LBUTTONDOWN:
            self._btn_flags |= MK_L
        elif msg == WM_LBUTTONUP:
            self._btn_flags &= ~MK_L
        elif msg == WM_RBUTTONDOWN:
            self._btn_flags |= MK_R
        elif msg == WM_RBUTTONUP:
            self._btn_flags &= ~MK_R
        elif msg == WM_MBUTTONDOWN:
            self._btn_flags |= MK_M
        elif msg == WM_MBUTTONUP:
            self._btn_flags &= ~MK_M
        self._prune_dead_targets()
        if not self.targets:
            return
        hwnd = self.main_hwnd
        rect = wintypes.RECT()
        user32.GetClientRect(hwnd, ctypes.byref(rect))
        if rect.right <= 0 or rect.bottom <= 0:
            return
        pt = wintypes.POINT(info.pt.x, info.pt.y)
        user32.ScreenToClient(hwnd, ctypes.byref(pt))
        inside = 0 <= pt.x < rect.right and 0 <= pt.y < rect.bottom
        if not inside:
            # 拖拽越界保护: 有按键按住时, MOVE 和所有 UP 消息必达 (钳制坐标), 防次窗口卡键
            up_msg = msg in (WM_LBUTTONUP, WM_RBUTTONUP, WM_MBUTTONUP)
            if not (up_msg or (msg == WM_MOUSEMOVE and self._btn_flags)):
                return  # 光标不在主窗口内且无按键按住, 不同步
            pt.x = min(max(pt.x, 0), rect.right - 1)
            pt.y = min(max(pt.y, 0), rect.bottom - 1)
        fx = pt.x / rect.right
        fy = pt.y / rect.bottom
        for t in self.targets:
            trect = wintypes.RECT()
            user32.GetClientRect(t, ctypes.byref(trect))
            if trect.right <= 0 or trect.bottom <= 0:
                continue
            tx = int(fx * trect.right)
            ty = int(fy * trect.bottom)
            lp = ((ty & 0xFFFF) << 16) | (tx & 0xFFFF)
            # 坐标下的子控件 (输入框等) 优先接收
            mt = self._resolve_mouse_target(t, tx, ty)
            if msg == WM_MOUSEWHEEL:
                delta = ctypes.c_short(info.mouseData >> 16).value
                wp = (delta & 0xFFFF) << 16
                # F-06: 按 Windows 规范, WM_MOUSEWHEEL 的 lParam 必须是屏幕坐标,
                # 而其余鼠标消息用客户区坐标 —— 滚轮需单独换算, 否则多显示器/
                # 依赖光标位置的程序会出现坐标语义错误。
                sp = wintypes.POINT(tx, ty)
                user32.ClientToScreen(t, ctypes.byref(sp))
                lp = ((sp.y & 0xFFFF) << 16) | (sp.x & 0xFFFF)
                self._post(mt, msg, wp, lp, owner=t)
            elif msg == WM_MOUSEMOVE:
                # 移动消息必须携带当前按键状态, 否则按住拖拽会失效
                self._post(mt, msg, self._btn_flags, lp, owner=t)
            else:
                self._post(mt, msg, self._btn_flags, lp, owner=t)

    # ---------- 键盘 ----------
    def _on_kb(self, nCode, wParam, lParam):
        try:
            if nCode == 0:
                info = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                # 紧急停止快捷键 Ctrl+Alt+Q: 同步引擎在运行期间随时可触发
                if (info.vkCode == HOTKEY_VK and not (info.flags & LLKHF_INJECTED)
                        and wParam == WM_KEYDOWN
                        and (user32.GetAsyncKeyState(VK_CONTROL) & 0x8000)
                        and (user32.GetAsyncKeyState(VK_MENU) & 0x8000)):
                    self.stop()
                    AUDIT.write("EMERGENCY_STOP", "快捷键触发")
                    self._status("已通过快捷键 Ctrl+Alt+Q 紧急停止")
                    return user32.CallNextHookEx(None, nCode, wParam, lParam)
                if self.active and self.sync_kb and wParam in KEY_MSGS \
                        and not (info.flags & LLKHF_INJECTED):
                    # B1/S1 被动校准: 用户切到某个次窗口操作时, 借机学习其焦点控件。
                    # 只读, 不抢前台、不注入输入; 学不到就保持"未校准"(后续拒绝投递)。
                    self._poll_learn_kb()
                    # ---- 阶段24: 按键规则表接管 ----
                    # 表内键不走全量转发 (否则同一个键会到目标两次), 由规则通道
                    # 自己发一对 down+up。表外键仍按下面的原逻辑全量转发。
                    _rule = self._kb_rule_for(info.vkCode)
                    if _rule is not None:
                        if wParam in (WM_KEYUP, WM_SYSKEYUP):
                            self._rule_down.discard(info.vkCode)
                            # 保护: 运行中把某键临时加进规则表时, 它可能已经由
                            # 全量转发按下 → 抬起必须由原通道补齐, 否则目标端卡键。
                            if info.vkCode in self._pressed:
                                self._forward_kb(wParam, info)
                        elif info.vkCode in self._rule_down:
                            pass    # 自动重复 (按住不放): 只认首次按下
                        elif self.kb_scope_main_only and not self._kb_gate_open():
                            pass    # 不归属主窗口 → 不触发 (与全量转发同一门控)
                        else:
                            self._rule_down.add(info.vkCode)
                            self._fire_kb_rule(_rule)
                    # F-02 输入门控: 只转发归属主窗口的输入。
                    #   工具自身窗口为前台时必然不等于主窗口 → 门控自然关闭,
                    #   等价于(并取代)原先"工具自身前台不转发"的独立判断。
                    elif wParam in (WM_KEYUP, WM_SYSKEYUP) and info.vkCode in self._pressed:
                        # F-04 释放必达: 该键是在门控放行期间按下的, 即使焦点已变化
                        # 也必须把释放送到原目标, 否则目标端永久卡键。
                        # 只发给按下时记录的、用户选定的目标, 不发给其他任何窗口。
                        self._forward_kb(wParam, info)
                    elif self.kb_scope_main_only and not self._kb_gate_open():
                        pass  # 输入不归属主窗口 (含主窗口已关闭/失效), 不转发
                    else:
                        self._forward_kb(wParam, info)
        except Exception:
            self._hook_error()
        # 无论如何都返回 CallNextHookEx, 绝不吞掉真实输入
        return user32.CallNextHookEx(None, nCode, wParam, lParam)

    def _resolve_kb_target(self, t):
        """[兼容接口] 返回键盘投递控件句柄; 拒绝投递时返回 KB_REFUSE(0)。
        真正的判定与拒绝原因请用 _kb_target_for(t) -> (hwnd, reason)。
        语义变更(阶段10/B1): 旧实现在解析失败时退化为目标顶层窗口(盲投, NEW-01),
        现在改为"未学习/无法确认 → 0", 由调用方按拒绝处理。"""
        h, _why = self._kb_target_for(t)
        return h

    def _resolve_mouse_target(self, t, x, y):
        """鼠标消息投给坐标下的子控件 (输入框等), 找不到就投顶层"""
        try:
            child = user32.ChildWindowFromPoint(t, wintypes.POINT(x, y))
            if child:
                return child
        except Exception:
            pass
        return t

    def _forward_kb(self, msg, info):
        self._budget_until = _time.monotonic() + 0.03  # 模式2 投递预算
        self._prune_dead_targets()
        if not self.targets:
            return
        lp = 1 | ((info.scanCode & 0xFF) << 16)
        if info.flags & 0x1:  # LLKHF_EXTENDED
            lp |= 1 << 24
        up_lp = (lp | (1 << 30) | (1 << 31)) & 0xFFFFFFFF  # 抬起: 转换状态+先前状态
        vk = info.vkCode
        shift_down = bool(user32.GetAsyncKeyState(VK_SHIFT) & 0x8000)

        if msg in (WM_KEYUP, WM_SYSKEYUP):
            # F-04: 抬起必须使用按下时记录的解析结果与 lParam, 保证配对一致。
            # 无记录的抬起 (例如同步开始前就按住的键, 或按下时被拒绝的目标)
            # 一律不投 —— 不得凭空补发, 也不得改投到别处 (INV-4)。
            rec = self._pressed.pop(vk, None)
            if not rec:
                return
            for t, kb in list(rec["res"].items()):
                if t not in self.targets:  # 目标已被摘除则不投
                    continue
                # 抬起也要过即时校验: 控件已销毁/句柄被复用/运行期变为敏感控件
                # → 跳过, 绝不盲投 (N-2)。宁可目标端留一个未释放的键状态,
                # 也不把释放事件注入到已变成密码框的控件里。
                okc, why = self._kb_delivery_check(t, kb, rec.get("sig", {}).get(t))
                if not okc:
                    self._record_refusal(t, why, "抬起前复检失败, 已跳过")
                    continue
                self._post(kb, msg, vk, rec["up_lp"], owner=t)
            return

        if vk not in self._pressed:
            # 首次按下时登记 (自动重复不覆盖, 保证抬起与首次按下同目标)
            res, fps, reasons = {}, {}, {}
            for t in self.targets:
                h, why = self._kb_target_for(t)
                reasons[t] = why
                if h:
                    res[t] = h
                    fps[t] = self._ctrl_sig(h, t)
                else:
                    # 拒绝: 不登记 → 该目标的抬起也不会补发 (INV-2/INV-4)
                    self._record_refusal(t, why)
            self._pressed[vk] = {
                "res": res, "sig": fps, "up_lp": up_lp, "why": reasons,
            }
        rec = self._pressed[vk]
        for t in self.targets:
            kb = rec["res"].get(t)
            if not kb:
                continue        # 被拒绝的目标: 本键全程不投递
            # N-2: 自动重复与首次按下的实际投递也走即时校验。
            # 校验不过 → 立即从按键记录里摘掉该目标, 使抬起也不再投它。
            okc, why = self._kb_delivery_check(t, kb, rec.get("sig", {}).get(t))
            if not okc:
                rec["res"].pop(t, None)
                rec.get("sig", {}).pop(t, None)
                self._record_refusal(t, why, "投递前复检失败, 本键不再投递")
                continue
            self._post(kb, msg, vk, lp & 0xFFFFFFFF, owner=t)
            # 可选补发 WM_CHAR (默认关): 目标消息循环会自己翻译 WM_KEYDOWN,
            # 再补 WM_CHAR 会双重输入; 仅当目标完全不响应按键消息时开启
            if self.send_char and msg == WM_KEYDOWN and 0x20 <= vk < 0x5F:
                ch = win32api.MapVirtualKey(vk, 2)  # MAPVK_VK_TO_CHAR
                if ch and not (ch & 0x80000000):  # 排除死键 (重音符号键)
                    ch &= 0xFFFF
                    if 0x41 <= vk <= 0x5A and not shift_down:
                        ch += 0x20  # 未按 Shift 时转小写
                    # F-12-2: WM_CHAR 同样是实际的键盘投递(会向控件注入一个字符),
                    # 因此与 KEYDOWN 同等地过敏感性闸口, 并且必须显式传 owner=t:
                    #   1) 模式2(同步投递)下 KEYDOWN 已在目标消息循环中执行完毕,
                    #      控件有可能在那一刻之后才被改成密码框 —— 只靠 KEYDOWN
                    #      那次检查存在"检查→投递"之间的状态变化窗口;
                    #   2) _post 的 owner 缺省为"按接收句柄记账", 而接收方是焦点
                    #      子控件 → 记账会落到非目标句柄上, 使该次投递在目标维度
                    #      不可见(诊断口径错误), 与其它键盘入口不一致。
                    okc2, why2 = self._kb_delivery_check(t, kb, rec.get("sig", {}).get(t))
                    if not okc2:
                        # R-19-1: 与 KB_RESCAN_UNKNOWN 同理, WM_CHAR 的拒绝也是
                        # "每字符每目标"一次, 未节流时同样给每次按键叠一层文件 I/O。
                        self._log_throttled(("KB_CHAR_SKIP", t), "KB_CHAR_SKIP",
                                            "目标=%d WM_CHAR 复检失败(%s), 已跳过"
                                            % (t, why2))
                    else:
                        self._post(kb, WM_CHAR, ch, lp & 0xFFFFFFFF, owner=t)

    # ---------- 持续跟随键 (F5) ----------
    def tap_follow_key_once(self):
        """向每个次窗口补发一次 VK_FOLLOW (按下+抬起)。返回 (已投递, 被拒)。

        语义边界 (必须与 _forward_kb 区分):
          这是【工具自己造键】, 不是转发用户按键。因此它不受
          kb_scope_main_only("仅主窗口前台才转发") 约束 —— 次窗口在后台
          也能收到, 这正是"跟随"要的效果。
        安全边界 (不得放宽):
          每个目标都必须先过 _kb_target_for(), 它内部依次做:
            句柄存活 → 归属/签名校验 → 敏感复检 → 自绘宿主 opt-in 判定;
          未校准(unlearned)、已确证敏感(sensitive)、无法确认(unknown) 一律拒绝。
          即: 放开的是"前台"限制, 不是"安全"限制。
        记账 (INV-8):
          拒绝走 _record_refusal (按目标计数 + 节流写审计 + 状态栏提示),
          投递走 _post 的既有记账, 不静默。
        """
        if not self.active or not self.follow_f5:
            return 0, 0
        self._prune_dead_targets()
        if not self.targets:
            return 0, 0
        # 模式2 的同步投递预算: 与 _forward_kb 一致, 只在前 30ms 内用
        # SendMessageTimeout, 之后自动降级 PostMessage, 防一次 tick 卡死主线程。
        self._budget_until = _time.monotonic() + 0.03
        # 扫描码必须换算: 部分游戏只认 lParam 高字节的硬件扫描码,
        # 填 0 会被当作"无效键"直接丢弃。
        try:
            sc = win32api.MapVirtualKey(VK_FOLLOW, 0) & 0xFF
        except Exception:
            sc = 0x3F  # F5 的 Set-1 标准扫描码, 换算失败时兜底
        lp_down = 1 | (sc << 16)
        lp_up = (lp_down | (1 << 30) | (1 << 31)) & 0xFFFFFFFF
        sent = skipped = 0
        for t in list(self.targets):
            h, why = self._kb_target_for(t)
            if not h:
                skipped += 1
                self._record_refusal(t, why, "F5 跟随")
                continue
            ok, _err = self._post(h, WM_KEYDOWN, VK_FOLLOW, lp_down, owner=t)
            if not ok:
                skipped += 1
                continue
            # 抬起必须发: 否则目标端会认为 F5 一直按着, 后续按键全被粘住
            self._post(h, WM_KEYUP, VK_FOLLOW, lp_up, owner=t)
            sent += 1
        self._follow_sent += sent
        self._follow_skip += skipped
        return sent, skipped

    # ---------- 按键规则表 (阶段24: 主号按下 → 次窗口执行) ----------
    def _vk_scancode(self, vk):
        """VK → (扫描码, 是否扩展键)。扫描码填 0 会被部分游戏当无效键丢弃。"""
        try:
            sc = win32api.MapVirtualKey(vk, 0) & 0xFF
        except Exception:
            sc = 0
        if not sc:
            # 少数键 MapVirtualKey 返回 0, 用 VK 低字节兜底 (至少不是 0)
            sc = vk & 0xFF
        return sc, (vk in _VK_EXTENDED)

    def _kb_rule_for(self, vk):
        """查找主号按键 vk 命中的规则; 未命中返回 None。
        多条规则映射同一主号键时取第一条生效的 (界面上不允许重复, 这里只做兜底)。"""
        if not self.kb_rules:
            return None
        for r in self.kb_rules:
            if not r.get("on", True):
                continue
            if int(r.get("src", 0)) == vk and int(r.get("dst", 0)) > 0:
                return r
        return None

    def _later(self, delay_ms, fn):
        """统一延时入口。钩子回调内绝不 sleep (低级钩子超时会被系统摘掉),
        所有延迟/连发都从这里走 QTimer; 探针可替换本方法验证调度逻辑。"""
        QTimer.singleShot(int(delay_ms), fn)

    def _fire_kb_rule(self, rule):
        """按规则调度投递。钩子回调内绝不阻塞 (低级钩子超时会被系统摘掉),
        因此延迟与连发全部交给 QTimer 异步完成。"""
        vk = int(rule.get("dst", 0))
        if vk <= 0:
            return
        try:
            delay = max(0, min(RULE_MAX_DELAY_MS, int(rule.get("delay", 0) or 0)))
            times = max(1, min(RULE_MAX_TIMES, int(rule.get("times", 1) or 1)))
        except Exception:
            delay, times = 0, 1
        if delay <= 0:
            self._deliver_rule_key(vk, times)
        else:
            self._later(delay, lambda: self._deliver_rule_key(vk, times))

    def _deliver_rule_key(self, vk, times_left):
        """向每个次窗口投递一次 次号键 (down+up), 可递归完成连发。

        安全边界 (与 F5 完全一致, 不得放宽):
          每个目标先过 _kb_target_for() —— 句柄存活 / 归属签名 / 敏感复检 /
          自绘宿主 opt-in; 未校准、确证敏感、无法确认一律拒绝。
        配对边界: 本通道自己发完整的一对, 因此不受主号 up 事件影响,
          也就不存在"只发 down 不发 up"卡键的可能 (目标摘除则整组跳过)。
        """
        if not self.active:      # 延迟/连发期间被停止 → 不再投
            return
        self._prune_dead_targets()
        if not self.targets:
            return
        self._budget_until = _time.monotonic() + 0.03
        sc, ext = self._vk_scancode(vk)
        lp_down = 1 | ((sc & 0xFF) << 16) | ((1 << 24) if ext else 0)
        lp_up = (lp_down | (1 << 30) | (1 << 31)) & 0xFFFFFFFF
        sent = skipped = 0
        for t in list(self.targets):
            h, why = self._kb_target_for(t)
            if not h:
                skipped += 1
                self._record_refusal(t, why, "按键规则")
                continue
            ok, _e = self._post(h, WM_KEYDOWN, vk, lp_down & 0xFFFFFFFF, owner=t)
            if not ok:
                skipped += 1
                continue
            # 抬起必发: 否则目标端认为该键一直按着, 后续按键全被粘住
            self._post(h, WM_KEYUP, vk, lp_up, owner=t)
            sent += 1
        self._rule_sent += sent
        self._rule_skip += skipped
        if times_left > 1:
            self._later(RULE_REPEAT_GAP_MS,
                        lambda: self._deliver_rule_key(vk, times_left - 1))

    # ---------- 阶段25: 回放投递 (无状态单事件接口, 供 ScriptPlayer 调用) ----------
    def replay_targets_ready(self):
        """回放前置校验。返回 '' 表示就绪, 否则返回给用户看的错误文本。"""
        self._prune_dead_targets()
        if not self.targets:
            return "没有可执行的次窗口, 请先添加次窗口"
        if not self.main_hwnd or not win32gui.IsWindow(self.main_hwnd):
            return "主窗口未设置或已失效, 请先设置主窗口"
        return ""

    def replay_mouse(self, msg, fx, fy, wp=0, delta=0):
        """向全部次窗口回放一条鼠标事件 (fx/fy = 录制时主窗口客户区归一化坐标)。
        坐标换算与 _forward_mouse 同一公式: 归一化坐标 × 目标客户区尺寸。
        返回 (成功投递目标数, 失败目标数)。"""
        MK_L, MK_R, MK_M = 0x0001, 0x0002, 0x0010
        if msg == WM_LBUTTONDOWN:
            self._replay_btn_flags |= MK_L
        elif msg == WM_LBUTTONUP:
            self._replay_btn_flags &= ~MK_L
        elif msg == WM_RBUTTONDOWN:
            self._replay_btn_flags |= MK_R
        elif msg == WM_RBUTTONUP:
            self._replay_btn_flags &= ~MK_R
        elif msg == WM_MBUTTONDOWN:
            self._replay_btn_flags |= MK_M
        elif msg == WM_MBUTTONUP:
            self._replay_btn_flags &= ~MK_M
        sent = skipped = 0
        for t in list(self.targets):
            try:
                trect = wintypes.RECT()
                if not user32.GetClientRect(t, ctypes.byref(trect)) \
                        or trect.right <= 0 or trect.bottom <= 0:
                    skipped += 1
                    continue
                tx = int(fx * trect.right)
                ty = int(fy * trect.bottom)
                if msg in (WM_LBUTTONDOWN, WM_RBUTTONDOWN, WM_MBUTTONDOWN):
                    self._replay_last_pt[t] = (tx, ty)  # 中止补发 UP 的落点
                mt = self._resolve_mouse_target(t, tx, ty)
                if msg == WM_MOUSEWHEEL:
                    # 与 _forward_mouse 同: 滚轮 lParam 必须是屏幕坐标 (F-06)
                    w = (delta & 0xFFFF) << 16
                    sp = wintypes.POINT(tx, ty)
                    user32.ClientToScreen(t, ctypes.byref(sp))
                    lp = ((sp.y & 0xFFFF) << 16) | (sp.x & 0xFFFF)
                else:
                    w = wp
                    lp = ((ty & 0xFFFF) << 16) | (tx & 0xFFFF)
                ok, _e = self._post(mt, msg, w, lp, owner=t)
                if ok:
                    sent += 1
                else:
                    skipped += 1
            except Exception:
                skipped += 1
        return sent, skipped

    def replay_kb(self, msg, vk, scan, ext):
        """向全部次窗口回放一条键盘事件。
        按下: 走 _kb_target_for 闸口 (未校准/敏感/失效 → 拒绝, INV-2 同源),
              解析结果登记进 _replay_pressed 供抬起配对;
        抬起: 只发给按下时登记的控件 (F-04 同源配对), 无配对的抬起不凭空补发。
        返回 (成功投递目标数, 失败/被拒目标数)。"""
        lp_down = 1 | ((scan & 0xFF) << 16)
        if ext:
            lp_down |= 1 << 24
        lp_up = (lp_down | (1 << 30) | (1 << 31)) & 0xFFFFFFFF
        sent = skipped = 0
        if msg in (WM_KEYUP, WM_SYSKEYUP):
            rec = self._replay_pressed.pop(vk, None)
            if not rec:
                return 0, 1
            for t, (h, sig) in list(rec.items()):
                if t not in self.targets:
                    continue
                okc, why = self._kb_delivery_check(t, h, sig)
                if not okc:
                    self._record_refusal(t, why, "回放抬起")
                    skipped += 1
                    continue
                ok, _e = self._post(h, msg, vk, lp_up, owner=t)
                if ok:
                    sent += 1
                else:
                    skipped += 1
            return sent, skipped
        # 按下: 首次按下解析登记, 后续同键事件复用登记结果
        if vk not in self._replay_pressed:
            rec = {}
            for t in list(self.targets):
                h, why = self._kb_target_for(t)
                if not h:
                    self._record_refusal(t, why, "回放")
                    continue
                rec[t] = (h, self._ctrl_sig(h, t))
            self._replay_pressed[vk] = rec
        rec = self._replay_pressed[vk]
        for t, (h, sig) in list(rec.items()):
            okc, why = self._kb_delivery_check(t, h, sig)
            if not okc:
                rec.pop(t, None)
                self._record_refusal(t, why, "回放复检")
                skipped += 1
                continue
            ok, _e = self._post(h, msg, vk, lp_down & 0xFFFFFFFF, owner=t)
            if ok:
                sent += 1
            else:
                skipped += 1
        return sent, skipped

    def replay_release_all(self):
        """回放中止/结束时的收尾: 补发所有未释放的 KEYUP 与鼠标按键 UP,
        防目标端永久卡键/粘键。只发给回放期间实际投递过的目标, 绝不外溢。"""
        released = 0
        for vk, rec in list(self._replay_pressed.items()):
            for t, (h, sig) in list(rec.items()):
                if t not in self.targets:
                    continue
                try:
                    okc, _why = self._kb_delivery_check(t, h, sig)
                    if okc:
                        sc = win32api.MapVirtualKey(vk, 0) & 0xFF
                        lp = (1 | (sc << 16) | (1 << 30) | (1 << 31)) & 0xFFFFFFFF
                        self._post(h, WM_KEYUP, vk, lp, owner=t)
                        released += 1
                except Exception:
                    pass
        self._replay_pressed.clear()
        if self._replay_btn_flags:
            MK_L, MK_R, MK_M = 0x0001, 0x0002, 0x0010
            ups = []
            if self._replay_btn_flags & MK_L:
                ups.append(WM_LBUTTONUP)
            if self._replay_btn_flags & MK_R:
                ups.append(WM_RBUTTONUP)
            if self._replay_btn_flags & MK_M:
                ups.append(WM_MBUTTONUP)
            for t, (tx, ty) in list(self._replay_last_pt.items()):
                if t not in self.targets:
                    continue
                lp = ((ty & 0xFFFF) << 16) | (tx & 0xFFFF)
                for msg in ups:
                    try:
                        self._post(self._resolve_mouse_target(t, tx, ty),
                                   msg, 0, lp, owner=t)
                        released += 1
                    except Exception:
                        pass
        self._replay_btn_flags = 0
        self._replay_last_pt.clear()
        return released

    # ---------- 消息投递 (模式) ----------
    def _post(self, hwnd, msg, wp, lp, owner=None):
        """投递一条消息, 返回 (ok, err)。
        语义边界: ok 仅代表投递 API 接受了该消息;
                  目标是否收到、是否处理, 无法从发送侧确认, 不得据此宣称同步成功。
        owner: 消息归属的次窗口 (用于按目标记账), 缺省按接收句柄记账。
        N-1: 记账通道由消息号推导 —— 键盘消息(WM_KEY*/WM_CHAR)与鼠标消息
             (MOUSE_MSGS)的取值区间互不相交, 因此无需新增参数即可分离记账,
             也就不会因为改签名而破坏既有测试夹具。"""
        if self.mode == 2 and _time.monotonic() < self._budget_until:
            # 模式2: 同步投递, 超时 20ms; 预算耗尽自动降级 PostMessage, 保证不卡真实输入
            result = ctypes.c_size_t(0)  # DWORD_PTR
            ok = bool(user32.SendMessageTimeoutW(
                hwnd, msg, wp, lp, SMTO_ABORTIFHUNG, 20, ctypes.byref(result)))
        else:
            # 模式1: PostMessage 异步投递 (最常用); 模式2 预算耗尽后的降级通道
            ok = bool(user32.PostMessageW(hwnd, msg, wp, lp))
        err = 0 if ok else ctypes.get_last_error()
        try:
            chan = "mouse" if msg in MOUSE_MSGS else "kb"
            self._record_delivery(owner or hwnd, ok, err, chan=chan)
        except Exception:
            pass  # 记账属于旁路, 绝不影响投递主流程
        return ok, err


class ActionRecorder:
    """阶段25: 动作录制器。自装低级钩子, 只记录不转发, 绝不吞真实输入。
    录制范围 (业主决策 2026-10-28):
      · 鼠标: 只录光标在主窗口客户区内的动作 (拖出期间不录, 如实记录边界);
      · 键盘: 只录主窗口为前台时的按键 (按住自动重复只记一次 down+up)。
    事件格式: {"t": 相对ms, "ch": "m"/"k", ...} 鼠标存归一化坐标 fx/fy,
    键盘存 vk/scan/ext —— 回放时按比例换算, 与窗口分辨率解耦。"""

    def __init__(self, status_cb=None):
        self.recording = False
        self.main_hwnd = None
        self.events = []
        self.status_cb = status_cb
        self._stop_cb = None          # Ctrl+Alt+Q 触发的 UI 侧停止回调
        self._mouse_proc = None
        self._kb_proc = None
        self._mouse_hook = None
        self._kb_hook = None
        self._t0 = 0.0
        self._btn_flags = 0
        self._last_move_t = 0
        self._kb_down = set()

    def _status(self, text):
        try:
            if self.status_cb:
                self.status_cb(text)
        except Exception:
            pass

    def start(self, main_hwnd, stop_cb):
        if self.recording:
            return False
        if not main_hwnd or not win32gui.IsWindow(main_hwnd):
            return False
        self.main_hwnd = main_hwnd
        self.events = []
        self._t0 = _time.monotonic()
        self._btn_flags = 0
        self._last_move_t = -10 ** 9
        self._kb_down = set()
        self._stop_cb = stop_cb
        self._mouse_proc = HOOKPROC(self._on_mouse)
        self._kb_proc = HOOKPROC(self._on_kb)
        self._mouse_hook = user32.SetWindowsHookExW(
            WH_MOUSE_LL, self._mouse_proc, None, 0)
        self._kb_hook = user32.SetWindowsHookExW(
            WH_KEYBOARD_LL, self._kb_proc, None, 0)
        if not self._mouse_hook or not self._kb_hook:
            self.stop()
            AUDIT.write("REC_FAIL", "钩子安装失败 错误码 %d" % ctypes.get_last_error())
            return False
        self.recording = True
        AUDIT.write("REC_START", "主=%s" % win32gui.GetWindowText(main_hwnd)[:20])
        return True

    def stop(self):
        """卸载钩子并结束录制。返回是否有录制会话被结束。"""
        if self._mouse_hook:
            user32.UnhookWindowsHookEx(self._mouse_hook)
            self._mouse_hook = None
        if self._kb_hook:
            user32.UnhookWindowsHookEx(self._kb_hook)
            self._kb_hook = None
        self._mouse_proc = None
        self._kb_proc = None
        was = self.recording
        self.recording = False
        self._kb_down.clear()
        if was:
            AUDIT.write("REC_STOP", "事件 %d 条" % len(self.events))
        return was

    def _now(self):
        return int((_time.monotonic() - self._t0) * 1000)

    def _in_main(self, x, y):
        """光标是否在主窗口客户区内; 返回 (inside, fx, fy 归一化坐标)。"""
        try:
            rect = wintypes.RECT()
            if not user32.GetClientRect(self.main_hwnd, ctypes.byref(rect)):
                return False, 0.0, 0.0
            if rect.right <= 0 or rect.bottom <= 0:
                return False, 0.0, 0.0
            pt = wintypes.POINT(x, y)
            user32.ScreenToClient(self.main_hwnd, ctypes.byref(pt))
            if not (0 <= pt.x < rect.right and 0 <= pt.y < rect.bottom):
                return False, 0.0, 0.0
            return True, pt.x / rect.right, pt.y / rect.bottom
        except Exception:
            return False, 0.0, 0.0

    def _on_mouse(self, nCode, wParam, lParam):
        try:
            if nCode == 0 and self.recording and wParam in MOUSE_MSGS:
                info = ctypes.cast(lParam, ctypes.POINTER(MSLLHOOKSTRUCT)).contents
                if not (info.flags & LLMHF_INJECTED):
                    self._capture_mouse(wParam, info)
        except Exception:
            pass  # 录制旁路绝不能影响真实输入: 任何异常都直接放行
        return user32.CallNextHookEx(None, nCode, wParam, lParam)

    def _capture_mouse(self, msg, info):
        inside, fx, fy = self._in_main(info.pt.x, info.pt.y)
        if not inside:
            return
        t = self._now()
        MK_L, MK_R, MK_M = 0x0001, 0x0002, 0x0010
        if msg == WM_LBUTTONDOWN:
            self._btn_flags |= MK_L
        elif msg == WM_LBUTTONUP:
            self._btn_flags &= ~MK_L
        elif msg == WM_RBUTTONDOWN:
            self._btn_flags |= MK_R
        elif msg == WM_RBUTTONUP:
            self._btn_flags &= ~MK_R
        elif msg == WM_MBUTTONDOWN:
            self._btn_flags |= MK_M
        elif msg == WM_MBUTTONUP:
            self._btn_flags &= ~MK_M
        if msg == WM_MOUSEMOVE:
            if t - self._last_move_t < REC_MOVE_MIN_MS:
                return  # 采样节流: 首个 move 总会被记录 (_last_move_t 初始化为极小值)
            self._last_move_t = t
        ev = {"t": t, "ch": "m", "msg": int(msg),
              "fx": round(fx, 4), "fy": round(fy, 4)}
        if msg == WM_MOUSEMOVE:
            ev["wp"] = self._btn_flags  # 拖拽语义需要按钮状态
        elif msg == WM_MOUSEWHEEL:
            ev["delta"] = ctypes.c_short(info.mouseData >> 16).value
        self.events.append(ev)

    def _on_kb(self, nCode, wParam, lParam):
        try:
            if nCode == 0:
                info = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                # Ctrl+Alt+Q: 录制期间的紧急停止 (与实时同步同一快捷键)
                if (info.vkCode == HOTKEY_VK and not (info.flags & LLKHF_INJECTED)
                        and wParam == WM_KEYDOWN
                        and (user32.GetAsyncKeyState(VK_CONTROL) & 0x8000)
                        and (user32.GetAsyncKeyState(VK_MENU) & 0x8000)):
                    cb = self._stop_cb
                    self._stop_cb = None  # 防长按自动重复连触
                    if cb:
                        cb()
                    return user32.CallNextHookEx(None, nCode, wParam, lParam)
                if self.recording and wParam in KEY_MSGS \
                        and not (info.flags & LLKHF_INJECTED) \
                        and user32.GetForegroundWindow() == self.main_hwnd:
                    self._capture_kb(wParam, info)
        except Exception:
            pass
        return user32.CallNextHookEx(None, nCode, wParam, lParam)

    def _capture_kb(self, msg, info):
        vk = info.vkCode
        if msg in (WM_KEYUP, WM_SYSKEYUP):
            if vk not in self._kb_down:
                return      # 只配对已录的按下: 防录制开始前就按住的键产生半程事件
            self._kb_down.discard(vk)
        else:
            if vk in self._kb_down:
                return      # 自动重复只记首次按下 (回放语义: 短按一次)
            self._kb_down.add(vk)
        self.events.append({
            "t": self._now(), "ch": "k", "msg": int(msg), "vk": int(vk),
            "scan": int(info.scanCode & 0xFF),
            "ext": 1 if (info.flags & 0x1) else 0,  # LLKHF_EXTENDED
        })


class ScriptPlayer:
    """阶段25: 脚本回放器。Qt 定时器驱动, 按录制时间表把事件重放给全部次窗口。
    与实时同步/录制互斥 (UI 层强制)。中止: Ctrl+Alt+Q 或手动停止;
    中止时经 engine.replay_release_all() 补发未释放按键, 防目标端卡键。"""

    TICK_MS = 10           # 定时器粒度; Windows 时钟约 15.6ms, 时序为近似值
    SPEED_MIN, SPEED_MAX = 0.1, 5.0

    def __init__(self, engine, status_cb=None, on_state=None):
        self.engine = engine
        self.status_cb = status_cb
        self.on_state = on_state      # 播放状态变化回调 (UI 复位用)
        self.playing = False
        self.speed = 1.0
        self.loops = 1                # 0 = 无限循环
        self._events = []
        self._idx = 0
        self._loop = 0
        self._t0 = 0.0
        self._timer = None            # 由 MainWindow 提供 (QTimer 须有 Qt 父对象)
        self._kb_proc = None
        self._kb_hook = None

    def _status(self, text):
        try:
            if self.status_cb:
                self.status_cb(text)
        except Exception:
            pass

    def attach_timer(self, timer):
        self._timer = timer

    def start(self, events, speed, loops):
        if self.playing or not events:
            return False
        err = self.engine.replay_targets_ready()
        if err:
            self._status(err)
            return False
        self._events = events
        self.speed = max(self.SPEED_MIN, min(float(speed or 1.0), self.SPEED_MAX))
        self.loops = max(0, int(loops))
        self._idx = 0
        self._loop = 0
        # 中止钩子: 只识别 Ctrl+Alt+Q, 其余输入一律放行, 绝不干预
        self._kb_proc = HOOKPROC(self._on_kb)
        self._kb_hook = user32.SetWindowsHookExW(
            WH_KEYBOARD_LL, self._kb_proc, None, 0)
        self.playing = True
        self._t0 = _time.monotonic()
        if self._timer:
            self._timer.start(self.TICK_MS)
        AUDIT.write("PLAY_START", "事件 %d 倍速 %.1f 循环 %d 目标 %d"
                    % (len(events), self.speed, self.loops or -1,
                       len(self.engine.targets)))
        return True

    def stop(self, finished=False):
        if not self.playing:
            return
        self.playing = False
        if self._timer:
            self._timer.stop()
        if self._kb_hook:
            user32.UnhookWindowsHookEx(self._kb_hook)
            self._kb_hook = None
        self._kb_proc = None
        n = self.engine.replay_release_all()
        if n:
            AUDIT.write("PLAY_RELEASE", "收尾补发 %d 条释放事件" % n)
        AUDIT.write("PLAY_STOP", "完整结束 %d 轮" % (self._loop + 1) if finished
                    else "手动/紧急中止")
        self._status("回放完成: 共执行 %d 轮" % (self._loop + 1) if finished
                     else "回放已停止")
        cb = self.on_state
        if cb:
            try:
                cb()
            except Exception:
                pass

    def _on_kb(self, nCode, wParam, lParam):
        try:
            if nCode == 0 and self.playing and wParam == WM_KEYDOWN:
                info = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                if (info.vkCode == HOTKEY_VK and not (info.flags & LLKHF_INJECTED)
                        and (user32.GetAsyncKeyState(VK_CONTROL) & 0x8000)
                        and (user32.GetAsyncKeyState(VK_MENU) & 0x8000)):
                    self.stop()
        except Exception:
            pass
        return user32.CallNextHookEx(None, nCode, wParam, lParam)

    def tick(self):
        if not self.playing:
            if self._timer:
                self._timer.stop()
            return
        now = (_time.monotonic() - self._t0) * self.speed
        evs = self._events
        n = len(evs)
        while self._idx < n and evs[self._idx]["t"] <= now:
            self._exec(evs[self._idx])
            self._idx += 1
        if self._idx >= n:
            self._loop += 1
            if self.loops and self._loop >= self.loops:
                self.stop(finished=True)
                return
            self._idx = 0
            self._t0 = _time.monotonic()  # 下一轮计时起点

    def _exec(self, ev):
        try:
            if ev.get("ch") == "m":
                self.engine.replay_mouse(int(ev["msg"]), float(ev["fx"]),
                                         float(ev["fy"]), wp=int(ev.get("wp", 0)),
                                         delta=int(ev.get("delta", 0)))
            else:
                self.engine.replay_kb(int(ev["msg"]), int(ev["vk"]),
                                      int(ev.get("scan", 0)), int(ev.get("ext", 0)))
        except Exception:
            pass  # 单事件异常不中断整轮回放; 投递失败已由 _post 记账


DARK_QSS = """
QMainWindow, QWidget { background-color: #1e1f22; color: #d7d8db; font-size: 13px; }
QTableWidget { background-color: #26282c; color: #d7d8db; gridline-color: #3a3d42;
  selection-background-color: #378ADD; border: 1px solid #3a3d42; border-radius: 6px; }
QHeaderView::section { background-color: #2f3237; color: #d7d8db; border: none;
  padding: 5px; border-right: 1px solid #3a3d42; }
QPushButton { background-color: #2f3237; color: #d7d8db; border: 1px solid #44474d;
  border-radius: 6px; padding: 6px 14px; }
QPushButton:hover { background-color: #378ADD; border-color: #378ADD; }
QPushButton:disabled { color: #6b6e74; background-color: #26282c; }
QPushButton#startBtn { background-color: #0F6E56; border-color: #0F6E56; font-weight: 500; }
QPushButton#startBtn:checked { background-color: #A32D2D; border-color: #A32D2D; }
QComboBox { background-color: #26282c; border: 1px solid #44474d; border-radius: 6px; padding: 4px 8px; }
QComboBox QAbstractItemView { background-color: #26282c; selection-background-color: #378ADD; }
QCheckBox::indicator { width: 15px; height: 15px; }
QLabel#statusLabel { color: #9FE1CB; }
QLabel#brandLabel { font-size: 20px; font-weight: 600; color: #E8EAED; letter-spacing: 2px; }
QLabel#brandSub { font-size: 12px; color: #8B909A; letter-spacing: 4px; }
/* 登录门: 输入框与页签必须跟深色主题一致, 否则会露出系统浅色底 */
QLineEdit { background-color: #26282c; border: 1px solid #44474d; border-radius: 6px;
  padding: 7px 9px; color: #d7d8db; selection-background-color: #378ADD; }
QLineEdit:focus { border-color: #378ADD; }
QTabWidget::pane { border: 1px solid #3a3d42; border-radius: 6px; top: -1px; }
QTabBar::tab { background-color: #26282c; color: #9aa0aa; padding: 7px 22px;
  border: 1px solid #3a3d42; border-bottom: none;
  border-top-left-radius: 6px; border-top-right-radius: 6px; }
QTabBar::tab:selected { background-color: #2f3237; color: #E8EAED; }
QTabBar::tab:hover { color: #E8EAED; }
"""


class _KeyCaptureButton(QPushButton):
    """点一下进入捕获态, 再按任意键即记录其 VK 码 (不用背 VK 表)。"""

    _MODS = (0x10, 0x11, 0x12, 0x5B, 0x5C)   # 单独按修饰键/Win 键不算

    def __init__(self, vk=0, parent=None):
        super().__init__(parent)
        self.vk = int(vk or 0)
        self._armed = False
        self.setMinimumWidth(84)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setToolTip("点一下这个按钮, 然后直接按你要的键")
        self.clicked.connect(self._arm)
        self._refresh()

    def _refresh(self):
        self.setText(_vk_name(self.vk))

    def _arm(self):
        self._armed = True
        self.setText("请按键…")
        self.setFocus(Qt.FocusReason.OtherFocusReason)

    def event(self, ev):
        # 必须在 event 层拦截: TAB 会被 Qt 的焦点链吃掉, 到不了 keyPressEvent
        if self._armed and ev.type() == QEvent.Type.KeyPress:
            return self._take(ev)
        return super().event(ev)

    def _take(self, ev):
        vk = int(ev.nativeVirtualKey() or 0)
        if vk <= 0 or vk in self._MODS:
            return True     # 修饰键单独按不记录, 继续等真正的键
        self.vk = vk
        self._armed = False
        self._refresh()
        return True


class KbRuleDialog(QDialog):
    """按键规则编辑器: 主号按下 → 次窗口执行。"""

    def __init__(self, rules, parent=None):
        super().__init__(parent)
        self.setWindowTitle("按键规则 · 主号按下 → 次窗口执行")
        self.resize(680, 420)
        lay = QVBoxLayout(self)
        tip = QLabel(
            "表内的键由本规则接管: 主号按下时, 次窗口按「次号按」那一列的键执行。\n"
            "表外的键 (WASD 等) 仍按「键盘同步」原样全量转发, 同一个键不会重复。\n"
            "只在主窗口处于前台时生效 —— 在浏览器/聊天框里按这些键不会触发。\n"
            "次窗口仍需先校准, 含密码控件的窗口一律拒绝投递。")
        tip.setWordWrap(True)
        lay.addWidget(tip)

        self.tbl = QTableWidget(0, 5)
        self.tbl.setHorizontalHeaderLabels(["启用", "主号按", "次号按", "延迟", "连发"])
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        hh = self.tbl.horizontalHeader()
        # 延迟/连发用固定宽度: ResizeToContents 只算表头文字, 不算 cellWidget,
        # 会让 QSpinBox 被挤成一条缝 (实测渲染确认)。
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.tbl.setColumnWidth(0, 58)
        self.tbl.setColumnWidth(3, 96)
        self.tbl.setColumnWidth(4, 72)
        lay.addWidget(self.tbl, 1)

        brow = QHBoxLayout()
        b_add = QPushButton("+ 添加")
        b_del = QPushButton("删除选中")
        b_def = QPushButton("恢复默认")
        b_add.clicked.connect(lambda: self._add_row())
        b_del.clicked.connect(self._del_rows)
        b_def.clicked.connect(self._reset)
        for b in (b_add, b_del, b_def):
            brow.addWidget(b)
        brow.addStretch(1)
        lay.addLayout(brow)

        ok = QPushButton("确定")
        ok.setDefault(True)
        cancel = QPushButton("取消")
        ok.clicked.connect(self.accept)
        cancel.clicked.connect(self.reject)
        frow = QHBoxLayout()
        frow.addStretch(1)
        frow.addWidget(ok)
        frow.addWidget(cancel)
        lay.addLayout(frow)

        for r in (rules or []):
            self._add_row(r)
        if self.tbl.rowCount() == 0:
            self._reset()
        self.tbl.clearSelection()
        self.tbl.setCurrentCell(-1, -1)   # 避免首行带一块选中底色, 看着像异常

    def _add_row(self, rule=None):
        rule = rule or {"on": True, "src": 0, "dst": 0, "delay": 0, "times": 1}
        r = self.tbl.rowCount()
        self.tbl.insertRow(r)
        it = QTableWidgetItem()
        it.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled
                    | Qt.ItemFlag.ItemIsSelectable)
        it.setCheckState(Qt.CheckState.Checked if rule.get("on", True)
                         else Qt.CheckState.Unchecked)
        self.tbl.setItem(r, 0, it)
        self.tbl.setCellWidget(r, 1, _KeyCaptureButton(int(rule.get("src", 0) or 0)))
        self.tbl.setCellWidget(r, 2, _KeyCaptureButton(int(rule.get("dst", 0) or 0)))
        sd = QSpinBox()
        sd.setRange(0, RULE_MAX_DELAY_MS)
        sd.setSingleStep(10)
        sd.setValue(max(0, min(RULE_MAX_DELAY_MS, int(rule.get("delay", 0) or 0))))
        sd.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sd.setStyleSheet("QSpinBox{border:1px solid #44474d;border-radius:4px;"
                         "padding:1px 3px;background:#26282c;color:#d7d8db;}")
        self.tbl.setCellWidget(r, 3, sd)
        sn = QSpinBox()
        sn.setRange(1, RULE_MAX_TIMES)
        sn.setValue(max(1, min(RULE_MAX_TIMES, int(rule.get("times", 1) or 1))))
        sn.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sn.setStyleSheet("QSpinBox{border:1px solid #44474d;border-radius:4px;"
                         "padding:1px 3px;background:#26282c;color:#d7d8db;}")
        self.tbl.setCellWidget(r, 4, sn)
        self.tbl.setRowHeight(r, 34)

    def _del_rows(self):
        rows = sorted({i.row() for i in self.tbl.selectedIndexes()}, reverse=True)
        if not rows and self.tbl.rowCount():
            rows = [self.tbl.rowCount() - 1]   # 没选中就删最后一行
        for r in rows:
            self.tbl.removeRow(r)

    def _reset(self):
        self.tbl.setRowCount(0)
        for r in DEFAULT_KB_RULES:
            self._add_row(dict(r))

    def result_rules(self):
        """读出表格内容。主号键或次号键没设置的整行丢弃 (不打断用户)。"""
        out = []
        for r in range(self.tbl.rowCount()):
            it = self.tbl.item(r, 0)
            on = bool(it and it.checkState() == Qt.CheckState.Checked)
            sb = self.tbl.cellWidget(r, 1)
            db = self.tbl.cellWidget(r, 2)
            sd = self.tbl.cellWidget(r, 3)
            sn = self.tbl.cellWidget(r, 4)
            src = int(getattr(sb, "vk", 0) or 0)
            dst = int(getattr(db, "vk", 0) or 0)
            if src <= 0 or dst <= 0:
                continue
            out.append({"on": on, "src": src, "dst": dst,
                        "delay": int(sd.value()) if sd else 0,
                        "times": int(sn.value()) if sn else 1})
        return out


def _pwd_problem(pw, label="密码"):
    """与服务端 pwd_problem 同规则的前端预检 (少一次"填完才知道不合规")。

    安全码与密码用同一把尺子, 只是最长 32 位; 传 label="安全码" 即可复用。
    """
    pw = pw or ""
    if len(pw) < 8:
        return "%s至少 8 位" % label
    if label == "安全码" and len(pw) > 32:
        return "安全码最多 32 位"
    if len(pw) > 64:
        return "%s过长" % label
    if not any(c.isalpha() and c.isascii() for c in pw) or not any(c.isdigit() for c in pw):
        return "%s需同时包含字母和数字" % label
    if pw != pw.strip():
        return "%s首尾不能是空格" % label
    return ""


class ForgotDialog(QDialog):
    """忘记密码: 用注册时设的安全码自助重置。

    为什么不让用户点"发送邮件/短信": 这套后台跑在局域网、没有邮件短信通道,
    安全码就是当初留给用户的那把备用钥匙。实在忘了安全码, 还有客服在管理台
    重置密码这条人工兜底 (管理台会员列表能看"安全码 已设/未设")。
    """

    def __init__(self, lic, parent=None, username=""):
        super().__init__(parent)
        self.lic = lic
        self.setWindowTitle("找回密码")
        self.setFixedSize(430, 330)
        v = QVBoxLayout(self)
        v.setSpacing(8)

        tip = QLabel("输入注册时设置的安全码即可重置密码。\n"
                     "重置后, 该账号在所有设备上的登录都会失效, 需要重新登录。")
        tip.setWordWrap(True)
        v.addWidget(tip)

        self.f_user = QLineEdit(username)
        self.f_user.setPlaceholderText("用户名")
        self.f_rc = QLineEdit()
        self.f_rc.setPlaceholderText("安全码 (注册时设置的, 8-32 位)")
        self.f_pw = QLineEdit()
        self.f_pw.setPlaceholderText("新密码 (至少 8 位, 含字母和数字)")
        self.f_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.f_pw2 = QLineEdit()
        self.f_pw2.setPlaceholderText("再输一次新密码")
        self.f_pw2.setEchoMode(QLineEdit.EchoMode.Password)
        self.f_pw2.returnPressed.connect(self.do_reset)
        for w in (self.f_user, self.f_rc, self.f_pw, self.f_pw2):
            v.addWidget(w)

        self.msg = QLabel("安全码记不得了? 联系客服在管理台重置密码。")
        self.msg.setObjectName("statusLabel")
        self.msg.setWordWrap(True)
        v.addWidget(self.msg)

        row = QHBoxLayout()
        row.addStretch(1)
        b = QPushButton("重置密码")
        b.setDefault(True)
        b.clicked.connect(self.do_reset)
        c = QPushButton("取消")
        c.clicked.connect(self.reject)
        row.addWidget(b)
        row.addWidget(c)
        v.addLayout(row)
        self.f_user.setFocus()

    def do_reset(self):
        u = self.f_user.text().strip()
        rc = self.f_rc.text()
        p = self.f_pw.text()
        p2 = self.f_pw2.text()
        if not u or not rc or not p:
            self.msg.setText("请填写用户名、安全码和新密码")
            return
        prob = _pwd_problem(p)
        if prob:
            self.msg.setText(prob)
            return
        if p != p2:
            self.msg.setText("两次输入的新密码不一致")
            return
        self.msg.setText("正在提交...")
        QApplication.processEvents()
        ok, txt = self.lic.forgot(u, rc, p)
        self.msg.setText(txt)
        if ok:
            AUDIT.write("RECOVER", "找回密码 %s" % u)
            QMessageBox.information(self, "密码已重置",
                                    "密码已重置, 请用新密码登录。\n"
                                    "如果这个账号在别的电脑上也登录过, 那些登录已失效。")
            self.setProperty("reset_user", u)
            self.accept()


class AccountSecurityDialog(QDialog):
    """账号安全: 改密码 / 设置安全码 (两条都要求验证当前密码)。"""

    def __init__(self, lic, parent=None):
        super().__init__(parent)
        self.lic = lic
        self.setWindowTitle("账号安全")
        self.setFixedSize(430, 520)
        v = QVBoxLayout(self)
        v.setSpacing(8)
        head = QLabel("当前账号: %s" % (lic.user or "-"))
        v.addWidget(head)

        g1 = QGroupBox("修改密码")
        f1 = QVBoxLayout(g1)
        self.p_old = QLineEdit(); self.p_old.setPlaceholderText("原密码")
        self.p_old.setEchoMode(QLineEdit.EchoMode.Password)
        self.p_new = QLineEdit(); self.p_new.setPlaceholderText("新密码 (至少 8 位, 含字母和数字)")
        self.p_new.setEchoMode(QLineEdit.EchoMode.Password)
        self.p_new2 = QLineEdit(); self.p_new2.setPlaceholderText("再输一次新密码")
        self.p_new2.setEchoMode(QLineEdit.EchoMode.Password)
        b1 = QPushButton("修改密码")
        b1.clicked.connect(self.do_change_pw)
        self.m1 = QLabel(""); self.m1.setObjectName("statusLabel"); self.m1.setWordWrap(True)
        for w in (self.p_old, self.p_new, self.p_new2, b1, self.m1):
            f1.addWidget(w)
        v.addWidget(g1)

        g2 = QGroupBox("安全码 (忘记密码时用它自助重置)")
        f2 = QVBoxLayout(g2)
        self.r_pw = QLineEdit(); self.r_pw.setPlaceholderText("当前密码 (用于确认身份)")
        self.r_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.r_code = QLineEdit()
        self.r_code.setPlaceholderText("安全码 8-32 位, 含字母和数字")
        self.r_code2 = QLineEdit()
        self.r_code2.setPlaceholderText("再输一次安全码")
        b2 = QPushButton("保存安全码")
        b2.clicked.connect(self.do_set_rc)
        self.m2 = QLabel("已设置" if lic.rc_set else "尚未设置, 忘记密码只能联系客服")
        self.m2.setObjectName("statusLabel"); self.m2.setWordWrap(True)
        for w in (self.r_pw, self.r_code, self.r_code2, b2, self.m2):
            f2.addWidget(w)
        v.addWidget(g2)

        row = QHBoxLayout()
        row.addStretch(1)
        c = QPushButton("关闭")
        c.clicked.connect(self.accept)
        row.addWidget(c)
        v.addLayout(row)

    def do_change_pw(self):
        o, n, n2 = self.p_old.text(), self.p_new.text(), self.p_new2.text()
        if not o or not n:
            self.m1.setText("请填写原密码和新密码"); return
        prob = _pwd_problem(n)
        if prob:
            self.m1.setText(prob); return
        if n != n2:
            self.m1.setText("两次输入的新密码不一致"); return
        if n == o:
            self.m1.setText("新密码不能与原密码相同"); return
        ok, txt = self.lic.change_password(o, n)
        self.m1.setText(txt)
        if ok:
            AUDIT.write("PASSWORD", "修改密码 %s" % (self.lic.user or ""))
            for w in (self.p_old, self.p_new, self.p_new2):
                w.clear()

    def do_set_rc(self):
        pw, c, c2 = self.r_pw.text(), self.r_code.text(), self.r_code2.text()
        if not pw or not c:
            self.m2.setText("请填写当前密码和安全码"); return
        prob = _pwd_problem(c, "安全码")
        if prob:
            self.m2.setText(prob); return
        if c != c2:
            self.m2.setText("两次输入的安全码不一致"); return
        ok, txt = self.lic.set_recovery_code(pw, c)
        self.m2.setText(txt)
        if ok:
            AUDIT.write("RECOVERY_CODE", "设置安全码 %s" % (self.lic.user or ""))
            self.r_pw.clear(); self.r_code.clear(); self.r_code2.clear()


class AccountGate(QDialog):
    """登录门: 账号密码登录 / 注册。

    为什么不再让用户输卡密: 卡密是"一次性凭证", 而账号是"持续关系" ——
    用户只需要记住一个用户名和密码, 到期续费、换机、查剩余时间都在这一个身份上。
    卡密降级为充值码, 登录后在主界面兑换。
    """

    def __init__(self, lic, reason=""):
        super().__init__()
        self.lic = lic
        self.setWindowTitle("阿信电脑同步器 · 登录")
        self.setFixedSize(470, 480)
        lay = QVBoxLayout(self)
        lay.setSpacing(8)

        brand = QLabel("阿信电脑同步器")
        brand.setObjectName("brandLabel")
        brand.setAlignment(Qt.AlignCenter)
        lay.addWidget(brand)
        sub = QLabel("账号登录 / 注册")
        sub.setObjectName("brandSub")
        sub.setAlignment(Qt.AlignCenter)
        lay.addWidget(sub)

        info = QLabel("机器码: %s" % lic.machine)
        info.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(info)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_login(), "登录")
        self.tabs.addTab(self._build_register(), "注册")
        lay.addWidget(self.tabs, 0)

        self.msg = QLabel(reason)
        self.msg.setObjectName("statusLabel")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        lay.addStretch(1)

        # 记住的是"用户名", 不是密码 —— 密码永不落盘
        rec = lic.read_token()
        if rec:
            self.login_user.setText(rec.get("user", ""))
            self.login_pw.setFocus()
        else:
            self.login_user.setFocus()

    # ---------- 页签 ----------
    def _build_login(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setSpacing(6)
        self.login_user = QLineEdit()
        self.login_user.setPlaceholderText("用户名")
        self.login_pw = QLineEdit()
        self.login_pw.setPlaceholderText("密码")
        self.login_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_pw.returnPressed.connect(self.do_login)
        b = QPushButton("登录")
        b.setDefault(True)
        b.clicked.connect(self.do_login)
        v.addWidget(self.login_user)
        v.addWidget(self.login_pw)
        v.addWidget(b)
        row = QHBoxLayout()
        row.addStretch(1)
        self.btn_forgot = QPushButton("忘记密码")
        self.btn_forgot.setFlat(True)
        self.btn_forgot.setStyleSheet("color:#2f6fdd; text-decoration:underline;")
        self.btn_forgot.clicked.connect(self.open_forgot)
        row.addWidget(self.btn_forgot)
        v.addLayout(row)
        tip = QLabel("换电脑登录会自动绑定新机器 (扣 6 小时, 最多 3 次)。\n"
                     "忘记密码: 注册时设过「安全码」可自助重置, 否则联系客服。")
        tip.setWordWrap(True)
        tip.setStyleSheet("color:#8B909A;")
        v.addWidget(tip)
        v.addStretch(1)
        return w

    def _build_register(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setSpacing(6)
        self.reg_user = QLineEdit()
        self.reg_user.setPlaceholderText("用户名 (3-24 位字母数字 _ . -)")
        self.reg_pw = QLineEdit()
        self.reg_pw.setPlaceholderText("密码 (至少 8 位, 含字母和数字)")
        self.reg_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_pw2 = QLineEdit()
        self.reg_pw2.setPlaceholderText("再输一次密码")
        self.reg_pw2.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_rc = QLineEdit()
        self.reg_rc.setPlaceholderText("安全码 (8-32 位, 含字母和数字, 找回密码用)")
        self.reg_rc2 = QLineEdit()
        self.reg_rc2.setPlaceholderText("再输一次安全码")
        self.reg_rc2.returnPressed.connect(self.do_register)
        b = QPushButton("注册并登录")
        b.clicked.connect(self.do_register)
        v.addWidget(self.reg_user)
        v.addWidget(self.reg_pw)
        v.addWidget(self.reg_pw2)
        v.addWidget(self.reg_rc)
        v.addWidget(self.reg_rc2)
        v.addWidget(b)
        tip = QLabel("安全码 = 忘记密码时自助重置的凭据, 请记在只有你知道的地方\n"
                     "(它和密码分开存, 不要设成一样的)。注册即赠 3 小时体验时长。")
        tip.setWordWrap(True)
        tip.setStyleSheet("color:#8B909A;")
        v.addWidget(tip)
        v.addStretch(1)
        return w

    def open_forgot(self):
        dlg = ForgotDialog(self.lic, self, self.login_user.text().strip())
        if dlg.exec() == QDialog.Accepted:
            self.login_user.setText(dlg.property("reset_user") or self.login_user.text())
            self.login_pw.clear()
            self.login_pw.setFocus()
            self.msg.setText("密码已重置, 请输入新密码登录")

    # ---------- 动作 ----------
    def do_login(self):
        u = self.login_user.text().strip()
        p = self.login_pw.text()
        if not u or not p:
            self.msg.setText("请输入用户名和密码")
            return
        self.msg.setText("正在登录...")
        ok, txt = self.lic.login(u, p)
        self.msg.setText(txt)
        if ok:
            AUDIT.write("LOGIN", "账号登录 %s" % u)
            self.accept()

    def do_register(self):
        u = self.reg_user.text().strip()
        p = self.reg_pw.text()
        p2 = self.reg_pw2.text()
        rc = self.reg_rc.text()
        rc2 = self.reg_rc2.text()
        if not u or not p:
            self.msg.setText("请填写用户名和密码")
            return
        prob = _pwd_problem(p)
        if prob:
            self.msg.setText(prob)
            return
        if p != p2:
            self.msg.setText("两次输入的密码不一致")
            return
        if not rc:
            self.msg.setText("请设置安全码 (忘记密码时用它重置, 建议记在手机备忘录里)")
            self.reg_rc.setFocus()
            return
        prob = _pwd_problem(rc, "安全码")
        if prob:
            self.msg.setText(prob)
            return
        if rc != rc2:
            self.msg.setText("两次输入的安全码不一致")
            return
        if rc == p:
            self.msg.setText("安全码不能和密码相同")
            return
        self.msg.setText("正在注册...")
        ok, txt = self.lic.register(u, p, rc)
        self.msg.setText(txt)
        if ok:
            AUDIT.write("REGISTER", "注册 %s" % u)
            self.accept()


class RedeemDialog(QDialog):
    """卡密兑换: 把卡密时长充进当前账号。"""

    def __init__(self, lic, parent=None):
        super().__init__(parent)
        self.lic = lic
        self.setWindowTitle("卡密兑换")
        self.setFixedSize(420, 200)
        v = QVBoxLayout(self)
        tip = QLabel("输入购买的卡密, 兑换后时长直接充进当前账号。\n"
                     "卡密只能兑换一次, 兑换后不可转移。")
        tip.setWordWrap(True)
        v.addWidget(tip)
        self.edit = QLineEdit()
        self.edit.setPlaceholderText("HZ-XXXX-XXXX-XXXX")
        self.edit.returnPressed.connect(self.do_redeem)
        v.addWidget(self.edit)
        self.msg = QLabel("")
        self.msg.setObjectName("statusLabel")
        self.msg.setWordWrap(True)
        v.addWidget(self.msg)
        row = QHBoxLayout()
        row.addStretch(1)
        b = QPushButton("兑换")
        b.setDefault(True)
        b.clicked.connect(self.do_redeem)
        c = QPushButton("取消")
        c.clicked.connect(self.reject)
        row.addWidget(b)
        row.addWidget(c)
        v.addLayout(row)

    def do_redeem(self):
        key = self.edit.text().strip().upper()
        if not key:
            self.msg.setText("请输入卡密")
            return
        self.msg.setText("正在兑换...")
        ok, txt = self.lic.redeem(key)
        self.msg.setText(txt)
        if ok:
            AUDIT.write("REDEEM", key[:4] + "..." + key[-4:])
            QTimer.singleShot(700, self.accept)


class PlanDialog(QDialog):
    """套餐购买: 选套餐 → 生成订单 → 支付 → 开通。

    金额只在服务端算: 客户端只传 plan_id, 这里显示的价格也是服务端下发的,
    界面上没有任何"可被改价"的字段。
    """

    def __init__(self, lic, parent=None):
        super().__init__(parent)
        self.lic = lic
        self.setWindowTitle("套餐与充值")
        self.resize(640, 460)
        self._order = None
        v = QVBoxLayout(self)

        # 打开时先拉一次最新剩余时间, 免得刚充完值还显示旧数字
        try:
            if lic.token:
                lic.me()
        except Exception:
            pass

        head = QLabel("当前账号: %s · %s" % (lic.user or "-", self._remain_text()))
        head.setObjectName("statusLabel")
        v.addWidget(head)
        self.head = head

        self.tbl = QTableWidget(0, 4)
        self.tbl.setHorizontalHeaderLabels(["套餐", "时长", "价格", "说明"])
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tbl.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        hh = self.tbl.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.tbl.setColumnWidth(0, 110)
        self.tbl.setColumnWidth(1, 90)
        self.tbl.setColumnWidth(2, 110)
        v.addWidget(self.tbl, 1)

        self.plans = lic.plans()
        for p in self.plans:
            r = self.tbl.rowCount()
            self.tbl.insertRow(r)
            self.tbl.setItem(r, 0, QTableWidgetItem(p.get("name", "")))
            self.tbl.setItem(r, 1, QTableWidgetItem("%d 天" % int(p.get("days", 0))))
            self.tbl.setItem(r, 2, QTableWidgetItem("¥ %s" % p.get("price_yuan", "")))
            self.tbl.setItem(r, 3, QTableWidgetItem(p.get("tag", "")))
            self.tbl.setRowHeight(r, 32)
        if self.plans:
            self.tbl.selectRow(0)
        else:
            self.tbl.setRowCount(1)
            self.tbl.setItem(0, 0, QTableWidgetItem("套餐加载失败"))
            self.tbl.setItem(0, 3, QTableWidgetItem("请检查网络或授权服务器是否运行"))

        # 支付区 (下单后才显示)
        self.pay_box = QWidget()
        pv = QVBoxLayout(self.pay_box)
        pv.setContentsMargins(0, 0, 0, 0)
        self.pay_info = QLabel("")
        self.pay_info.setWordWrap(True)
        pv.addWidget(self.pay_info)
        prow = QHBoxLayout()
        self.btn_mock = QPushButton("模拟支付成功 (测试)")
        self.btn_mock.clicked.connect(self.do_mock_pay)
        self.btn_open = QPushButton("打开支付页面")
        self.btn_open.clicked.connect(self.do_open_pay)
        self.btn_check = QPushButton("我已完成支付")
        self.btn_check.clicked.connect(self.do_check_pay)
        for b in (self.btn_mock, self.btn_open, self.btn_check):
            b.hide()
            prow.addWidget(b)
        prow.addStretch(1)
        pv.addLayout(prow)
        self.pay_box.hide()
        v.addWidget(self.pay_box)

        self.msg = QLabel("")
        self.msg.setObjectName("statusLabel")
        self.msg.setWordWrap(True)
        v.addWidget(self.msg)

        row = QHBoxLayout()
        self.btn_buy = QPushButton("立即购买")
        self.btn_buy.clicked.connect(self.do_buy)
        self.btn_redeem = QPushButton("卡密兑换…")
        self.btn_redeem.clicked.connect(self.do_redeem)
        close = QPushButton("关闭")
        close.clicked.connect(self.reject)
        row.addWidget(self.btn_buy)
        row.addWidget(self.btn_redeem)
        row.addStretch(1)
        row.addWidget(close)
        v.addLayout(row)

    def _remain_text(self):
        if self.lic.remaining > 0:
            return "剩余 %s" % _fmt_secs(self.lic.remaining)
        return "未开通 / 已到期"

    def _refresh_head(self):
        self.head.setText("当前账号: %s · %s" % (self.lic.user or "-", self._remain_text()))

    def do_buy(self):
        rows = self.tbl.selectionModel().selectedRows() if self.tbl.selectionModel() else []
        if not rows:
            self.msg.setText("请先选择一个套餐")
            return
        idx = rows[0].row()
        if idx >= len(self.plans):
            return
        plan = self.plans[idx]
        self.msg.setText("正在创建订单...")
        ok, txt, d = self.lic.create_order(plan.get("id", ""))
        if not ok:
            self.msg.setText(txt)
            return
        self._order = d
        self.msg.setText("订单已创建, 请完成支付")
        pay = d.get("pay") or {}
        self.pay_info.setText(
            "订单号: %s\n套餐: %s · %d 天\n应付金额: ¥ %s\n支付通道: %s"
            % (d.get("order_id", ""), d.get("plan_name", ""), int(d.get("days", 0)),
               d.get("amount_yuan", ""), pay.get("provider", "-")))
        self.pay_box.show()
        self.btn_buy.setEnabled(False)
        # 只有 mock 通道才显示"模拟支付"; 真实通道下这个按钮根本不该存在
        self.btn_mock.setVisible(pay.get("provider") == "mock")
        self.btn_open.setVisible(pay.get("provider") == "epay" and bool(pay.get("url")))
        self.btn_check.setVisible(pay.get("provider") != "mock")

    def do_mock_pay(self):
        if not self._order:
            return
        ok, txt = self.lic.mock_pay(self._order.get("order_id", ""))
        self.msg.setText(txt)
        if ok:
            self._refresh_head()
            AUDIT.write("PAY", "测试支付成功 订单=%s" % self._order.get("order_id", ""))
            QTimer.singleShot(600, self.accept)

    def do_open_pay(self):
        pay = (self._order or {}).get("pay") or {}
        url = pay.get("url", "")
        if not url:
            self.msg.setText("支付链接为空, 请检查支付通道配置")
            return
        try:
            from PySide6.QtGui import QDesktopServices
            from PySide6.QtCore import QUrl
            QDesktopServices.openUrl(QUrl(url))
            self.msg.setText("已在浏览器打开支付页面, 支付完成后点「我已完成支付」")
        except Exception as e:
            self.msg.setText("打开支付页面失败: %s" % e)

    def do_check_pay(self):
        if not self._order:
            return
        d = self.lic.query_order(self._order.get("order_id", ""))
        if not d:
            self.msg.setText("查询失败, 请稍后再试")
            return
        if d.get("status") == "paid":
            self.lic._apply(d)
            self._refresh_head()
            self.msg.setText("支付成功, 套餐已开通")
            QTimer.singleShot(600, self.accept)
        else:
            self.msg.setText("尚未收到支付结果, 请稍候再点一次")

    def do_redeem(self):
        dlg = RedeemDialog(self.lic, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._refresh_head()
            self.msg.setText("兑换成功, 剩余 %s" % _fmt_secs(self.lic.remaining))


def _acquire_single_instance():
    """单实例互斥锁: 防双开导致双重转发"""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    h = kernel32.CreateMutexW(None, False, "Global\\AxinSyncerMutex")
    return not (h and ctypes.get_last_error() == 183)  # ERROR_ALREADY_EXISTS


class MainWindow(QMainWindow):
    # 心跳结果由工作线程通过信号回传主线程 (跨线程自动排队), 工作线程绝不接触 UI
    hb_result = Signal(bool, str, int)

    def __init__(self, lic):
        super().__init__()
        self.lic = lic
        self._ui_lock = False   # 表格回填期间屏蔽 itemChanged (防勾选框被程序化写入时误触发)
        self.engine = SyncEngine(self._own_hwnd, self._set_status)
        # 阶段25: 录制与回放 (与实时同步互斥, 见 toggle_sync / toggle_record / toggle_play)
        self.recorder = ActionRecorder(self._set_status)
        self.player = ScriptPlayer(self.engine, self._set_status, self._play_state_reset)
        self._play_timer = QTimer(self)
        self._play_timer.timeout.connect(self.player.tick)
        self.player.attach_timer(self._play_timer)
        self.setWindowTitle("阿信电脑同步器")
        self.resize(640, 460)
        self._build_ui()
        self.refresh_windows()
        self.refresh_scripts()
        self.restore_config()
        # ---- F-03 心跳线程控制 ----
        self._hb_inflight = False   # 单飞: 上一次未回来就不再发起, 防线程堆积
        self._closing = False       # 关闭中: 不再处理任何回传结果
        self.hb_result.connect(self._hb_done)
        # 授权心跳: 每 60s 验证一次, 失效即停功能并弹登录门
        self._hb = QTimer(self)
        self._hb.timeout.connect(self._heartbeat)
        self._hb.start(HEARTBEAT_MS)
        self._heartbeat()
        # 投递状态刷新 (1s): 只更新表格单元格, 不做网络/阻塞操作
        self._st = QTimer(self)
        self._st.timeout.connect(self._refresh_delivery_states)
        self._st.start(1000)
        # 持续跟随键 (F5): 不在构造期启动, 由 toggle_sync 按勾选状态启停;
        # 停止/关窗必须同时停掉, 否则关窗后仍会向已失效句柄投递。
        self._f5 = QTimer(self)
        self._f5.timeout.connect(self._follow_f5_tick)

    # ---------- F-03 授权心跳 (异步) ----------
    def _heartbeat(self):
        """发起心跳。真正的网络请求在工作线程执行 —— 主线程(也就是输入钩子回调
        所在的线程)绝不能被阻塞, 否则同步期间输入转发会停滞 (阶段3-6 T-08 实测)。"""
        if self._hb_inflight or self._closing:
            return  # 单飞保护: 上一次还没回来就不发起新的, 绝不堆叠线程
        self._hb_inflight = True
        t = _threading.Thread(target=self._hb_run, name="axin-hb", daemon=True)
        t.start()

    def _hb_run(self):
        """工作线程: 只做网络请求, 结果通过信号回传, 不接触任何 UI 对象"""
        try:
            ok, txt = self.lic.heartbeat()
            remain = int(self.lic.remaining or 0)
        except Exception as e:
            ok, txt, remain = False, "心跳异常: %s" % e, 0
        self.hb_result.emit(bool(ok), str(txt), remain)

    def _hb_done(self, ok, txt, remain):
        """主线程: 处理心跳结果"""
        self._hb_inflight = False
        if self._closing:
            return
        title = "阿信电脑同步器"
        if self.lic.user:
            title += " | %s" % self.lic.user
        if 0 < remain < 10**7:
            title += " | 剩余 %s" % _fmt_secs(remain)
        elif getattr(self.lic, "expires_at", 0):
            # 断网时服务端算不出"剩余秒数", 但本地缓存的到期日仍可用 ——
            # 直接显示出来, 让用户一眼确认"账号还在有效期内"。
            title += " | 到期 %s" % _time.strftime(
                "%Y-%m-%d", _time.localtime(self.lic.expires_at))
        self.setWindowTitle(title)
        self._refresh_account()
        if ok:
            return
        self.engine.stop()
        self.start_btn.setChecked(False)
        self.start_btn.setText("开始 (紧急停止快捷键: Ctrl+Alt+Q)")
        AUDIT.write("LOGIN_DENY", txt[:40])
        gate = AccountGate(self.lic, "登录已失效: %s" % txt)
        if gate.exec() != QDialog.DialogCode.Accepted:
            self.close()

    def _refresh_account(self):
        """刷新顶部的账号/剩余时间显示 (每秒随心跳一起更新)"""
        if not hasattr(self, "acct_label"):
            return
        if not self.lic.user:
            self.acct_label.setText("未登录")
            return
        if self.lic.remaining > 0:
            st = "剩余 %s" % _fmt_secs(self.lic.remaining)
        else:
            st = "已到期, 请续费"
        self.acct_label.setText("账号 %s · %s" % (self.lic.user, st))

    def open_plans(self):
        """套餐 / 充值: 购买套餐、兑换卡密都在这里"""
        dlg = PlanDialog(self.lic, self)
        dlg.exec()
        self._refresh_account()
        self._set_status("当前剩余 %s" % _fmt_secs(self.lic.remaining)
                         if self.lic.remaining > 0 else "套餐未开通或已到期")

    def open_security(self):
        """账号安全: 改密码 / 设安全码"""
        dlg = AccountSecurityDialog(self.lic, self)
        dlg.exec()
        self._refresh_account()

    def do_logout(self):
        ans = QMessageBox.question(self, "退出登录",
                                   "退出后需要重新输入账号密码才能使用。确认退出?",
                                   QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if ans != QMessageBox.Yes:
            return
        self.engine.stop()
        self.lic.logout()
        AUDIT.write("LOGOUT", "用户主动退出")
        self.close()

    # ---------- UI ----------
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(8)
        layout.setContentsMargins(14, 14, 14, 14)

        # 账号行: 登录身份 + 剩余时间 + 套餐入口
        row0 = QHBoxLayout()
        self.acct_label = QLabel("")
        self.acct_label.setObjectName("statusLabel")
        btn_plan = QPushButton("套餐 / 充值")
        btn_plan.setToolTip("购买套餐、兑换卡密、查看剩余时间")
        btn_plan.clicked.connect(self.open_plans)
        btn_sec = QPushButton("账号安全")
        btn_sec.setToolTip("修改密码、设置安全码 (忘记密码时自助重置)")
        btn_sec.clicked.connect(self.open_security)
        btn_logout = QPushButton("退出登录")
        btn_logout.clicked.connect(self.do_logout)
        row0.addWidget(self.acct_label, 1)
        row0.addWidget(btn_plan)
        row0.addWidget(btn_sec)
        row0.addWidget(btn_logout)
        layout.addLayout(row0)
        self._refresh_account()

        # 窗口选择行
        row1 = QHBoxLayout()
        self.win_combo = QComboBox()
        self.win_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.win_combo.setMinimumContentsLength(30)
        btn_refresh = QPushButton("刷新")
        btn_main = QPushButton("设为主窗口")
        btn_sub = QPushButton("添加为次窗口")
        btn_refresh.clicked.connect(self.refresh_windows)
        btn_main.clicked.connect(self.set_main)
        btn_sub.clicked.connect(self.add_sub)
        row1.addWidget(self.win_combo, 1)
        row1.addWidget(btn_refresh)
        row1.addWidget(btn_main)
        row1.addWidget(btn_sub)
        layout.addLayout(row1)

        # 窗口列表
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["句柄", "标题", "角色", "投递(API层)", "自绘窗口放行"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.itemChanged.connect(self._on_table_item_changed)
        layout.addWidget(self.table, 1)

        btn_del = QPushButton("移除选中项")
        btn_del.clicked.connect(self.remove_selected)
        layout.addWidget(btn_del)

        # 同步选项行
        row2 = QHBoxLayout()
        self.chk_mouse = QCheckBox("鼠标同步")
        self.chk_kb = QCheckBox("键盘同步")
        self.chk_char = QCheckBox("补发字符(双字时开)")
        self.chk_mouse.setChecked(True)
        self.chk_kb.setChecked(True)
        self.chk_kb.setToolTip(
            "输入门控: 只有当主窗口处于前台时, 键盘输入才会被转发。\n"
            "在别的程序(聊天/浏览器/密码框)里打字不会被转发到次窗口。\n\n"
            "校准: 每个次窗口需先切到前台一次(点一下它的输入区),\n"
            "工具会记住它真正的输入控件; 未校准的次窗口不会收到键盘\n"
            "(状态列会显示\"键盘未转发:未校准\")。\n\n"
            "含密码输入框的窗口不会出现在可选列表中。")
        self.chk_char.setToolTip("游戏完全收不到打字内容时再勾选, 普通程序勾了会重复输入")
        # 持续跟随键: 开始后由工具按固定间隔向所有次窗口补发 F5
        self.chk_f5 = QCheckBox("次窗口持续F5")
        self.chk_f5.setToolTip(
            "开始同步后, 每 1 秒向所有次窗口各补发一次 F5 (按下+抬起)。\n\n"
            "与「键盘同步」的区别:\n"
            "· 键盘同步 = 转发你按的键, 且仅当主窗口在前台;\n"
            "· 持续F5 = 工具自己造键, 次窗口在后台也会收到。\n\n"
            "仍然会被拒绝的情况 (与键盘同步同一套闸口):\n"
            "· 该窗口尚未校准 → 先把它切到前台点一下输入区;\n"
            "· 该窗口含密码输入控件 → 永久拒绝, 不给放行开关。\n\n"
            "注意: 开启期间, 表格「投递(API层)」列每秒都会被 F5 的投递结果\n"
            "刷新一次, 会盖住你自己按键的真实状态。要诊断键盘是否送达,\n"
            "请先取消本勾选再看。\n\n"
            "F5 在部分游戏里是刷新/重载, 频繁触发可能产生副作用, 请先在单窗口验证。")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["模式1 - PostMessage (异步)", "模式2 - SendMessage (同步)"])
        row2.addWidget(self.chk_mouse)
        row2.addWidget(self.chk_kb)
        row2.addWidget(self.chk_char)
        row2.addWidget(self.chk_f5)
        row2.addWidget(QLabel("转发模式:"))
        row2.addWidget(self.mode_combo, 1)
        layout.addLayout(row2)

        # 开始/停止
        row3 = QHBoxLayout()
        self.start_btn = QPushButton("开始 (紧急停止快捷键: Ctrl+Alt+Q)")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.setCheckable(True)
        self.start_btn.clicked.connect(self.toggle_sync)
        row3.addWidget(self.start_btn, 2)
        # 按键规则: 表内键由本规则接管 (可映射/延迟/连发), 表外键仍全量转发
        self.kb_rule_btn = QPushButton()
        self.kb_rule_btn.setToolTip(
            "配置「主号按下某个键 → 次窗口按另一个键」。\n\n"
            "默认已填 1/2/3/4/5/TAB, 与原来的键盘同步效果一致;\n"
            "改「次号按」那一列即可做键位映射 (例如主号按 1, 次号按 3)。\n\n"
            "规则表内的键由本规则独占投递, 不会和键盘同步重复。\n"
            "仅当主窗口在前台时生效。含密码控件的窗口一律拒绝。")
        self.kb_rule_btn.clicked.connect(self.open_kb_rules)
        row3.addWidget(self.kb_rule_btn, 1)
        self._refresh_rule_btn()
        layout.addLayout(row3)

        # 阶段25: 录制 / 回放 —— 主窗口录制动作, 所有次窗口执行
        row4 = QHBoxLayout()
        self.rec_btn = QPushButton("● 开始录制")
        self.rec_btn.setCheckable(True)
        self.rec_btn.setToolTip(
            "在主窗口内操作, 工具只记录不转发:\n"
            "· 鼠标: 只录主窗口客户区内的动作 (拖出窗口的部分不录)\n"
            "· 键盘: 只录主窗口为前台时的按键 (按住自动重复只记一次)\n\n"
            "停止: 再点一次本按钮, 或 Ctrl+Alt+Q。\n"
            "录制结果自动存入程序目录的 scripts/ 文件夹。")
        self.rec_btn.clicked.connect(self.toggle_record)
        self.play_btn = QPushButton("▶ 执行到所有次窗口")
        self.play_btn.setCheckable(True)
        self.play_btn.setToolTip(
            "把选中的脚本按时间表回放给全部次窗口 (数量上限 16):\n"
            "· 鼠标按主/次窗口比例自动换算坐标\n"
            "· 键盘只发给已校准且无密码控件的窗口 (与键盘同步同一套闸口)\n"
            "· 与实时同步/录制互斥: 执行期间不能开始同步或录制, 反之亦然\n"
            "· 遍数 0 = 无限循环; 倍速 100% = 按录制原速\n"
            "· 紧急停止: Ctrl+Alt+Q (自动补发未释放的按键, 防卡键)")
        self.play_btn.clicked.connect(self.toggle_play)
        self.script_combo = QComboBox()
        self.script_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.script_combo.setMinimumContentsLength(16)
        btn_scripts = QPushButton("刷新脚本")
        btn_scripts.clicked.connect(self.refresh_scripts)
        self.loop_spin = QSpinBox()
        self.loop_spin.setRange(0, 999)
        self.loop_spin.setValue(1)
        self.loop_spin.setToolTip("执行遍数; 0 = 无限循环直到手动停止")
        self.speed_spin = QSpinBox()
        self.speed_spin.setRange(10, 500)
        self.speed_spin.setValue(100)
        self.speed_spin.setSuffix("%")
        self.speed_spin.setToolTip("执行速度; 100% = 与录制时相同")
        row4.addWidget(self.rec_btn)
        row4.addWidget(self.play_btn)
        row4.addWidget(self.script_combo, 1)
        row4.addWidget(btn_scripts)
        row4.addWidget(QLabel("遍数"))
        row4.addWidget(self.loop_spin)
        row4.addWidget(QLabel("倍速"))
        row4.addWidget(self.speed_spin)
        layout.addLayout(row4)

        self.status_label = QLabel("就绪: 开2个目标窗口 → 刷新 → 设主窗口/次窗口 → 开始"
                                   " (键盘需把每个次窗口切到前台校准一次)")
        self.status_label.setObjectName("statusLabel")
        layout.addWidget(self.status_label)

    # ---------- 窗口管理 ----------
    def refresh_windows(self):
        cur = self.win_combo.currentText()
        self.win_combo.clear()
        for hwnd, title in enum_windows():
            self.win_combo.addItem("%s ─ %s" % (hwnd, title[:40]), hwnd)
        if cur:
            idx = self.win_combo.findText(cur)
            if idx >= 0:
                self.win_combo.setCurrentIndex(idx)
        self._set_status("已刷新, 共 %d 个窗口" % self.win_combo.count())

    def _selected_hwnd(self):
        return self.win_combo.currentData()

    def _find_row(self, hwnd):
        for r in range(self.table.rowCount()):
            try:
                if int(self.table.item(r, 0).text()) == hwnd:
                    return r
            except (TypeError, ValueError):
                continue
        return -1

    def _upsert_row(self, hwnd, role):
        r = self._find_row(hwnd)
        if r < 0:
            r = self.table.rowCount()
            self.table.insertRow(r)
        title = win32gui.GetWindowText(hwnd) or "(无标题)"
        self._ui_lock = True
        try:
            self.table.setItem(r, 0, QTableWidgetItem(str(hwnd)))
            self.table.setItem(r, 1, QTableWidgetItem(title[:50]))
            self.table.setItem(r, 2, QTableWidgetItem(role))
            self.table.setItem(r, 3, QTableWidgetItem("—"))
            self.table.setItem(r, 4, self._make_optin_item(hwnd))
        finally:
            self._ui_lock = False

    def _make_optin_item(self, hwnd):
        """第 5 列: [B 方案] 自绘窗口放行的勾选框。

        只有"确实因为自绘输入宿主而无法核实"的目标才可勾选。普通窗口不给可勾的
        盒子 —— 否则用户会以为"勾了更保险", 反而在普通窗口上关掉检测。"""
        item = QTableWidgetItem()
        item.setCheckState(Qt.Checked if self.engine.allow_opaque(hwnd) else Qt.Unchecked)
        if self.engine._is_opaque_target(hwnd, hwnd):
            item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            item.setToolTip(
                "该窗口使用自绘界面(浏览器/Electron/UWP 等), 工具无法检测其中是否\n"
                "有密码输入框。勾选表示你确认【这个窗口里没有密码/口令输入】,\n"
                "允许把键盘同步进来。\n\n"
                "每次投递前仍会复检, 一旦发现真正的密码框立即收回放行。\n"
                "该确认不随配置保存, 下次启动需重新勾选。")
        else:
            item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            item.setToolTip("该窗口不涉及自绘输入宿主, 此项不适用")
        return item

    def _on_table_item_changed(self, item):
        if self._ui_lock or item is None or item.column() != 4:
            return
        try:
            hwnd = int(self.table.item(item.row(), 0).text())
        except (TypeError, ValueError, AttributeError):
            return
        on = item.checkState() == Qt.Checked
        self.engine.set_allow_opaque(hwnd, on)
        if on:
            self._set_status("目标 %d 已放行: 按你的确认视为无密码框 (未做检测)" % hwnd)
        else:
            self._set_status("目标 %d 已收回放行; 该目标的键盘同步将按'无法确认'拒绝"
                             % hwnd)

    def set_main(self):
        hwnd = self._selected_hwnd()
        if not hwnd or not win32gui.IsWindow(hwnd):
            return
        self.engine.main_hwnd = hwnd
        self._upsert_row(hwnd, "★ 主窗口")
        AUDIT.write("SET_MAIN", "hwnd=%d" % hwnd)
        self.save_config()
        self._set_status("主窗口: %s" % win32gui.GetWindowText(hwnd)[:30])

    def add_sub(self):
        hwnd = self._selected_hwnd()
        if not hwnd:
            return
        if not win32gui.IsWindow(hwnd):
            QMessageBox.warning(self, "提示", "该窗口已关闭, 请刷新后重新选择")
            return
        if hwnd == self.engine.main_hwnd:
            QMessageBox.information(self, "提示", "该窗口已是主窗口")
            return
        if hwnd in self.engine.targets:
            QMessageBox.information(self, "提示", "该窗口已在次窗口列表中")
            return
        if len(self.engine.targets) >= MAX_TARGETS:
            QMessageBox.warning(self, "提示", "次窗口数量已达上限 (%d 个)" % MAX_TARGETS)
            return
        # S2/T-11d: 含密码输入控件的窗口不得作为同步目标
        # (同步的按键会进入该窗口, 若焦点落在密码框则键内容会被一起送进去)
        # [B 方案] 三态处理: 确定命中 → 拒绝; 结构性无法核实(自绘宿主) → 用户显式确认
        # 后可加入并放行; 其它无法确认(枚举异常/超时) → 仍拒绝, 不给 opt-in 选项。
        optin = False
        wst = _window_password_state(hwnd)
        if wst == SENS_YES:
            AUDIT.write("ADD_SUB_DENY", "hwnd=%d 含密码输入控件" % hwnd)
            QMessageBox.warning(
                self, "无法添加该窗口",
                "该窗口内含密码/口令输入框。\n"
                "为避免同步的按键内容落进密码框, 不允许把它设为次窗口。\n\n"
                "如该窗口不是登录/支付类界面, 请换用其他窗口作为目标。")
            self._set_status("已拒绝: 该窗口含密码输入控件")
            return
        if wst == SENS_UNKNOWN:
            if not self.engine._is_opaque_target(hwnd, hwnd):
                AUDIT.write("ADD_SUB_DENY", "hwnd=%d 无法确认(非自绘宿主)" % hwnd)
                QMessageBox.warning(
                    self, "暂时无法确认该窗口",
                    "本次扫描该窗口时出现超时或权限受限, 无法确认其中是否含密码框。\n"
                    "请稍后重试; 若持续如此, 请换用其他窗口作为目标。")
                self._set_status("已拒绝: 无法确认该窗口是否含密码控件")
                return
            ans = QMessageBox.question(
                self, "该窗口无法检测密码框",
                "该窗口使用自绘界面(浏览器 / Electron / UWP 等), 工具无法检测\n"
                "其中是否有密码输入框。\n\n"
                "仅当你确认【这个窗口里没有密码 / 口令输入】时才可继续。\n"
                "加入后该窗口会出现在列表里, 并勾选'自绘窗口放行'。\n"
                "每次投递前仍会复检; 一旦发现真正的密码框会立即收回放行。\n\n"
                "是否继续?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if ans != QMessageBox.Yes:
                AUDIT.write("ADD_SUB_DENY", "hwnd=%d 用户取消自绘窗口放行" % hwnd)
                self._set_status("已取消: 未确认该窗口无密码输入")
                return
            optin = True
        self.engine.targets.append(hwnd)
        if optin:
            self.engine.set_allow_opaque(hwnd, True)
        AUDIT.write("ADD_SUB", "hwnd=%d" % hwnd)
        self._upsert_row(hwnd, "次窗口")
        self.save_config()
        self._set_status("次窗口 +1, 共 %d 个" % len(self.engine.targets))

    def remove_selected(self):
        rows = sorted({i.row() for i in self.table.selectedIndexes()}, reverse=True)
        if not rows:
            return
        for r in rows:
            hwnd = int(self.table.item(r, 0).text())
            if hwnd == self.engine.main_hwnd:
                self.engine.main_hwnd = None
            if hwnd in self.engine.targets:
                self.engine.targets.remove(hwnd)
            self.engine._forget_target(hwnd)   # INV-6: 手动移除也要回收键盘校准状态
            AUDIT.write("REMOVE", "hwnd=%d" % hwnd)
            self.table.removeRow(r)
        self.save_config()

    def _refresh_delivery_states(self):
        """每秒刷新"投递(API层)"列 — F-01 可观测性。
        语义: 仅代表投递 API 是否接受该消息, 不代表目标内部已接收或已处理。
        另含 B1 的键盘拒绝状态(未校准/敏感控件/控件失效/无法确认) —— 禁止显示为"正常"。
        N-1: 该列显示的是【汇总状态】, 规则见 target_states():
             键盘异常优先(显示为"键盘未转发:xxx"), 其次鼠标异常(显示为"失败×N"),
             两者都正常才是"正常"。鼠标投递成功不会把键盘的拒绝状态刷掉。"""
        # B1/S1: 顺带做一次被动校准 —— 用户把某个目标切到前台后,
        # 即使没按键也能在 1 秒内完成校准 (只读, 不抢前台)。
        try:
            if self.engine.active and self.engine.sync_kb:
                self.engine._poll_learn_kb()
        except Exception:
            pass
        try:
            states = self.engine.target_states()
        except Exception:
            return
        for r in range(self.table.rowCount()):
            try:
                hwnd = int(self.table.item(r, 0).text())
            except (TypeError, ValueError, AttributeError):
                continue
            if hwnd not in states:
                continue
            state, consec, err = states[hwnd]
            if state.startswith("正常"):
                # [B 方案] 放行中的自绘窗口显示"正常(自绘窗口,未检测密码框)",
                # 不能与真正通过检测的目标显示成同一个词。
                text = state
            elif state in KB_REASON_ALL:
                text = "键盘未转发:%s" % state
            else:
                text = "失败×%d %s" % (consec, _err_text(err))
            item = self.table.item(r, 3)
            if item is None:
                self.table.setItem(r, 3, QTableWidgetItem(text))
            elif item.text() != text:
                item.setText(text)

    # ---------- 按键规则 (阶段24) ----------
    def _refresh_rule_btn(self):
        n = len([r for r in self.engine.kb_rules if r.get("on", True)])
        self.kb_rule_btn.setText("按键规则 (%d)…" % n)

    def open_kb_rules(self):
        dlg = KbRuleDialog(self.engine.kb_rules, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self.engine.kb_rules = dlg.result_rules()
        self._refresh_rule_btn()
        n = len([r for r in self.engine.kb_rules if r.get("on", True)])
        self._set_status("按键规则已更新: %d 条生效 (表内键由规则接管, 表外键仍全量转发)" % n)
        self.save_config()

    # ---------- 配置持久化 (存窗口指纹而非句柄, 规避句柄回收) ----------
    def _win_fingerprint(self, hwnd):
        fp = self.engine._fingerprint(hwnd)
        if not fp:
            return None
        return {"pid": fp[0], "cls": fp[1],
                "title": (win32gui.GetWindowText(hwnd) or "")[:50]}

    def save_config(self):
        try:
            data = {
                "main": self._win_fingerprint(self.engine.main_hwnd),
                "subs": [self._win_fingerprint(h) for h in self.engine.targets],
                # 阶段24: 按键规则随配置保存 (只是键位/延迟/连发这些参数,
                # 不含任何窗口状态, 也不影响任何安全判定)
                "kb_rules": [dict(r) for r in self.engine.kb_rules
                             if int(r.get("dst", 0)) > 0],
            }
            with open(_os.path.join(APP_DIR, "config.json"), "w", encoding="utf-8") as f:
                _json.dump(data, f, ensure_ascii=False, indent=1)
        except Exception:
            pass

    def _match_fingerprint(self, fp):
        """按 pid+类名+标题 在当前窗口里找回上次的窗口"""
        if not fp or not isinstance(fp, dict):
            return None
        for hwnd, title in enum_windows():
            f = self._win_fingerprint(hwnd)
            if f and f["pid"] == fp.get("pid") and f["cls"] == fp.get("cls") \
                    and f["title"] == fp.get("title"):
                return hwnd
        return None

    def restore_config(self):
        try:
            with open(_os.path.join(APP_DIR, "config.json"), "r", encoding="utf-8") as f:
                data = _json.load(f)
            if not isinstance(data, dict):
                return
            # 阶段24: 恢复按键规则 (逐条校验, 任何一条不合法就跳过该条)
            rules = data.get("kb_rules")
            if isinstance(rules, list):
                clean = []
                for r in rules[:32]:
                    if not isinstance(r, dict):
                        continue
                    try:
                        src, dst = int(r.get("src", 0)), int(r.get("dst", 0))
                        if not (0 < src < 256 and 0 < dst < 256):
                            continue
                        clean.append({
                            "on": bool(r.get("on", True)),
                            "src": src, "dst": dst,
                            "delay": max(0, min(RULE_MAX_DELAY_MS,
                                                int(r.get("delay", 0) or 0))),
                            "times": max(1, min(RULE_MAX_TIMES,
                                                int(r.get("times", 1) or 1))),
                        })
                    except Exception:
                        continue
                if clean:
                    self.engine.kb_rules = clean
                    try:
                        self._refresh_rule_btn()
                    except Exception:
                        pass
            main_hwnd = self._match_fingerprint(data.get("main"))
            if main_hwnd:
                self.engine.main_hwnd = main_hwnd
                self._upsert_row(main_hwnd, "★ 主窗口")
            for fp in (data.get("subs") or [])[:MAX_TARGETS]:
                h = self._match_fingerprint(fp)
                if h and h != main_hwnd and h not in self.engine.targets:
                    # S2: 恢复配置也是一条旁路 —— 含密码控件的历史目标不自动加入
                    if self.engine.has_sensitive_ctrl(h):
                        AUDIT.write("RESTORE_DENY", "hwnd=%d 含密码输入控件" % h)
                        continue
                    self.engine.targets.append(h)
                    self._upsert_row(h, "次窗口")
            if main_hwnd or self.engine.targets:
                self._set_status("已恢复上次配置: 主=%s 次=%d 个"
                                 % ("有" if main_hwnd else "无", len(self.engine.targets)))
        except Exception:
            pass  # 配置损坏直接忽略重建

    # ---------- 同步控制 ----------
    def toggle_sync(self, checked):
        if checked:
            # 阶段25 互斥铁律: 录制 / 回放 / 实时同步两两互斥, 先到先得
            if self.recorder.recording or self.player.playing:
                self.start_btn.setChecked(False)
                self._set_status("实时同步与录制/回放互斥, 请先停止它们")
                AUDIT.write("SYNC_DENY_MUTEX", "录制=%s 回放=%s"
                            % (self.recorder.recording, self.player.playing))
                return
            # 授权闸口: 没开通/已到期就不许启动同步。
            # 这是"付费才能用"的真正执行点 —— 界面按钮只是表象, 服务端剩余时间
            # 才是权威; 这里用本地最近一次心跳拿到的剩余时间做快速判断。
            if self.lic.remaining <= 0:
                self.start_btn.setChecked(False)
                self._set_status("套餐未开通或已到期, 请先购买套餐或兑换卡密")
                AUDIT.write("DENY_EXPIRED", "剩余时长 0, 拒绝启动")
                QMessageBox.information(
                    self, "需要开通套餐",
                    "当前账号没有可用时长。\n\n点右上角「套餐 / 充值」选择套餐,"
                    " 或使用卡密兑换时长后再开始同步。")
                return
            self.engine.sync_mouse = self.chk_mouse.isChecked()
            self.engine.sync_kb = self.chk_kb.isChecked()
            self.engine.send_char = self.chk_char.isChecked()
            self.engine.follow_f5 = self.chk_f5.isChecked()
            self.engine.mode = self.mode_combo.currentIndex() + 1
            if not self.engine.start():
                self.start_btn.setChecked(False)
                self._f5.stop()   # 启动被拒时不得留下定时器
            else:
                self.start_btn.setText("停止 (紧急停止快捷键: Ctrl+Alt+Q)")
                if self.engine.follow_f5:
                    self._f5.start(FOLLOW_INTERVAL_MS)
                    AUDIT.write("FOLLOW_ON", "F5 跟随 %dms 目标=%d 个"
                                % (FOLLOW_INTERVAL_MS, len(self.engine.targets)))
                # 阶段24: 规则表寄生在键盘同步通道内 (共用同一门控与闸口),
                # 没勾键盘同步时不会生效 —— 必须明说, 否则用户会以为规则失灵。
                if not self.chk_kb.isChecked():
                    _on = [r for r in self.engine.kb_rules if r.get("on", True)]
                    if _on:
                        self._set_status("提示: 按键规则共 %d 条, 但未勾选「键盘同步」"
                                         " → 不会生效" % len(_on))
                        AUDIT.write("KB_RULE_IDLE", "规则 %d 条因未勾选键盘同步而未生效"
                                    % len(_on))
        else:
            self._f5.stop()
            self.engine.stop()
            self.start_btn.setText("开始 (紧急停止快捷键: Ctrl+Alt+Q)")
            self._set_status("已停止")

    def _follow_f5_tick(self):
        """定时器回调: 同步已停或开关已关 → 自停, 避免残留投递。
        这一层自检是必需的: 心跳失效、紧急停止等路径会直接调 engine.stop(),
        不会经过 toggle_sync, 因此定时器必须能自己发现"该停了"。"""
        if not self.engine.active or not self.engine.follow_f5:
            self._f5.stop()
            return
        self.engine.tap_follow_key_once()

    def _own_hwnd(self):
        return int(self.winId()) if self.isVisible() else None

    # ---------- 阶段25: 录制与回放 ----------
    def refresh_scripts(self):
        """扫描 scripts/ 目录, 回填脚本下拉框。"""
        cur = self.script_combo.currentText()
        self.script_combo.clear()
        try:
            names = sorted(f for f in _os.listdir(SCRIPTS_DIR)
                           if f.endswith(".json"))
        except OSError:
            names = []
        for n in names:
            self.script_combo.addItem(n)
        self.script_combo.setEnabled(bool(names))
        if cur:
            idx = self.script_combo.findText(cur)
            if idx >= 0:
                self.script_combo.setCurrentIndex(idx)

    def _save_script(self):
        """把录制事件写入 scripts/<时间戳>.json。返回路径或 None。"""
        try:
            _os.makedirs(SCRIPTS_DIR, exist_ok=True)
            name = _time.strftime("rec_%Y%m%d_%H%M%S") + ".json"
            path = _os.path.join(SCRIPTS_DIR, name)
            with open(path, "w", encoding="utf-8") as f:
                _json.dump({"version": 1, "count": len(self.recorder.events),
                            "events": self.recorder.events},
                           f, ensure_ascii=False)
            AUDIT.write("REC_SAVE", "%s 事件 %d 条" % (name, len(self.recorder.events)))
            return path
        except Exception as e:
            self._set_status("脚本保存失败: %s" % e)
            AUDIT.write("REC_SAVE_FAIL", str(e)[:40])
            return None

    def _load_script(self):
        """读取并校验选中的脚本。只接受已知形状的事件, 防手改文件注入意外消息。
        返回事件列表; 无效返回 None。"""
        name = self.script_combo.currentText()
        if not name:
            return None
        try:
            with open(_os.path.join(SCRIPTS_DIR, name), "r", encoding="utf-8") as f:
                data = _json.load(f)
            evs = data.get("events", [])
            if not isinstance(evs, list) or len(evs) > SCRIPT_MAX_EVENTS:
                self._set_status("脚本已损坏或过大, 拒绝加载: %s" % name)
                return None
            ok = []
            for e in evs:
                try:
                    if (e.get("ch") == "m" and int(e["msg"]) in MOUSE_MSGS
                            and 0.0 <= float(e["fx"]) <= 1.0
                            and 0.0 <= float(e["fy"]) <= 1.0):
                        ok.append(e)
                    elif (e.get("ch") == "k" and int(e["msg"]) in KEY_MSGS
                            and int(e["vk"]) > 0):
                        ok.append(e)
                except (KeyError, TypeError, ValueError):
                    continue
            if not ok:
                self._set_status("脚本中没有有效事件: %s" % name)
                return None
            return ok
        except Exception as e:
            self._set_status("脚本加载失败: %s" % e)
            return None

    def toggle_record(self, checked):
        if checked:
            # 互斥: 同步 / 回放进行中一律拒绝 (先到先得)
            if self.engine.active:
                self.rec_btn.setChecked(False)
                self._set_status("录制与实时同步互斥, 请先停止同步")
                return
            if self.player.playing:
                self.rec_btn.setChecked(False)
                self._set_status("录制与回放互斥, 请先停止回放")
                return
            hwnd = self.engine.main_hwnd
            if not hwnd or not win32gui.IsWindow(hwnd):
                self.rec_btn.setChecked(False)
                self._set_status("请先设置主窗口再录制")
                return
            if not self.recorder.start(hwnd, self.stop_record_from_hotkey):
                self.rec_btn.setChecked(False)
                self._set_status("录制钩子安装失败, 详见 audit.log")
                return
            self.rec_btn.setText("■ 停止录制 (Ctrl+Alt+Q)")
            self.start_btn.setEnabled(False)
            self.play_btn.setEnabled(False)
            self._set_status("录制中: 在主窗口内操作; 再点一次或 Ctrl+Alt+Q 结束"
                             " (只记录不转发)")
        else:
            self._finish_record()

    def stop_record_from_hotkey(self):
        """录制钩子的 Ctrl+Alt+Q 回调。钩子装在主线程, 此处可直接操作 UI。"""
        if self.rec_btn.isChecked():
            self.rec_btn.setChecked(False)   # 触发 toggle_record(False) 走收尾
            self._finish_record()

    def _finish_record(self):
        n = len(self.recorder.events)
        self.recorder.stop()
        self.rec_btn.setText("● 开始录制")
        self.start_btn.setEnabled(True)
        self.play_btn.setEnabled(True)
        if n == 0:
            self._set_status("录制结束: 没有录到任何动作, 未保存")
            return
        path = self._save_script()
        if path:
            self.refresh_scripts()
            idx = self.script_combo.findText(_os.path.basename(path))
            if idx >= 0:
                self.script_combo.setCurrentIndex(idx)
            self._set_status("录制完成: %d 个动作, 已保存 scripts/%s"
                             % (n, _os.path.basename(path)))

    def toggle_play(self, checked):
        if checked:
            if self.engine.active or self.recorder.recording:
                self.play_btn.setChecked(False)
                self._set_status("回放与实时同步/录制互斥, 请先停止它们")
                return
            evs = self._load_script()
            if not evs:
                self.play_btn.setChecked(False)
                return
            if not self.player.start(evs, self.speed_spin.value() / 100.0,
                                     self.loop_spin.value()):
                self.play_btn.setChecked(False)
                return
            self.play_btn.setText("■ 停止执行 (Ctrl+Alt+Q)")
            self.start_btn.setEnabled(False)
            self.rec_btn.setEnabled(False)
            loops_txt = "无限" if self.loop_spin.value() == 0 \
                else "%d 遍" % self.loop_spin.value()
            self._set_status("执行中: %d 个动作 → %d 个次窗口 (%s, 倍速 %d%%);"
                             " Ctrl+Alt+Q 停止"
                             % (len(evs), len(self.engine.targets), loops_txt,
                                self.speed_spin.value()))
        else:
            self.player.stop()

    def _play_state_reset(self):
        """回放结束 (自然完成或中止) 的 UI 复位。player.stop() 回调。"""
        self.play_btn.setChecked(False)
        self.play_btn.setText("▶ 执行到所有次窗口")
        self.start_btn.setEnabled(True)
        self.rec_btn.setEnabled(True)

    def _set_status(self, text):
        self.status_label.setText(text)

    def closeEvent(self, event):
        # 关闭时停止计时器并拒收心跳回传, 防止线程在窗口销毁后触碰 UI
        self._closing = True
        for name in ("_hb", "_st", "_f5"):
            timer = getattr(self, name, None)
            if timer is not None:
                try:
                    timer.stop()
                except Exception:
                    pass
        self.engine.stop()
        # 阶段25: 关窗必须同时停录制与回放 (回放收尾会补发未释放按键, 防目标端卡键)
        self.recorder.stop()
        self.player.stop()
        super().closeEvent(event)


def selftest():
    """离屏自检: 枚举窗口 + 引擎类可用"""
    for hwnd, title in enum_windows()[:5]:
        print("窗口: %s ─ %s" % (hwnd, title[:40]))
    eng = SyncEngine(lambda: None)
    print("引擎自检 OK, 钩子未安装, active=%s" % eng.active)
    print("SELFTEST_PASS")


def main():
    if "--selftest" in sys.argv:
        selftest()
        return
    if not _acquire_single_instance():
        ctypes.windll.user32.MessageBoxW(
            None, "阿信电脑同步器已在运行, 请勿重复打开。", "提示", 0x40)
        return
    try:
        app = QApplication(sys.argv)
        app.setStyleSheet(DARK_QSS)
        lic = AccountClient()
        AUDIT.write("APP_START", "机器码 %s" % lic.machine)
        # [免密进入] 本地令牌仍有效 → 直接进主界面, 不弹登录门。
        # 令牌是服务端签发的可撤销凭证, 不是密码; 密码本身从不落盘。
        ok_local, local_info = lic.load_local()
        if ok_local:
            AUDIT.write("LOGIN", "账号自动登录 %s" % lic.user)
        else:
            gate = AccountGate(lic, local_info if local_info != "尚未登录" else "")
            if gate.exec() != QDialog.DialogCode.Accepted:
                AUDIT.write("APP_EXIT", "未登录退出")
                return
        win = MainWindow(lic)
        win.show()
        sys.exit(app.exec())
    except Exception:
        # 无控制台模式下崩溃写日志到 exe 同目录, 避免无声闪退
        import traceback
        import os
        try:
            log_path = os.path.join(os.path.dirname(sys.executable), "error.log")
            with open(log_path, "a", encoding="utf-8") as f:
                f.write("==== %s ====\n" % __import__("datetime").datetime.now())
                f.write(traceback.format_exc())
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()
