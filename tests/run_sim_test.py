# -*- coding: utf-8 -*-
"""
模拟测试: 用同步引擎的真实转发逻辑, 向 TEST-B 模拟键盘输入/按键/鼠标走动,
并读取 TEST-B 输入框内容验证是否同步成功。
(直接调用引擎的 _forward_*, 不装钩子, 不动真实鼠标键盘)
"""
import os
import sys
import time
import ctypes
import subprocess
from ctypes import wintypes

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import win32gui
import win32con
import win32api
import win32process
from multisync import (
    SyncEngine, KBDLLHOOKSTRUCT, MSLLHOOKSTRUCT,
    WM_KEYDOWN, WM_KEYUP, WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_LBUTTONUP,
    _window_password_state, SENS_NO,
)

user32 = ctypes.WinDLL("user32")
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print("[%s] %s %s" % ("PASS" if ok else "FAIL", name, detail))


def find_window(title, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        h = win32gui.FindWindow(None, title)
        if h:
            return h
        time.sleep(0.3)
    raise RuntimeError("找不到窗口: " + title)


def child_edits(hwnd):
    res = []
    win32gui.EnumChildWindows(hwnd, lambda c, _: res.append(c), None)
    return [c for c in res if win32gui.GetClassName(c) == "Edit"]


def force_foreground(hwnd):
    """把目标窗口真正切到前台。

    为什么需要: 引擎学习键盘目标依赖前台线程的 GUITHREADINFO.hwndFocus,
    只有前台窗口才有焦点信息。而本测试用 PostMessage 模拟点击, 投递消息
    不会让窗口变成前台; 后台进程直接 SetForegroundWindow 又被系统拒绝。
    所以借用前台线程的输入队列 (AttachThreadInput) 再切 —— 对应真实使用中
    "用户点一下目标窗口它就来到前台" 这个前提。
    """
    u32 = ctypes.windll.user32
    fg = win32gui.GetForegroundWindow()
    cur = win32api.GetCurrentThreadId()
    tids = [cur]
    for w in (fg, hwnd):
        t = win32process.GetWindowThreadProcessId(w)[0] if w else 0
        if t and t not in tids:
            tids.append(t)
    attached = []
    try:
        for t in tids[1:]:
            if u32.AttachThreadInput(cur, t, True):
                attached.append(t)
        u32.SetForegroundWindow(hwnd)
        u32.BringWindowToTop(hwnd)
        time.sleep(0.25)
    finally:
        for t in attached:
            u32.AttachThreadInput(cur, t, False)
    return win32gui.GetForegroundWindow() == hwnd


def get_text(hedit):
    ln = user32.SendMessageW(hedit, win32con.WM_GETTEXTLENGTH, 0, 0)
    buf = ctypes.create_unicode_buffer(ln + 1)
    user32.SendMessageW(hedit, win32con.WM_GETTEXT, ln + 1, buf)
    return buf.value


def type_keys(eng, s):
    """模拟逐键按下/抬起 (含 KEYDOWN/KEYUP 配对)"""
    for ch in s:
        vk = ord(ch.upper())
        st = KBDLLHOOKSTRUCT(vkCode=vk, scanCode=win32api.MapVirtualKey(vk, 0),
                             flags=0, time=0, dwExtraInfo=0)
        eng._forward_kb(WM_KEYDOWN, st)
        time.sleep(0.01)
        eng._forward_kb(WM_KEYUP, st)
        time.sleep(0.02)


def main():
    proc = subprocess.Popen([sys.executable, "test_targets.py"], cwd=HERE)
    try:
        hwnd_a = find_window("TEST-A")
        hwnd_b = find_window("TEST-B")
        edit_b = child_edits(hwnd_b)[0]
        print("测试窗口就绪: A=%d B=%d B_Edit=%d" % (hwnd_a, hwnd_b, edit_b))

        eng = SyncEngine(lambda: None)
        eng.main_hwnd = hwnd_a
        eng.targets = [hwnd_b]
        eng.mode = 1
        eng.sync_mouse = True
        eng.sync_kb = True
        eng.send_char = False  # 默认关 (开了会双重输入)
        eng.active = True  # 直接激活 (绕过钩子安装, 钩子逻辑已在自检验证)

        # ---- 测试0: 先点击 B 中心建立焦点 (模拟真实使用流程) ----
        # 真实流程里用户是"先在主界面把 B 加成次窗口, 再点它", 加窗时引擎已经
        # 扫过一次密码控件。这一步不能省: 跨进程 EM_GETPASSWORDCHAR 首次查询
        # 冷态要 30-50ms, 超过引擎 20ms 的探测预算 → 首扫必然报"无法确认"
        # (fail-closed, 产品行为正确)。预热后再断言, 测的才是正常投递路径。
        wst = _window_password_state(hwnd_b)
        check("目标窗口安全扫描 (选窗预热)", wst == SENS_NO, "state=%s" % wst)
        # 真实流程里用户是先点了目标窗口它才在前台, 这里补上这一步;
        # 否则后台运行时目标永远不是前台, 引擎按设计拒绝盲投 (GUID 拿不到焦点).
        fg_ok = force_foreground(hwnd_b)
        check("目标窗口切到前台", fg_ok,
              "foreground=%d target=%d" % (win32gui.GetForegroundWindow(), hwnd_b))
        arect0 = wintypes.RECT()
        user32.GetClientRect(hwnd_a, ctypes.byref(arect0))
        cpt = wintypes.POINT(arect0.right // 2, arect0.bottom // 2)
        user32.ClientToScreen(hwnd_a, ctypes.byref(cpt))
        ms0 = MSLLHOOKSTRUCT(pt=wintypes.POINT(cpt.x, cpt.y), mouseData=0,
                             flags=0, time=0, dwExtraInfo=0)
        eng._forward_mouse(WM_MOUSEMOVE, ms0)
        eng._forward_mouse(WM_LBUTTONDOWN, ms0)
        time.sleep(0.1)
        eng._forward_mouse(WM_LBUTTONUP, ms0)
        time.sleep(0.3)
        focus = eng._resolve_kb_target(hwnd_b)
        check("点击建立焦点", win32gui.GetClassName(focus) == "Edit",
              "焦点类名: %s" % win32gui.GetClassName(focus))

        # ---- 测试1: 键盘输入 (数字+大小写) ----
        type_keys(eng, "1a2")
        time.sleep(0.3)
        txt = get_text(edit_b)
        check("键盘输入 '1a2' 同步", txt == "1a2", "B中实际: %r" % txt)

        # ---- 测试2: 按键配对 (按下/抬起 次数一致, 不出现卡键) ----
        before = len(txt)
        type_keys(eng, "b")
        time.sleep(0.3)
        txt = get_text(edit_b)
        check("按键抬起配对 (无卡键)", len(txt) == before + 1, "B中实际: %r" % txt)

        # ---- 测试3: 鼠标走动 + 点击 (主A中心 → B应收到等比坐标) ----
        arect = wintypes.RECT()
        user32.GetClientRect(hwnd_a, ctypes.byref(arect))
        pt = wintypes.POINT(arect.right // 2, arect.bottom // 2)
        user32.ClientToScreen(hwnd_a, ctypes.byref(pt))
        ms = MSLLHOOKSTRUCT(pt=wintypes.POINT(pt.x, pt.y), mouseData=0,
                            flags=0, time=0, dwExtraInfo=0)
        try:
            eng._forward_mouse(WM_MOUSEMOVE, ms)
            eng._forward_mouse(WM_LBUTTONDOWN, ms)
            time.sleep(0.1)
            eng._forward_mouse(WM_LBUTTONUP, ms)
            check("鼠标移动+点击转发", True, "无异常, 按键标志=%d" % eng._btn_flags)
        except Exception as e:
            check("鼠标移动+点击转发", False, repr(e))

        # ---- 测试4: 点击后键盘仍正常 (焦点/卡键回归检查) ----
        type_keys(eng, "9")
        time.sleep(0.3)
        txt = get_text(edit_b)
        check("点击后键盘仍正常", txt.endswith("9"), "B中实际: %r" % txt)

        # ---- 测试5: 模式2 SendMessage 通路 ----
        # 说明: SendMessage 直达窗口过程, 不经 TranslateMessage 翻译,
        # 所以按键消息本身不产生字符, 需配合补发 WM_CHAR (这也是原版工具的用法)
        eng.mode = 2
        eng.send_char = True
        type_keys(eng, "7")
        time.sleep(0.3)
        txt = get_text(edit_b)
        check("模式2 (SendMessage+补发字符) 通路", txt.endswith("7"), "B中实际: %r" % txt)
        eng.mode = 1
        eng.send_char = False

        # ---- 测试6: 关闭补发字符后恢复正常 (单次输入) ----
        before = len(txt)
        type_keys(eng, "5")
        time.sleep(0.3)
        txt = get_text(edit_b)
        check("关闭补发恢复正常(单次输入)", len(txt) == before + 1, "实际: %r" % txt)

        # ---- 汇总 ----
        failed = [r for r in RESULTS if not r[1]]
        print("-" * 40)
        print("总计: %d 项, 通过 %d, 失败 %d" % (len(RESULTS), len(RESULTS) - len(failed), len(failed)))
        print("SIM_TEST_PASS" if not failed else "SIM_TEST_FAIL")
    finally:
        eng_active = False
        try:
            win32gui.PostMessage(hwnd_a, win32con.WM_CLOSE, 0, 0)
            win32gui.PostMessage(hwnd_b, win32con.WM_CLOSE, 0, 0)
        except Exception:
            pass
        time.sleep(0.5)
        proc.terminate()


if __name__ == "__main__":
    main()
