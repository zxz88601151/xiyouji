# -*- coding: utf-8 -*-
"""逐步调试2: 点击建立焦点后, KEYDOWN 与 CHAR 是否双重插入"""
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
from multisync import SyncEngine, KBDLLHOOKSTRUCT, MSLLHOOKSTRUCT, \
    WM_KEYDOWN, WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_LBUTTONUP

user32 = ctypes.WinDLL("user32")


def find_window(title, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        h = win32gui.FindWindow(None, title)
        if h:
            return h
        time.sleep(0.3)
    raise RuntimeError("no window " + title)


def child_edits(hwnd):
    res = []
    win32gui.EnumChildWindows(hwnd, lambda c, _: res.append(c), None)
    return [c for c in res if win32gui.GetClassName(c) == "Edit"]


def get_text(hedit):
    ln = user32.SendMessageW(hedit, win32con.WM_GETTEXTLENGTH, 0, 0)
    buf = ctypes.create_unicode_buffer(ln + 1)
    user32.SendMessageW(hedit, win32con.WM_GETTEXT, ln + 1, buf)
    return buf.value


proc = subprocess.Popen([sys.executable, "test_targets.py"], cwd=HERE)
try:
    hwnd_a = find_window("TEST-A")
    hwnd_b = find_window("TEST-B")
    edit_b = child_edits(hwnd_b)[0]
    print("A=%d B=%d EditB=%d" % (hwnd_a, hwnd_b, edit_b))

    eng = SyncEngine(lambda: None)
    eng.main_hwnd = hwnd_a
    eng.targets = [hwnd_b]
    eng.active = True

    # 点击 B 的 Edit 建立焦点 (A 的中心 → 等比落到 B 的中心, 必在 Edit 内)
    arect = wintypes.RECT()
    user32.GetClientRect(hwnd_a, ctypes.byref(arect))
    cpt = wintypes.POINT(arect.right // 2, arect.bottom // 2)
    user32.ClientToScreen(hwnd_a, ctypes.byref(cpt))
    ms = MSLLHOOKSTRUCT(pt=wintypes.POINT(cpt.x, cpt.y), mouseData=0,
                        flags=0, time=0, dwExtraInfo=0)
    eng._btn_flags = 1
    eng._forward_mouse(WM_MOUSEMOVE, ms)
    eng._forward_mouse(WM_LBUTTONDOWN, ms)
    eng._forward_mouse(WM_LBUTTONUP, ms)
    eng._btn_flags = 0
    time.sleep(0.2)

    kb = eng._resolve_kb_target(hwnd_b)
    print("点击后焦点: %d (类名: %s)" % (kb, win32gui.GetClassName(kb)))

    vk = ord("9")
    st = KBDLLHOOKSTRUCT(vkCode=vk, scanCode=win32api.MapVirtualKey(vk, 0),
                         flags=0, time=0, dwExtraInfo=0)

    user32.PostMessageW(kb, WM_KEYDOWN, vk, 1)
    time.sleep(0.3)
    print("仅 WM_KEYDOWN 后: %r" % get_text(edit_b))

    user32.PostMessageW(kb, 0x0102, 0x39, 1)  # WM_CHAR
    time.sleep(0.3)
    print("再补 WM_CHAR 后: %r" % get_text(edit_b))
finally:
    try:
        win32gui.PostMessage(hwnd_a, win32con.WM_CLOSE, 0, 0)
        win32gui.PostMessage(hwnd_b, win32con.WM_CLOSE, 0, 0)
    except Exception:
        pass
    time.sleep(0.5)
    proc.terminate()
