# -*- coding: utf-8 -*-
"""模拟测试用: 创建两个带真实 Edit 输入框的窗口 TEST-A / TEST-B"""
import sys
import win32gui
import win32con
import win32api

CLS = "SyncTestWndCls"


def create_one(title, x, y):
    wc = win32gui.WNDCLASS()
    wc.lpszClassName = CLS
    wc.lpfnWndProc = win32gui.DefWindowProc
    wc.hInstance = win32api.GetModuleHandle(None)
    try:
        win32gui.RegisterClass(wc)
    except win32gui.error:
        pass
    hwnd = win32gui.CreateWindowEx(
        0, CLS, title,
        win32con.WS_OVERLAPPEDWINDOW | win32con.WS_VISIBLE,
        x, y, 420, 320, None, None, wc.hInstance, None)
    hedit = win32gui.CreateWindowEx(
        win32con.WS_EX_CLIENTEDGE, "Edit", "",
        win32con.WS_CHILD | win32con.WS_VISIBLE | win32con.ES_MULTILINE
        | win32con.ES_AUTOVSCROLL | win32con.WS_VSCROLL,
        0, 0, 400, 280, hwnd, None, wc.hInstance, None)
    return hwnd, hedit


def main():
    hwnd_a, _ = create_one("TEST-A", 100, 120)
    hwnd_b, _ = create_one("TEST-B", 580, 120)
    print("READY A=%d B=%d" % (hwnd_a, hwnd_b))
    sys.stdout.flush()
    # 阻塞式消息泵: 目标必须能"立即"应答跨进程消息(EM_GETPASSWORDCHAR 等)。
    # 原来的 PumpWaitingMessages + sleep(50ms) 让每次应答慢 30-50ms,
    # 超过引擎 20ms 的敏感探测预算 → 引擎按 fail-closed 报"无法确认"。
    # 真实 Win32/Qt 目标应答是亚毫秒级, 慢在这里的是模拟器本身。
    win32gui.PumpMessages()


if __name__ == "__main__":
    main()
