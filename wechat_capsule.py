#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wechat_capsule.py —— 微信提醒胶囊（Windows；Pillow 可选，UI Automation 用于精确唤起账号）

原理：
  用 RegisterShellHookWindow 注册一个隐藏窗口，接收系统广播的 HSHELL_FLASH
  （某窗口请求任务栏关注 = 图标闪烁）。通过闪烁窗口所属进程的可执行文件名
  判断是否为微信（Weixin.exe / WeChat.exe），并按窗口句柄分别跟踪提醒。

  微信提醒来源是 Shell Hook；外部消息由内嵌局域网 HTTP 接口接收。
  外部消息摘要显示在灵动岛；完整消息保存在本地 SQLite 收件箱中并记录已读状态。

运行（推荐先 pip install pillow，获得抗锯齿/阴影/弹簧动画）：
  pythonw wechat_capsule.py           # 后台运行，可从右下角托盘菜单退出
  python wechat_capsule.py            # 调试运行（保留控制台）
  python wechat_capsule.py --hide-idle     # 无提醒时隐藏，有提醒才弹出
  python wechat_capsule.py --probe    # 只在控制台打印事件，用于诊断兼容性
  python wechat_capsule.py --probe --all   # 同时显示其他程序的闪烁事件，判断 Hook 本身是否工作
  python wechat_capsule.py --exe my.exe   # 额外匹配其他进程名（可多次指定）

操作：
  左键点击胶囊      有未读接口消息时打开消息记录，否则唤起对应微信账号
  按住左键拖动      把胶囊拖到屏幕任意位置（位置会被记住）
  右键点击胶囊      菜单：恢复到顶部 / 模拟提醒 / 消息记录 / 样式 / 复制接口 / 查看文档 / 退出
  点击托盘图标      菜单：消息记录 / 恢复位置 / 复制接口 / 查看文档 / 退出程序
  微信窗口被激活    自动清除提醒点
"""
import argparse
import base64
from contextlib import closing
import ctypes
import hmac
import io
import json
import math
import os
import queue
import re
import secrets
import sqlite3
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
import unicodedata
import webbrowser
from datetime import datetime
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.parse import parse_qs, urlparse

try:
    import uiautomation as _uia
except Exception:
    _uia = None

# ----------------------------------------------------------------------------
# Win32 常量
# ----------------------------------------------------------------------------
HSHELL_REDRAW = 6
HSHELL_WINDOWACTIVATED = 4
HSHELL_FLASH = 0x8006  # HSHELL_REDRAW | HSHELL_HIGHBIT
HSHELL_RUDEAPPACTIVATED = 0x8004
GW_OWNER = 4

WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_NULL = 0x0000
WM_CONTEXTMENU = 0x007B
WM_LBUTTONUP = 0x0202
VK_LBUTTON = 0x01
WM_RBUTTONUP = 0x0205
WM_TRAY_CALLBACK = 0x8001
WS_POPUP = 0x80000000
WS_EX_TOOLWINDOW = 0x00000080
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

NIM_ADD = 0x00000000
NIM_DELETE = 0x00000002
NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
IMAGE_ICON = 1
LR_LOADFROMFILE = 0x00000010
IDI_APPLICATION = 32512
MF_STRING = 0x00000000
TPM_RIGHTBUTTON = 0x0002
TPM_RETURNCMD = 0x0100
TRAY_CMD_RESTORE = 101
TRAY_CMD_EXIT = 102
TRAY_CMD_MESSAGES = 103
TRAY_CMD_COPY_INTERFACE = 104
TRAY_CMD_DOCUMENTATION = 105
TRAY_CMD_GITHUB = 106
TRAY_CMD_CHECK_UPDATES = 107

DEFAULT_EXE_NAMES = {"weixin.exe", "wechat.exe"}
# 读不到进程路径时（例如微信以管理员运行而本脚本不是），退而用窗口标题匹配
WECHAT_TITLES = {"微信", "wechat", "weixin"}

_u = None  # user32
_k = None  # kernel32
_shell = None  # shell32
WNDPROC = None
WNDCLASSW = None


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]


class NOTIFYICONIDENTIFIER(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("guidItem", GUID),
    ]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HANDLE),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uTimeoutOrVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", GUID),
        ("hBalloonIcon", wintypes.HANDLE),
    ]


def load_win32():
    """延迟加载 Win32 API，保证非 Windows 平台上能给出友好提示。"""
    global _u, _k, WNDPROC, WNDCLASSW, _shell
    _u = ctypes.WinDLL("user32", use_last_error=True)
    _k = ctypes.WinDLL("kernel32", use_last_error=True)
    _shell = ctypes.WinDLL("shell32", use_last_error=True)
    lresult = ctypes.c_ssize_t

    WNDPROC = ctypes.WINFUNCTYPE(
        lresult, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
    )

    class _WNDCLASSW(ctypes.Structure):
        _fields_ = [
            ("style", wintypes.UINT),
            ("lpfnWndProc", WNDPROC),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", wintypes.HINSTANCE),
            ("hIcon", ctypes.c_void_p),
            ("hCursor", ctypes.c_void_p),
            ("hbrBackground", ctypes.c_void_p),
            ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
        ]

    WNDCLASSW = _WNDCLASSW

    _u.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
    _u.RegisterWindowMessageW.restype = wintypes.UINT
    _u.DefWindowProcW.argtypes = [
        wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
    ]
    _u.DefWindowProcW.restype = lresult
    _u.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
    _u.RegisterClassW.restype = wintypes.ATOM
    _u.CreateWindowExW.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
    ]
    _u.CreateWindowExW.restype = wintypes.HWND
    _u.RegisterShellHookWindow.argtypes = [wintypes.HWND]
    _u.RegisterShellHookWindow.restype = wintypes.BOOL
    _u.DeregisterShellHookWindow.argtypes = [wintypes.HWND]
    _u.DeregisterShellHookWindow.restype = wintypes.BOOL
    _u.GetMessageW.argtypes = [
        ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT
    ]
    _u.GetMessageW.restype = ctypes.c_int
    _u.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    _u.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    _u.DispatchMessageW.restype = lresult
    _u.PostQuitMessage.argtypes = [ctypes.c_int]
    _u.PostMessageW.argtypes = [
        wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
    ]
    _u.PostMessageW.restype = wintypes.BOOL
    _u.GetForegroundWindow.restype = wintypes.HWND
    _u.EnumWindows.argtypes = [
        ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, ctypes.c_ssize_t),
        ctypes.c_ssize_t,
    ]
    _u.EnumWindows.restype = wintypes.BOOL
    _u.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
    _u.GetWindow.restype = wintypes.HWND
    _u.IsWindow.argtypes = [wintypes.HWND]
    _u.IsWindow.restype = wintypes.BOOL
    _u.IsWindowVisible.argtypes = [wintypes.HWND]
    _u.IsWindowVisible.restype = wintypes.BOOL
    _u.IsIconic.argtypes = [wintypes.HWND]
    _u.IsIconic.restype = wintypes.BOOL
    get_dpi_for_window = getattr(_u, "GetDpiForWindow", None)
    if get_dpi_for_window:
        get_dpi_for_window.argtypes = [wintypes.HWND]
        get_dpi_for_window.restype = wintypes.UINT
    _u.GetWindowThreadProcessId.argtypes = [
        wintypes.HWND, ctypes.POINTER(wintypes.DWORD)
    ]
    _u.GetWindowThreadProcessId.restype = wintypes.DWORD
    _u.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    _u.GetWindowTextW.restype = ctypes.c_int
    _u.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    _u.GetClassNameW.restype = ctypes.c_int
    _u.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    _u.ShowWindow.restype = wintypes.BOOL
    _u.LoadImageW.argtypes = [
        wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
        ctypes.c_int, ctypes.c_int, wintypes.UINT,
    ]
    _u.LoadImageW.restype = wintypes.HANDLE
    _u.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
    _u.LoadIconW.restype = wintypes.HANDLE
    _u.GetSystemMetrics.argtypes = [ctypes.c_int]
    _u.GetSystemMetrics.restype = ctypes.c_int
    _u.DestroyIcon.argtypes = [wintypes.HANDLE]
    _u.DestroyIcon.restype = wintypes.BOOL
    _u.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
    _u.GetCursorPos.restype = wintypes.BOOL
    _u.GetDC.argtypes = [wintypes.HWND]
    _u.GetDC.restype = wintypes.HDC
    _u.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    _u.ReleaseDC.restype = ctypes.c_int
    _u.GetAsyncKeyState.argtypes = [ctypes.c_int]
    _u.GetAsyncKeyState.restype = ctypes.c_short
    _u.SetForegroundWindow.argtypes = [wintypes.HWND]
    _u.SetForegroundWindow.restype = wintypes.BOOL
    _u.CreatePopupMenu.restype = wintypes.HMENU
    _u.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t,
                               wintypes.LPCWSTR]
    _u.AppendMenuW.restype = wintypes.BOOL
    _u.TrackPopupMenu.argtypes = [
        wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, ctypes.c_void_p,
    ]
    _u.TrackPopupMenu.restype = wintypes.UINT
    _u.DestroyMenu.argtypes = [wintypes.HMENU]
    _u.DestroyMenu.restype = wintypes.BOOL
    _shell.Shell_NotifyIconW.argtypes = [
        wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)
    ]
    _shell.Shell_NotifyIconW.restype = wintypes.BOOL

    _k.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    _k.GetModuleHandleW.restype = wintypes.HMODULE
    _k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k.OpenProcess.restype = wintypes.HANDLE
    _k.CloseHandle.argtypes = [wintypes.HANDLE]
    _k.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _k.QueryFullProcessImageNameW.restype = wintypes.BOOL


def process_image(hwnd):
    """返回窗口所属进程的完整 exe 路径，失败返回空串。"""
    if not hwnd:
        return ""
    pid = wintypes.DWORD(0)
    _u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if not pid.value:
        return ""
    handle = _k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
    if not handle:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(1024)
        if _k.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value
    finally:
        _k.CloseHandle(handle)
    return ""


def window_title(hwnd):
    if not hwnd:
        return ""
    buf = ctypes.create_unicode_buffer(256)
    _u.GetWindowTextW(hwnd, buf, 256)
    return buf.value


def window_class(hwnd):
    if not hwnd:
        return ""
    buf = ctypes.create_unicode_buffer(256)
    _u.GetClassNameW(hwnd, buf, len(buf))
    return buf.value


def is_wechat_main_window(hwnd, exe_names, expected_pid=None):
    """只接受可验证的微信主窗，不操作 Shell Hook 的代理/托盘窗口。"""
    if not hwnd or not _u.IsWindow(hwnd):
        return False
    pid = wintypes.DWORD(0)
    _u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if expected_pid and pid.value != int(expected_pid):
        return False
    exe = process_image(hwnd)
    if not exe or os.path.basename(exe).lower() not in exe_names:
        return False
    if window_class(hwnd).lower() != "qt51514qwindowicon":
        return False
    return window_title(hwnd).strip().lower() in WECHAT_TITLES


def resolve_wechat_main_window(source_hwnd, source_pid, exe_names):
    """把闪烁源句柄解析到同一实例的主窗口；不确定时返回 0。"""
    current = int(source_hwnd or 0)
    visited = set()
    while current and current not in visited:
        visited.add(current)
        if is_wechat_main_window(current, exe_names):
            return current
        current = int(_u.GetWindow(current, GW_OWNER) or 0)

    if not source_pid:
        return 0
    matches = []
    exact_titles = []
    enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, ctypes.c_ssize_t)

    @enum_proc
    def visit(hwnd, _lparam):
        if is_wechat_main_window(hwnd, exe_names, source_pid):
            matches.append(int(hwnd))
            if window_title(hwnd).strip() == "微信":
                exact_titles.append(int(hwnd))
        return True

    _u.EnumWindows(visit, 0)
    if len(exact_titles) == 1:
        return exact_titles[0]
    if len(matches) == 1:
        return matches[0]
    return 0


def next_pending_window_handle(pending_windows, last_opened_hwnd):
    """只轮换仍有效且通过微信主窗校验的提醒窗口。"""
    handles = [handle for handle in pending_windows
               if handle > 0 and is_wechat_main_window(handle, DEFAULT_EXE_NAMES)]
    if not handles:
        return None
    if last_opened_hwnd in handles:
        return handles[(handles.index(last_opened_hwnd) + 1) % len(handles)]
    return handles[0]


def _wechat_tray_owner_windows():
    """Find one verified WeChat tray callback window per running process."""
    owners = {}
    ambiguous = set()
    enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, ctypes.c_ssize_t)

    @enum_proc
    def visit(hwnd, _lparam):
        if window_class(hwnd) != "Qt51514WxTrayIconMessageWindowClass":
            return True
        pid = wintypes.DWORD(0)
        _u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        exe = process_image(hwnd)
        if (not pid.value or not exe
                or os.path.basename(exe).lower() not in DEFAULT_EXE_NAMES):
            return True
        if pid.value in owners:
            ambiguous.add(pid.value)
        owners[pid.value] = int(hwnd)
        return True

    _u.EnumWindows(visit, 0)
    for pid in ambiguous:
        owners.pop(pid, None)
    return owners


def wechat_source_label(pid):
    """Return a session-local account label only when multiple WeChat instances run."""
    if not pid:
        return ""
    pids = sorted(_wechat_tray_owner_windows())
    if len(pids) < 2 or int(pid) not in pids:
        return ""
    # Numbering is deterministic for the current processes; it is not a WeChat user ID.
    return f"来自微信{pids.index(int(pid)) + 1}"


def pending_wechat_source_label(pending_windows):
    """Use the most recently pending real instance as the capsule's visible source."""
    pids = [int(pid) for pid in pending_windows.values() if int(pid) > 0]
    return wechat_source_label(pids[-1]) if pids else ""


def _wechat_tray_button_controls():
    """Read WeChat buttons from the Explorer notification area via UI Automation."""
    if _uia is None:
        return []
    controls = []
    traversable = {
        "Shell_TrayWnd", "Shell_SecondaryTrayWnd",
        "Windows.UI.Composition.DesktopWindowContentBridge",
        "Windows.UI.Input.InputSite.WindowClass",
        "Taskbar.TaskbarFrameAutomationPeer", "",
    }
    try:
        stack = [(control, 0) for control in _uia.GetRootControl().GetChildren()]
        while stack:
            control, depth = stack.pop()
            class_name = getattr(control, "ClassName", "") or ""
            automation_id = getattr(control, "AutomationId", "") or ""
            if (class_name == "SystemTray.NormalButton"
                    and automation_id == "NotifyItemIcon"):
                name_lines = (getattr(control, "Name", "") or "").strip().splitlines()
                name = name_lines[0].strip() if name_lines else ""
                if name.lower() in WECHAT_TITLES and not control.IsOffscreen:
                    controls.append(control)
                continue
            if depth < 7 and class_name in traversable:
                try:
                    stack.extend((child, depth + 1) for child in control.GetChildren())
                except Exception:
                    continue
    except Exception:
        return []
    return controls


def _tray_icon_rects(owner_hwnd):
    """Read tray-icon bounds registered by an owner HWND; never sends it messages."""
    get_rect = getattr(_shell, "Shell_NotifyIconGetRect", None)
    if get_rect is None:
        return []
    get_rect.argtypes = [ctypes.POINTER(NOTIFYICONIDENTIFIER),
                         ctypes.POINTER(wintypes.RECT)]
    get_rect.restype = ctypes.c_long
    rects = []
    for uid in range(256):
        identity = NOTIFYICONIDENTIFIER(
            ctypes.sizeof(NOTIFYICONIDENTIFIER), owner_hwnd, uid, GUID())
        rect = wintypes.RECT()
        try:
            if get_rect(ctypes.byref(identity), ctypes.byref(rect)) == 0:
                rects.append((int(rect.left), int(rect.top),
                              int(rect.right), int(rect.bottom)))
        except (OSError, ctypes.ArgumentError):
            return []
    return rects


def _tray_rect_matches(shell_rect, control_rect):
    """Allow the 1 px bounds difference seen between Shell and UIA coordinates."""
    shell_x = (shell_rect[0] + shell_rect[2]) / 2
    shell_y = (shell_rect[1] + shell_rect[3]) / 2
    control_x = (control_rect[0] + control_rect[2]) / 2
    control_y = (control_rect[1] + control_rect[3]) / 2
    return abs(shell_x - control_x) <= 4 and abs(shell_y - control_y) <= 4


def _activate_wechat_tray_button(target_pid):
    """Invoke the exact WeChat tray item; fail closed when PID mapping is unclear."""
    owners = _wechat_tray_owner_windows()
    buttons = _wechat_tray_button_controls()
    if not owners or len(owners) != len(buttons):
        return False

    mapped = {}
    used_controls = set()
    for pid, owner_hwnd in owners.items():
        rects = _tray_icon_rects(owner_hwnd)
        if len(rects) > 1:
            return False
        if not rects:
            continue
        matches = []
        for control in buttons:
            try:
                bounds = control.BoundingRectangle
                control_rect = (bounds.left, bounds.top, bounds.right, bounds.bottom)
                if _tray_rect_matches(rects[0], control_rect):
                    matches.append(control)
            except Exception:
                continue
        if len(matches) != 1 or id(matches[0]) in used_controls:
            return False
        mapped[pid] = matches[0]
        used_controls.add(id(matches[0]))

    remaining_pids = [pid for pid in owners if pid not in mapped]
    remaining_controls = [control for control in buttons
                          if id(control) not in used_controls]
    if remaining_pids or remaining_controls:
        # A remaining pair is unambiguous only when all other accounts were anchored.
        if (len(remaining_pids) != 1 or len(remaining_controls) != 1
                or len(mapped) != len(owners) - 1
                or (len(owners) > 1 and not mapped)):
            return False
        mapped[remaining_pids[0]] = remaining_controls[0]

    control = mapped.get(int(target_pid))
    if control is None:
        return False
    try:
        invoke = control.GetInvokePattern()
        if invoke is None:
            return False
        invoke.Invoke()
        return True
    except Exception:
        return False


def open_wechat_target(pending_windows, last_opened_hwnd):
    """Use the selected account's native tray action instead of forcing its main HWND."""
    hwnd = next_pending_window_handle(pending_windows, last_opened_hwnd)
    if hwnd is not None:
        pid = wintypes.DWORD(0)
        _u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return bool(pid.value and _activate_wechat_tray_button(pid.value)), hwnd
    if any(handle != 0 for handle in pending_windows):
        return False, None
    try:
        os.startfile("weixin://")
        return True, None
    except OSError:
        return False, None


def find_wechat_window(exe_names):
    """返回唯一显示中的微信主窗口；有多个候选时不猜测。"""
    matches = []
    enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, ctypes.c_ssize_t)

    @enum_proc
    def visit(hwnd, _lparam):
        if not _u.IsWindowVisible(hwnd):
            return True
        if window_title(hwnd).strip().lower() not in WECHAT_TITLES:
            return True
        exe = process_image(hwnd)
        if not exe or os.path.basename(exe).lower() in exe_names:
            matches.append(hwnd)
        return True

    _u.EnumWindows(visit, 0)
    return matches[0] if len(matches) == 1 else None


# ----------------------------------------------------------------------------
# Shell Hook 监听线程
# ----------------------------------------------------------------------------
class ShellHookListener(threading.Thread):
    """
    在独立线程里创建隐藏窗口并跑消息循环。
    通过 on_event(kind, payload) 回调（在本线程内触发）：
      kind = "flash"      微信请求任务栏关注
      kind = "activated"  微信窗口被激活（用户已看到）
      kind = "raw"        仅 probe 模式：事件及窗口句柄、进程 ID
    """

    def __init__(self, exe_names, on_event, probe=False, tray_enabled=False):
        super().__init__(daemon=True, name="ShellHookListener")
        self.exe_names = {n.lower() for n in exe_names}
        self.on_event = on_event
        self.probe = probe
        self.tray_enabled = tray_enabled
        self.hwnd = None
        self.tray_data = None
        self.tray_icon_owned = False
        self.ready = threading.Event()
        self.error = None
        self._wndproc_ref = None
        self.total = 0            # 收到的 SHELLHOOK 消息总数（任何类型）
        self.seen_codes = set()   # 出现过的 wParam 类型
        self.last_exception = None

    # -- helpers
    def _classify_window(self, hwnd):
        """返回 (是否微信, exe 路径或空串, 窗口标题)。"""
        exe = process_image(hwnd)
        if exe:
            return os.path.basename(exe).lower() in self.exe_names, exe, ""
        title = window_title(hwnd)
        return title.strip().lower() in WECHAT_TITLES, "", title

    def _on_shell_message(self, code, lparam):
        self.total += 1
        self.seen_codes.add(code)
        if code not in (HSHELL_FLASH, HSHELL_WINDOWACTIVATED,
                        HSHELL_RUDEAPPACTIVATED, HSHELL_REDRAW):
            return
        mask = (1 << (8 * ctypes.sizeof(ctypes.c_void_p))) - 1
        target = lparam & mask
        wechat, exe, title = self._classify_window(target)
        target_pid = wintypes.DWORD(0)
        _u.GetWindowThreadProcessId(target, ctypes.byref(target_pid))
        main_hwnd = (resolve_wechat_main_window(
            target, target_pid.value, self.exe_names) if wechat else 0)
        state_key = main_hwnd or -int(target_pid.value or target or 1)

        if self.probe:
            self.on_event("raw", (code, exe or "?", wechat, title,
                                   int(target), int(target_pid.value),
                                   int(main_hwnd)))
        if not wechat:
            return

        if code == HSHELL_FLASH:
            # 只忽略同一微信实例的前台窗口；另一个登录实例仍需单独提醒。
            fg = _u.GetForegroundWindow()
            if self._classify_window(fg)[0]:
                fg_pid = wintypes.DWORD(0)
                _u.GetWindowThreadProcessId(fg, ctypes.byref(fg_pid))
                if fg_pid.value == target_pid.value:
                    return
            self.on_event("flash", (int(state_key), int(target_pid.value)))
        elif code in (HSHELL_WINDOWACTIVATED, HSHELL_RUDEAPPACTIVATED):
            self.on_event("activated", (int(state_key), int(target_pid.value)))

    def _add_tray_icon(self, hwnd):
        if self.tray_data is not None:
            return
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "wechat_capsule.ico")
        icon = _u.LoadImageW(
            None, icon_path, IMAGE_ICON,
            _u.GetSystemMetrics(49), _u.GetSystemMetrics(50), LR_LOADFROMFILE,
        )
        self.tray_icon_owned = bool(icon)
        if not icon:
            resource = ctypes.cast(ctypes.c_void_p(IDI_APPLICATION), wintypes.LPCWSTR)
            icon = _u.LoadIconW(None, resource)
        if not icon:
            raise ctypes.WinError(ctypes.get_last_error())

        data = NOTIFYICONDATAW()
        data.cbSize = ctypes.sizeof(data)
        data.hWnd = hwnd
        data.uID = 1
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        data.uCallbackMessage = WM_TRAY_CALLBACK
        data.hIcon = icon
        data.szTip = "微信消息胶囊"
        if not _shell.Shell_NotifyIconW(NIM_ADD, ctypes.byref(data)):
            if self.tray_icon_owned:
                _u.DestroyIcon(icon)
                self.tray_icon_owned = False
            raise ctypes.WinError(ctypes.get_last_error())
        self.tray_data = data

    def _remove_tray_icon(self):
        if self.tray_data is None:
            return
        data, self.tray_data = self.tray_data, None
        try:
            _shell.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(data))
        finally:
            if self.tray_icon_owned:
                _u.DestroyIcon(data.hIcon)
                self.tray_icon_owned = False

    def _show_tray_menu(self, hwnd):
        menu = _u.CreatePopupMenu()
        if not menu:
            return
        command = 0
        try:
            _u.AppendMenuW(menu, MF_STRING, TRAY_CMD_MESSAGES, "消息记录")
            _u.AppendMenuW(menu, MF_STRING, TRAY_CMD_RESTORE, "恢复胶囊位置")
            _u.AppendMenuW(menu, MF_STRING, TRAY_CMD_COPY_INTERFACE, "复制接口")
            _u.AppendMenuW(menu, MF_STRING, TRAY_CMD_DOCUMENTATION, "查看文档")
            _u.AppendMenuW(menu, MF_STRING, TRAY_CMD_GITHUB, "GitHub")
            _u.AppendMenuW(menu, MF_STRING, TRAY_CMD_CHECK_UPDATES, "检查更新")
            _u.AppendMenuW(menu, MF_STRING, TRAY_CMD_EXIT, "退出")
            point = wintypes.POINT()
            _u.GetCursorPos(ctypes.byref(point))
            _u.SetForegroundWindow(hwnd)
            command = _u.TrackPopupMenu(
                menu, TPM_RETURNCMD | TPM_RIGHTBUTTON,
                point.x, point.y, 0, hwnd, None,
            )
        finally:
            _u.DestroyMenu(menu)
            _u.PostMessageW(hwnd, WM_NULL, 0, 0)

        if command == TRAY_CMD_RESTORE:
            self.on_event("tray_restore", None)
        elif command == TRAY_CMD_MESSAGES:
            self.on_event("tray_messages", None)
        elif command == TRAY_CMD_COPY_INTERFACE:
            self.on_event("tray_copy_interface", None)
        elif command == TRAY_CMD_DOCUMENTATION:
            self.on_event("tray_documentation", None)
        elif command == TRAY_CMD_GITHUB:
            self.on_event("tray_github", None)
        elif command == TRAY_CMD_CHECK_UPDATES:
            self.on_event("tray_check_updates", None)
        elif command == TRAY_CMD_EXIT:
            self.on_event("tray_exit", None)

    def _on_tray_message(self, hwnd, event):
        # 左键或右键单击托盘图标都打开简洁菜单。
        if event in (WM_LBUTTONUP, WM_RBUTTONUP, WM_CONTEXTMENU):
            self._show_tray_menu(hwnd)

    # -- thread body
    def run(self):
        try:
            self._pump()
        except Exception as exc:  # noqa: BLE001
            self.error = exc
            self.ready.set()

    def _pump(self):
        shellhook_msg = _u.RegisterWindowMessageW("SHELLHOOK")

        def wndproc(hwnd, msg, wparam, lparam):
            if msg == shellhook_msg:
                try:
                    self._on_shell_message(int(wparam), int(lparam))
                except Exception:  # noqa: BLE001  异常不能让窗口过程崩溃，但要记录
                    self.last_exception = traceback.format_exc()
                    if self.probe:
                        print("[错误] 处理 Shell 消息时出现异常：\n" + self.last_exception)
                return 0
            if msg == WM_TRAY_CALLBACK and self.tray_enabled:
                try:
                    self._on_tray_message(hwnd, int(lparam))
                except Exception:  # noqa: BLE001
                    self.last_exception = traceback.format_exc()
                return 0
            if msg == WM_DESTROY:
                self._remove_tray_icon()
                _u.PostQuitMessage(0)
                return 0
            return _u.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._wndproc_ref = WNDPROC(wndproc)  # 必须保持引用，否则被 GC 会崩溃
        hinst = _k.GetModuleHandleW(None)
        class_name = "WeChatCapsuleShellHook"

        wc = WNDCLASSW()
        wc.lpfnWndProc = self._wndproc_ref
        wc.hInstance = hinst
        wc.lpszClassName = class_name
        if not _u.RegisterClassW(ctypes.byref(wc)):
            raise ctypes.WinError(ctypes.get_last_error())

        # 注意：必须是顶层窗口（不能用 HWND_MESSAGE），否则收不到 Shell Hook 广播
        hwnd = _u.CreateWindowExW(
            WS_EX_TOOLWINDOW, class_name, "", WS_POPUP,
            0, 0, 0, 0, None, None, hinst, None,
        )
        if not hwnd:
            raise ctypes.WinError(ctypes.get_last_error())
        if not _u.RegisterShellHookWindow(hwnd):
            raise ctypes.WinError(ctypes.get_last_error())

        self.hwnd = hwnd
        if self.tray_enabled:
            self._add_tray_icon(hwnd)
        self.ready.set()

        msg = wintypes.MSG()
        while _u.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            _u.TranslateMessage(ctypes.byref(msg))
            _u.DispatchMessageW(ctypes.byref(msg))

        self._remove_tray_icon()
        _u.DeregisterShellHookWindow(hwnd)

    def stop(self):
        if self.hwnd:
            _u.PostMessageW(self.hwnd, WM_CLOSE, 0, 0)


# ----------------------------------------------------------------------------
# 胶囊 UI —— 优先 Pillow + 分层窗口（抗锯齿、阴影、弹簧动画），否则退回 tkinter
# ----------------------------------------------------------------------------
try:
    from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont
    HAVE_PIL = True
except ImportError:  # 没装 Pillow 时使用简易 tkinter 版本
    HAVE_PIL = False

try:
    import numpy as np
except ImportError:  # Pillow fallback keeps the island usable without glass fields.
    np = None


def _clamp(v, lo=0.0, hi=1.0):
    return lo if v < lo else hi if v > hi else v


# 内嵌的微信图标（192x192 PNG，已裁掉透明边）。想换图标：python wechat_capsule.py --icon 你的.png
WECHAT_ICON_B64 = (
    "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"
    "kP82/xsBWgHcgOaAqUDHwJWBfUGkoAVB1UEPgs2CRcE9IXBIYMj2kLvzDecL53eFgtCA0O2h98KMw5aFfR+OCQ8Lrwl/GGET"
    "URDRv4C6YMmClgWvIr0iyyLvRJlESaJ6oxWjE6Kbo1/HeMeUx0hjrWJXxl6K04gTxHXHY+Oj45vipxf6LNy5cDzBPqE44foi"
    "40V5iy4s1licvvj4EsUlnCVHEtGJMYktie85oZwGzvTSgKW1S6e4bO4u7hOeB28Hb5Lvyi/nTyS5JpUnPUp2Td6ePJninlKR"
    "8lTAFlQLnqf6p9alvk4LTduf9ik9Jr09A5eRmHFUSBGmCfsytTPzMoezzLOKs6TLnJftXDYlChI1ZUPZi7K7xTTZz9SAxESy"
    "XjKa45ZTk/MmNzr3SJ5ynjBvYLnZ8k3LJ/J9879egVrBXdFboFuwtmB0pefK+lXQqqWrelfrry5aPb7Gb82BtYS1aWt/KLQu"
    "LC98uS5mXU+RVtGaorH1futbixWKRcU3NrhsqNuI2ijYOLhp7qaqTR9LeCUXS61LK0rfb+ZuvviVzVeVX33akrRlsMyhbM9W"
    "zFbh1uvb3LcdKFcuzy8f2x6yvXMHY0fJjpc7l+y8UGFXUbeLsEuyS1oZXNldZVC1tep9dUr1SI1XTXutZu2m2te7ebuv7PHY"
    "01anVVda926vYO/Ner/6zgajhop9mH05+x42Rjf2f836urlJo6m06cN+4X7pgYgDfc2Ozc0tmi1lrXCrpHXyYMLBy994f9Pd"
    "xmyrb6e3lx4ChySHHn+b+O31w0GHe4+wjrR9Z/hdbQe1o6QT6lzeOdWV0iXtjusePhp4tLfHpafje8vv9x/TPVZzXOV42QnC"
    "iaITn07mn5w+lXXq6enk02O9S3rvnIk9c60vvG/wbNDZ8+d8z53p9+w/ed71/LELzheOXmRd7LrkcKlzwH6g4wf7HzoGHQY7"
    "hxyHui87Xe4Znjd84or7ldNXva+euxZw7dLI/JHh61HXb95IuCG9ybv56Fb6ree3c27P3FlzF3235J7SvYr7mvcbfjT9sV3q"
    "ID0+6j068GDBgztj3LEnP2X/9H686CH5YcWEzkTzI9tHxyZ9Jy8/Xvh4/EnWk5mnxT8r/1z7zOTZd794/DIwFTs1/lz0/NOv"
    "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"
    "RK5CYII="
)

ICON_OVERRIDE = None
_icon_src = None

CONFIG_PATH = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")),
                           "wechat_capsule.json")
DATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")),
                        "WeixinMsgIsland")
MESSAGE_DB_PATH = os.path.join(DATA_DIR, "messages.sqlite3")
DEFAULT_RECEIVE_HOST = "0.0.0.0"
DEFAULT_RECEIVE_PORT = 8080
DOCUMENTATION_URL = (
    "https://rcn7yg9nflbn.feishu.cn/wiki/EyaswUU3ti3Bv0kTDmpc2YwInab"
    "?from=from_copylink"
)
GITHUB_URL = "https://github.com/likeyun/WeixinMsgIsland"
GITHUB_LATEST_RELEASE_API = (
    "https://api.github.com/repos/likeyun/WeixinMsgIsland/releases/latest"
)
GITHUB_RELEASES_URL = f"{GITHUB_URL}/releases"
APP_VERSION = "1.1.0"
THEME_DEFAULT = "default"
THEME_LIQUID_GLASS = "liquid_glass"
THEME_MILK = "glass_milk"
THEME_CHROME = "glass_chrome"
THEME_BLUE_FLOW = "blue_flow"
THEME_RAINBOW = "rainbow_glass"
THEME_DROPLET = "liquid_droplet"
THEME_CLEAR_LEGACY = "clear_glass"
THEME_RGB_NEON = "rgb_neon"
THEME_TEAL_BREATH = "teal_breath"
THEME_SPECTRUM = "pastel_spectrum"
THEME_AURORA = "teal_aurora"
THEME_OPTIONS = (
    THEME_MILK, THEME_CHROME, THEME_BLUE_FLOW, THEME_RAINBOW, THEME_DROPLET,
    THEME_RGB_NEON, THEME_TEAL_BREATH, THEME_SPECTRUM, THEME_AURORA,
)
THEME_LIGHT_OPTIONS = {THEME_MILK, THEME_RAINBOW, THEME_SPECTRUM}
THEME_DARK_OPTIONS = {
    THEME_CHROME, THEME_BLUE_FLOW, THEME_RGB_NEON, THEME_TEAL_BREATH,
    THEME_AURORA,
}
THEME_ANIMATED_OPTIONS = {
    THEME_BLUE_FLOW, THEME_DROPLET, THEME_TEAL_BREATH, THEME_AURORA,
}
THEME_MENU_LABELS = (
    (THEME_MILK, "01 · 乳白玻璃"),
    (THEME_CHROME, "02 · 银边深色玻璃"),
    (THEME_BLUE_FLOW, "03 · 蓝色流光"),
    (THEME_RAINBOW, "04 · 柔彩虹玻璃"),
    (THEME_DROPLET, "05 · 液态玻璃水滴"),
    (THEME_RGB_NEON, "06 · RGB 霓虹边"),
    (THEME_TEAL_BREATH, "07 · 青绿呼吸边"),
    (THEME_SPECTRUM, "08 · 日光彩谱"),
    (THEME_AURORA, "09 · 青绿极光"),
)
GLASS_BLUR_RADIUS = 0.9
GLASS_REFRACTION_STRENGTH = 6.4
GLASS_SHADOW_STRENGTH = 0.15


def load_config():
    """读取用户配置；文件缺失或损坏时回退为空配置。"""
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def save_config_fields(values=None, remove=()):
    """合并保存配置字段，保留位置、主题及未来新增设置。"""
    data = load_config()
    for key in remove:
        data.pop(key, None)
    if values:
        data.update(values)
    tmp_path = CONFIG_PATH + ".tmp"
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH) or ".", exist_ok=True)
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, CONFIG_PATH)
    except (OSError, TypeError, ValueError):
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        pass


def get_receive_token(override=None):
    """返回接口令牌；未配置时首次生成随机令牌并持久化。"""
    if override is not None:
        token = str(override).strip()
        if not token:
            raise ValueError("消息接口令牌不能为空")
        return token

    token = load_config().get("receive_token")
    if isinstance(token, str) and token.strip():
        return token.strip()

    token = secrets.token_urlsafe(32)
    save_config_fields({"receive_token": token})
    if load_config().get("receive_token") != token:
        raise OSError(f"无法将消息接口令牌保存到配置文件：{CONFIG_PATH}")
    return token


def build_receive_endpoint(token, port):
    """生成可直接复制的局域网接口示例地址。"""
    return (f"http://{get_lan_ip()}:{int(port)}/receive"
            f"?content=[msg]&token={token}")


def copy_receive_endpoint(root, token, port):
    endpoint = build_receive_endpoint(token, port)
    root.clipboard_clear()
    root.clipboard_append(endpoint)
    root.update_idletasks()
    return endpoint


def open_documentation():
    try:
        webbrowser.open(DOCUMENTATION_URL, new=2)
    except Exception as exc:  # noqa: BLE001
        if sys.stderr is not None:
            print(f"无法打开文档链接：{exc}", file=sys.stderr)


def open_github():
    try:
        webbrowser.open(GITHUB_URL, new=2)
    except Exception as exc:  # noqa: BLE001
        if sys.stderr is not None:
            print(f"无法打开 GitHub 仓库：{exc}", file=sys.stderr)


def release_version_parts(version):
    parts = re.findall(r"\d+", str(version))
    if not parts:
        raise ValueError(f"无法识别发行版版本号：{version}")
    return tuple(int(part) for part in parts)


def is_release_newer(latest, current):
    latest_parts = release_version_parts(latest)
    current_parts = release_version_parts(current)
    width = max(len(latest_parts), len(current_parts))
    latest_parts += (0,) * (width - len(latest_parts))
    current_parts += (0,) * (width - len(current_parts))
    return latest_parts > current_parts


def check_github_release_async(events):
    """在线程中读取 GitHub 最新正式发行版，避免阻塞 Tk 消息循环。"""
    def worker():
        try:
            request = Request(
                GITHUB_LATEST_RELEASE_API,
                headers={"Accept": "application/vnd.github+json",
                         "User-Agent": "WeixinMsgIsland-update-check"},
            )
            with urlopen(request, timeout=8) as response:
                release = json.loads(response.read().decode("utf-8"))
            tag = release.get("tag_name")
            if not tag:
                raise ValueError("GitHub 返回的发行版没有版本标签")
            release_url = release.get("html_url", GITHUB_RELEASES_URL)
            if not release_url.startswith(GITHUB_RELEASES_URL + "/"):
                release_url = GITHUB_RELEASES_URL
            events.put(("update_result", {
                "latest": str(tag),
                "url": release_url,
                "is_newer": is_release_newer(tag, APP_VERSION),
            }))
        except Exception as exc:  # noqa: BLE001
            events.put(("update_result", {"error": str(exc)}))

    threading.Thread(target=worker, daemon=True,
                     name="GitHubReleaseCheck").start()


def show_update_result(result):
    if result.get("error"):
        message = f"检查更新失败：{result['error']}\n请检查网络连接后重试。"
        ctypes.windll.user32.MessageBoxW(None, message, "检查更新", 0x10)
        return

    latest = result["latest"]
    if result["is_newer"]:
        message = (f"发现新版本 {latest}（当前版本 v{APP_VERSION}）。\n"
                   "是否打开 GitHub Releases 查看并下载？")
        answer = ctypes.windll.user32.MessageBoxW(
            None, message, "发现新版本", 0x24)
        if answer == 6:  # IDYES
            webbrowser.open(result["url"], new=2)
    else:
        ctypes.windll.user32.MessageBoxW(
            None, f"当前已是最新版本（{latest}）。", "检查更新", 0x40)


def load_position():
    """读取上次拖动后的位置：(胶囊中心 x, 胶囊顶部 y)，没有则返回 None。"""
    data = load_config()
    try:
        cx, ty = float(data["cx"]), float(data["ty"])
        return (cx, ty) if math.isfinite(cx) and math.isfinite(ty) else None
    except (KeyError, TypeError, ValueError):
        return None


def load_theme():
    theme = load_config().get("theme")
    if theme == THEME_LIQUID_GLASS:  # Keep settings created by the first glass build.
        return THEME_CHROME
    if theme == THEME_CLEAR_LEGACY:
        return THEME_DROPLET
    return theme if theme in (THEME_DEFAULT, *THEME_OPTIONS) else THEME_DEFAULT


def normalize_theme(theme):
    if theme == THEME_LIQUID_GLASS:
        return THEME_CHROME
    if theme == THEME_CLEAR_LEGACY:
        return THEME_DROPLET
    return theme if theme in (THEME_DEFAULT, *THEME_OPTIONS) else THEME_DEFAULT


def save_position(pos):
    """保存位置；pos 为 None 时只移除位置，保留主题设置。"""
    if pos is None:
        save_config_fields(remove=("cx", "ty"))
    else:
        save_config_fields({"cx": float(pos[0]), "ty": float(pos[1])})


class MessageStore:
    """把局域网接口收到的消息保存到本机 SQLite，并记录已读状态。"""

    def __init__(self, path=MESSAGE_DB_PATH):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        with closing(self._connect()) as db, db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received_at TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    content TEXT NOT NULL,
                    is_read INTEGER NOT NULL DEFAULT 0,
                    read_at TEXT
                )
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def add(self, content, source_ip, received_at):
        with closing(self._connect()) as db, db:
            cursor = db.execute(
                "INSERT INTO messages (received_at, source_ip, content) VALUES (?, ?, ?)",
                (received_at, source_ip, content),
            )
            return {
                "id": cursor.lastrowid,
                "received_at": received_at,
                "source_ip": source_ip,
                "content": content,
                "is_read": False,
            }

    def list_messages(self, limit=500):
        with closing(self._connect()) as db, db:
            rows = db.execute(
                "SELECT id, received_at, source_ip, content, is_read, read_at "
                "FROM messages ORDER BY id DESC LIMIT ?", (int(limit),)
            ).fetchall()
        return [dict(row) for row in rows]

    def latest_unread(self):
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT id, received_at, source_ip, content, is_read, read_at "
                "FROM messages WHERE is_read = 0 ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def get_message(self, message_id):
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT id, received_at, source_ip, content, is_read, read_at "
                "FROM messages WHERE id = ?", (int(message_id),)
            ).fetchone()
        return dict(row) if row else None

    def latest_message(self):
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT id, received_at, source_ip, content, is_read, read_at "
                "FROM messages ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def mark_read(self, message_id):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with closing(self._connect()) as db, db:
            db.execute(
                "UPDATE messages SET is_read = 1, read_at = ? WHERE id = ?",
                (now, int(message_id)),
            )

    def mark_all_read(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with closing(self._connect()) as db, db:
            db.execute(
                "UPDATE messages SET is_read = 1, read_at = ? WHERE is_read = 0",
                (now,),
            )


class MessageRequestHandler(BaseHTTPRequestHandler):
    """兼容现有 GET /receive?content=...&token=... 接口。"""

    server_version = "WeixinMsgIsland/1.0"

    def log_message(self, _format, *_args):
        # URL 中包含 token 和消息正文，不写入访问日志。
        pass

    def send_json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path not in ("/", "/receive"):
            return self.send_json(404, {"success": False, "msg": "接口不存在"})

        params = parse_qs(parsed.query, keep_blank_values=True)
        content = params.get("content", [None])[0]
        token = params.get("token", [""])[0]
        if not hmac.compare_digest(token.encode("utf-8"),
                                    self.server.receive_token.encode("utf-8")):
            return self.send_json(403, {"success": False, "msg": "Token 验证失败"})
        if content is None or not content.strip():
            return self.send_json(400, {"success": False, "msg": "content 不能为空"})
        if len(content) > 10000:
            return self.send_json(413, {"success": False, "msg": "内容不能超过10000个字符"})

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        source_ip = self.client_address[0]
        try:
            message = self.server.message_store.add(content, source_ip, now)
        except sqlite3.Error:
            return self.send_json(500, {"success": False, "msg": "消息本地保存失败"})

        self.server.on_message(message)
        return self.send_json(200, {
            "success": True,
            "msg": "接收成功",
            "data": {"content": content, "time": now},
        })


class EmbeddedMessageServer(ThreadingHTTPServer):
    """由灵动岛进程托管的局域网消息接收服务。"""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, token, message_store, on_message):
        self.receive_token = token
        self.message_store = message_store
        self.on_message = on_message
        super().__init__(address, MessageRequestHandler)


def _strip_notification_prefix(line):
    """移除转发标题里的“来自”和未读条数前缀。"""
    cleaned = " ".join(str(line).split()).strip()
    had_prefix = False
    for _ in range(3):
        previous = cleaned
        cleaned, count = re.subn(r"^来自\s*", "", cleaned, count=1)
        had_prefix = had_prefix or bool(count)
        cleaned, count = re.subn(
            r"^[\[【]\s*\d+\s*条\s*[\]】]\s*", "", cleaned, count=1)
        had_prefix = had_prefix or bool(count)
        if cleaned == previous:
            break
    return cleaned.strip(), had_prefix


def summarize_message(content):
    """从未带发送人标记的正文中去掉常见传输元数据。"""
    lines = [" ".join(line.split()) for line in str(content).splitlines()]
    lines = [line for line in lines if line]
    meaningful = []
    for line in lines:
        line, _had_prefix = _strip_notification_prefix(line)
        if not line:
            continue
        if re.match(
                r"^(?:SIM\d*[_\s-]|SubId\s*:|UID\s*[:：]|QCOM\b|"
                r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",
                line, re.IGNORECASE):
            continue
        if re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", line):
            continue
        if line == "liKeYun科技":
            continue
        if re.fullmatch(r"[+\d().\-\s]{7,}", line):
            continue
        for opening, closing in (("【", "】"), ("（", "）"), ("(", ")"),
                                 ("[", "]")):
            if line.startswith(opening) and closing in line:
                _, body = line.split(closing, 1)
                line = body.strip() or line
                break
        meaningful.append(line)
    return " · ".join(meaningful[:2]) if meaningful else "收到一条新消息"


def extract_message_details(content):
    """提取发送人和正文，去掉条数、来源前缀及转发服务元数据。"""
    senders = []
    bodies = []
    unlabelled_bodies = []
    metadata = re.compile(
        r"^(?:SIM\d*[_\s-]|SubId\s*:|UID\s*[:：]|QCOM\b|"
        r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",
        re.IGNORECASE,
    )
    package_name = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")
    for raw_line in str(content).splitlines():
        line = " ".join(raw_line.split()).strip()
        if not line:
            continue
        clean_line, had_prefix = _strip_notification_prefix(line)
        if (not clean_line or metadata.match(line) or metadata.match(clean_line)
                or package_name.fullmatch(line) or package_name.fullmatch(clean_line)):
            continue
        if clean_line == "liKeYun科技":
            continue
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", clean_line):
            unlabelled_bodies.append(clean_line)
            continue

        sender_field = re.match(r"^(?:发送人|联系人|发件人)\s*[:：]\s*(.+)$", clean_line)
        if sender_field:
            sender_value, _ = _strip_notification_prefix(sender_field.group(1))
            sender_value = sender_value.strip(" ：:-")
            if sender_value:
                quoted_sender = re.match(r'^["“「](.+?)["”」]\s*(.*)$', sender_value)
                if quoted_sender:
                    sender_value = quoted_sender.group(1).strip()
                    if quoted_sender.group(2).strip():
                        bodies.append(quoted_sender.group(2).strip())
                if sender_value and sender_value not in senders:
                    senders.append(sender_value)
            continue

        body_field = re.match(r"^(?:消息内容|正文|内容)\s*[:：]\s*(.+)$", clean_line)
        if body_field:
            unlabelled_bodies.append(body_field.group(1).strip())
            continue

        quoted = re.match(r'^["“「](.+?)["”」]\s*(.*)$', clean_line)
        if quoted:
            sender, body = quoted.group(1).strip(), quoted.group(2).strip()
        else:
            labeled = re.match(r"^([^:：]{1,40})[:：]\s*(.+)$", clean_line)
            if labeled:
                sender, body = labeled.group(1).strip(), labeled.group(2).strip()
            elif had_prefix:
                # 常见通知标题：“来自 [13条] 联系人名”。
                sender, body = clean_line.strip(" ：:-"), ""
            else:
                unlabelled_bodies.append(clean_line)
                continue

        if sender and sender not in senders:
            senders.append(sender)
        if body:
            bodies.append(body)

    if senders:
        message_parts = (bodies + unlabelled_bodies)[:2]
        return "、".join(senders), " · ".join(message_parts) or "收到一条新消息"
    return "", summarize_message(content)


def truncate_display_text(text, max_units):
    """按中文宽字符近似截断单行摘要，避免简易 Tk 胶囊换行溢出。"""
    value = " ".join(str(text).split())
    units = 0.0
    result = []
    for char in value:
        width = 1.0 if ord(char) > 255 else 0.55
        if units + width > max_units:
            return "".join(result).rstrip() + "…"
        result.append(char)
        units += width
    return value


class IslandMessagePanel:
    """Windowless message detail state; IslandRenderer paints it into the island."""

    MAX_HISTORY_ROWS = 6

    def __init__(self, root, store, get_anchor=None, on_read=None, scale=1.0,
                 on_change=None):
        self.root = root  # Kept for call compatibility; no Toplevel is created.
        self.store = store
        self.get_anchor = get_anchor
        self.on_read = on_read or (lambda _message_id=None: None)
        self.on_change = on_change or (lambda: None)
        self.scale = scale
        self.current_message = None
        self.active_tab = "current"
        self.rows = []
        self.selected_index = -1
        self.is_open = False
        self.history_scroll = 0
        self.body_scroll = 0
        self.body_scroll_max = 0

    def _changed(self):
        self.on_change()

    def set_current(self, message):
        self.current_message = message
        if self.is_open and self.active_tab == "current":
            self.body_scroll = 0
            self.body_scroll_max = 0
            self._changed()

    def show_current(self, message):
        self.current_message = message
        self.active_tab = "current"
        self.body_scroll = 0
        self.body_scroll_max = 0
        self.open()

    def show_history(self):
        self.active_tab = "history"
        self.refresh_history(notify=False)
        self.open()

    def open(self):
        if not self.is_open:
            self.is_open = True
        self._changed()

    def close(self):
        if self.is_open:
            self.is_open = False
            self._changed()

    def toggle(self, message=None):
        if self.is_open:
            self.close()
        else:
            self.show_current(message or self.current_message or self.store.latest_message())

    def select_tab(self, tab):
        if tab not in ("current", "history"):
            return
        self.active_tab = tab
        self.body_scroll = 0
        self.body_scroll_max = 0
        if tab == "history":
            self.refresh_history(notify=False)
        self._changed()

    def refresh_history(self, select_id=None, notify=True):
        self.rows = self.store.list_messages()
        if not self.rows:
            self.selected_index = -1
        elif select_id is not None:
            self.selected_index = next(
                (i for i, row in enumerate(self.rows)
                 if int(row["id"]) == int(select_id)), 0)
        elif self.selected_index < 0 or self.selected_index >= len(self.rows):
            self.selected_index = 0
        self.history_scroll = min(
            self.history_scroll, max(0, len(self.rows) - self.MAX_HISTORY_ROWS))
        if notify:
            self._changed()

    def select_history(self, index):
        if not 0 <= int(index) < len(self.rows):
            return
        self.selected_index = int(index)
        row = self.rows[self.selected_index]
        if not bool(row.get("is_read", False)):
            self.store.mark_read(row["id"])
            row["is_read"] = 1
            self.on_read(row["id"])
        self.body_scroll = 0
        self.body_scroll_max = 0
        self._changed()

    def mark_current_read(self):
        message = self.current_message
        if not message or bool(message.get("is_read", False)):
            return
        self.store.mark_read(message["id"])
        message["is_read"] = 1
        self.on_read(message["id"])
        self._changed()

    def mark_all_read(self):
        self.store.mark_all_read()
        self.refresh_history(notify=False)
        if self.current_message:
            self.current_message["is_read"] = 1
        self.on_read(None)
        self._changed()

    def scroll(self, region, delta):
        try:
            delta = int(delta)
        except (TypeError, ValueError):
            return False
        if delta == 0:
            return False
        step = -1 if delta > 0 else 1
        steps = min(8, max(1, abs(delta) // 120))
        if region == "history":
            new_scroll = min(
                max(0, len(self.rows) - self.MAX_HISTORY_ROWS),
                max(0, self.history_scroll + step * steps))
            if new_scroll == self.history_scroll:
                return False
            self.history_scroll = new_scroll
        elif region == "body":
            if self.active_tab == "history":
                selected = (self.rows[self.selected_index]
                            if 0 <= self.selected_index < len(self.rows) else {})
                body = extract_message_details(selected.get("content", ""))[1]
            else:
                body = extract_message_details(
                    (self.current_message or {}).get("content", ""))[1]
            line_count = sum(max(1, math.ceil(sum(
                1.0 if ord(char) > 255 else 0.55 for char in line) / 22.0))
                for line in body.splitlines() or [body])
            max_scroll = (self.body_scroll_max if self.body_scroll_max > 0
                          else max(0, line_count - 5))
            new_scroll = min(max_scroll,
                             max(0, self.body_scroll + step * 2 * steps))
            if new_scroll == self.body_scroll:
                return False
            self.body_scroll = new_scroll
        else:
            return False
        self._changed()
        return True

    def view_model(self):
        message = self.current_message or {}
        sender, body = extract_message_details(message.get("content", ""))
        selected = (self.rows[self.selected_index]
                    if 0 <= self.selected_index < len(self.rows) else None)
        hist_sender, hist_body = extract_message_details(
            selected.get("content", "") if selected else "")
        rows = []
        for row in self.rows:
            row_sender, row_body = extract_message_details(row.get("content", ""))
            rows.append({
                "id": row.get("id"), "sender": row_sender or "微信消息",
                "body": row_body, "unread": not bool(row.get("is_read", False)),
                "time": row.get("received_at", row.get("created_at", row.get("time", ""))),
            })
        return {
            "open": self.is_open, "tab": self.active_tab,
            "sender": sender or "微信消息", "body": body,
            "time": message.get("received_at", message.get("time", "")),
            "unread": bool(message) and not bool(message.get("is_read", False)),
            "rows": rows, "selected_index": self.selected_index,
            "selected_sender": hist_sender or "微信消息", "selected_body": hist_body,
            "selected_time": selected.get("received_at", selected.get("time", "")) if selected else "",
            "history_scroll": self.history_scroll, "body_scroll": self.body_scroll,
        }


class MessageCenter:
    """Route received messages to the island and expose a windowless detail model."""

    def __init__(self, root, store, on_preview, get_anchor=None, scale=1.0,
                 on_detail_change=None):
        self.root = root
        self.store = store
        self.on_preview = on_preview
        self.get_anchor = get_anchor
        self.scale = scale
        self.on_detail_change = on_detail_change or (lambda: None)
        self.panel = None
        self.current_message = None

    def _ensure_panel(self):
        if self.panel is None:
            self.panel = IslandMessagePanel(
                self.root, self.store, self.get_anchor,
                self._refresh_preview, scale=self.scale,
                on_change=self.on_detail_change,
            )
        return self.panel

    def receive(self, message):
        self.current_message = message
        self.on_preview(message)
        if self.panel and self.panel.is_open:
            if self.panel.active_tab == "current":
                self.panel.set_current(message)
            else:
                self.panel.refresh_history()

    def restore_unread(self):
        self.current_message = self.store.latest_unread()
        self.on_preview(self.current_message)

    def _refresh_preview(self, _message_id=None):
        self.current_message = self.store.latest_unread()
        self.on_preview(self.current_message)

    def toggle_current(self, message_id=None):
        panel = self._ensure_panel()
        if panel.is_open:
            panel.close()
            return
        message = (self.store.get_message(message_id) if message_id is not None
                   else self.current_message or self.store.latest_message())
        panel.show_current(message)

    def show_history(self):
        self._ensure_panel().show_history()

    def update_position(self):
        # Kept as a compatibility hook; the single island window owns its position.
        return None


DETAIL_DOUBLE_CLICK_SECONDS = 0.5


def is_detail_double_click(previous, timestamp, x, y, max_distance=10):
    if not previous:
        return False
    last_time, last_x, last_y = previous
    return (timestamp - last_time <= DETAIL_DOUBLE_CLICK_SECONDS
            and max(abs(x - last_x), abs(y - last_y)) <= max_distance)


def mark_all_read_and_open_wechat(message_center, pending_windows,
                                  last_opened_hwnd):
    panel = message_center.panel
    if panel:
        panel.mark_all_read()
        panel.close()
    return open_wechat_target(pending_windows, last_opened_hwnd)

def virtual_screen():
    """整个虚拟桌面（多显示器）的 (x, y, 宽, 高)。"""
    try:
        gm = _u.GetSystemMetrics
        return gm(76), gm(77), gm(78), gm(79)
    except Exception:  # noqa: BLE001
        return 0, 0, 1920, 1080


class Spring:
    """解析积分阻尼弹簧；k=omega²，c=2*zeta*omega。"""

    def __init__(self, value, stiffness=576.0, damping=32.64):
        self.x = float(value)
        self.v = 0.0
        self.target = float(value)
        self.k = stiffness
        self.c = damping
        self._travel = 0.0

    @staticmethod
    def coefficients(omega, zeta):
        """Convert natural frequency and damping ratio to k/c coefficients."""
        omega = max(0.01, float(omega))
        zeta = max(0.0, float(zeta))
        return omega * omega, 2.0 * zeta * omega

    def set_response(self, omega, zeta):
        self.k, self.c = self.coefficients(omega, zeta)
        return self

    def set_target(self, target, stiffness=None, damping=None):
        target = float(target)
        if abs(target - self.target) > 1e-9:
            # Keep current velocity, and scale settling tolerance to this move.
            self._travel = max(abs(target - self.x), abs(target - self.target))
        elif self._travel <= 1e-9:
            self._travel = abs(target - self.x)
        self.target = target
        if stiffness is not None:
            self.k = stiffness
        if damping is not None:
            self.c = damping

    def step(self, dt):
        """解析积分阻尼弹簧，动画速度不再依赖帧率或固定子步长。"""
        if dt <= 0.0:
            return

        y = self.x - self.target
        alpha = self.c * 0.5
        discriminant = self.c * self.c - 4.0 * self.k

        if discriminant < -1e-8:  # 欠阻尼：保留自然的轻微过冲
            omega = math.sqrt(self.k - alpha * alpha)
            decay = math.exp(-alpha * dt)
            cos_t = math.cos(omega * dt)
            sin_t = math.sin(omega * dt)
            b = (self.v + alpha * y) / omega
            self.x = self.target + decay * (y * cos_t + b * sin_t)
            self.v = decay * (
                self.v * cos_t - (alpha * self.v + self.k * y) / omega * sin_t
            )
        elif discriminant > 1e-8:  # 过阻尼
            root = math.sqrt(discriminant)
            r1 = (-self.c + root) * 0.5
            r2 = (-self.c - root) * 0.5
            a = (self.v - r2 * y) / (r1 - r2)
            b = y - a
            e1, e2 = math.exp(r1 * dt), math.exp(r2 * dt)
            self.x = self.target + a * e1 + b * e2
            self.v = a * r1 * e1 + b * r2 * e2
        else:  # 临界阻尼
            decay = math.exp(-alpha * dt)
            b = self.v + alpha * y
            self.x = self.target + decay * (y + b * dt)
            self.v = decay * (self.v - alpha * b * dt)

    @property
    def at_rest(self):
        if self._travel <= 1e-9:
            return abs(self.x - self.target) < 1e-4 and abs(self.v) < 1e-3
        # End the active render loop once the remaining ripple is subpixel and
        # nearly imperceptible; this avoids an unnecessarily long spring tail.
        position_tolerance = max(0.01, self._travel * 0.004)
        velocity_tolerance = max(0.1, self._travel * 0.025)
        return (abs(self.x - self.target) <= position_tolerance
                and abs(self.v) <= velocity_tolerance)

    def snap(self):
        self.x = self.target
        self.v = 0.0
        self._travel = 0.0


def _load_font(size, bold=False):
    win = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts")
    names = ["msyhbd.ttc", "msyh.ttc", "simhei.ttf"] if bold else ["msyh.ttc", "simhei.ttf"]
    cands = [os.path.join(win, n) for n in names]
    cands += [  # 非 Windows 环境（仅用于开发预览）
        "/usr/share/fonts/opentype/noto/NotoSansCJK-%s.ttc" % ("Bold" if bold else "Regular"),
        "/usr/share/fonts/truetype/dejavu/DejaVuSans%s.ttf" % ("-Bold" if bold else ""),
    ]
    for path in cands:
        try:
            return ImageFont.truetype(path, max(int(round(size)), 6))
        except OSError:
            continue
    return ImageFont.load_default()


def _draw_fallback_icon(px):
    """内嵌图标解码失败时，用代码画一个微信风格图标（圆角绿底 + 两个白色气泡），4 倍超采样抗锯齿。"""
    ss = 4
    n = px * ss
    green = (7, 193, 96, 255)
    white = (255, 255, 255, 255)
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, n - 1, n - 1], radius=int(n * 0.26), fill=green)
    # 大气泡（左上）
    d.ellipse([n * 0.13, n * 0.20, n * 0.67, n * 0.64], fill=white)
    d.polygon([(n * 0.24, n * 0.56), (n * 0.20, n * 0.76), (n * 0.40, n * 0.62)], fill=white)
    # 小气泡（右下，带绿色描边与大气泡分隔）
    d.ellipse([n * 0.38, n * 0.40, n * 0.88, n * 0.79], fill=white,
              outline=green, width=max(2, int(n * 0.04)))
    d.polygon([(n * 0.74, n * 0.74), (n * 0.80, n * 0.90), (n * 0.62, n * 0.77)], fill=white)
    # 眼睛
    r1 = n * 0.035
    for cx, cy in ((0.30, 0.37), (0.47, 0.37)):
        d.ellipse([n * cx - r1, n * cy - r1, n * cx + r1, n * cy + r1], fill=green)
    r2 = n * 0.03
    for cx, cy in ((0.57, 0.58), (0.71, 0.58)):
        d.ellipse([n * cx - r2, n * cy - r2, n * cx + r2, n * cy + r2], fill=green)
    return img.resize((px, px), Image.LANCZOS)


def _icon_source():
    global _icon_src
    if _icon_src is None:
        try:
            if ICON_OVERRIDE:
                img = Image.open(ICON_OVERRIDE).convert("RGBA")
            else:
                img = Image.open(io.BytesIO(base64.b64decode(WECHAT_ICON_B64))).convert("RGBA")
            bbox = img.getchannel("A").getbbox()
            if bbox:
                img = img.crop(bbox)
            side = max(img.size)  # 补成正方形，避免拉伸变形
            square = Image.new("RGBA", (side, side), (0, 0, 0, 0))
            square.paste(img, ((side - img.width) // 2, (side - img.height) // 2))
            _icon_src = square
        except Exception:  # noqa: BLE001
            _icon_src = False
    return _icon_src


def load_wechat_icon(px):
    src = _icon_source()
    if not src:
        return _draw_fallback_icon(px)
    return src.resize((px, px), Image.LANCZOS)


class ScreenBackgroundCapture:
    """Capture only the island's screen rectangle into a reusable in-memory DIB."""

    REFRESH_SECONDS = 0.06
    SRCCOPY = 0x00CC0020  # Intentionally omit CAPTUREBLT: layered windows stay excluded.

    def __init__(self, width):
        self.width = max(1, int(width))
        self.g = ctypes.WinDLL("gdi32", use_last_error=True)
        self.g.CreateCompatibleDC.argtypes = [wintypes.HDC]
        self.g.CreateCompatibleDC.restype = wintypes.HDC
        self.g.DeleteDC.argtypes = [wintypes.HDC]
        self.g.DeleteDC.restype = wintypes.BOOL
        self.g.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
        self.g.SelectObject.restype = wintypes.HGDIOBJ
        self.g.DeleteObject.argtypes = [wintypes.HGDIOBJ]
        self.g.DeleteObject.restype = wintypes.BOOL
        self.g.CreateDIBSection.argtypes = [
            wintypes.HDC, ctypes.c_void_p, wintypes.UINT,
            ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE, wintypes.DWORD,
        ]
        self.g.CreateDIBSection.restype = wintypes.HBITMAP
        self.g.BitBlt.argtypes = [
            wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HDC, ctypes.c_int, ctypes.c_int, wintypes.DWORD,
        ]
        self.g.BitBlt.restype = wintypes.BOOL

        class BITMAPINFOHEADER(ctypes.Structure):
            _fields_ = [
                ("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG),
                ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD),
                ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
                ("biClrImportant", wintypes.DWORD),
            ]

        class BITMAPINFO(ctypes.Structure):
            _fields_ = [("bmiHeader", BITMAPINFOHEADER),
                        ("bmiColors", wintypes.DWORD * 1)]

        self._bitmap_info = BITMAPINFO
        self._bitmap_header = BITMAPINFOHEADER
        self.memdc = self.g.CreateCompatibleDC(None)
        if not self.memdc:
            raise ctypes.WinError(ctypes.get_last_error())
        self.bitmap = None
        self.old_bitmap = None
        self.bits = None
        self.capacity_h = 0
        self.cache_rect = None
        self.cache_height = 0
        self.cache_image = None
        self.cache_views = {}
        self.last_capture_at = 0.0
        self.last_capture_ms = 0.0
        self.cache_hits = 0

    def _ensure_capacity(self, height):
        if height <= self.capacity_h:
            return
        height = max(64, int(math.ceil(height / 64.0) * 64))
        info = self._bitmap_info()
        info.bmiHeader.biSize = ctypes.sizeof(self._bitmap_header)
        info.bmiHeader.biWidth = self.width
        info.bmiHeader.biHeight = -height  # Top-down BGRA rows.
        info.bmiHeader.biPlanes = 1
        info.bmiHeader.biBitCount = 32
        info.bmiHeader.biCompression = 0
        bits = ctypes.c_void_p()
        bitmap = self.g.CreateDIBSection(
            None, ctypes.byref(info), 0, ctypes.byref(bits), None, 0)
        if not bitmap or not bits.value:
            raise ctypes.WinError(ctypes.get_last_error())
        previous = self.g.SelectObject(self.memdc, bitmap)
        if not previous:
            self.g.DeleteObject(bitmap)
            raise ctypes.WinError(ctypes.get_last_error())
        if self.bitmap:
            self.g.DeleteObject(self.bitmap)
        else:
            self.old_bitmap = previous
        self.bitmap = bitmap
        self.bits = bits.value
        self.capacity_h = height

    def capture(self, x, y, height):
        width, height = self.width, max(1, int(height))
        rect = (int(x), int(y), width)
        now = time.perf_counter()
        if (rect == self.cache_rect and self.cache_height >= height
                and now - self.last_capture_at < self.REFRESH_SECONDS
                and self.cache_image is not None):
            self.cache_hits += 1
            return self._view(height)

        capture_height = max(height, self.cache_height if rect == self.cache_rect else 0)
        capture_height = min(8192, int(math.ceil(capture_height / 64.0) * 64))
        started = time.perf_counter()
        screen_dc = _u.GetDC(None)
        if not screen_dc:
            return self._view(height) if rect == self.cache_rect and self.cache_height >= height else None
        try:
            self._ensure_capacity(capture_height)
            ok = self.g.BitBlt(self.memdc, 0, 0, width, capture_height,
                               screen_dc, int(x), int(y), self.SRCCOPY)
            if not ok:
                return self._view(height) if rect == self.cache_rect and self.cache_height >= height else None
            raw = ctypes.string_at(self.bits, width * capture_height * 4)
            image = Image.frombytes("RGB", (width, capture_height), raw, "raw", "BGRX")
        except Exception:  # noqa: BLE001
            return self._view(height) if rect == self.cache_rect and self.cache_height >= height else None
        finally:
            _u.ReleaseDC(None, screen_dc)

        self.last_capture_ms = (time.perf_counter() - started) * 1000.0
        self.last_capture_at = time.perf_counter()
        self.cache_rect = rect
        self.cache_height = capture_height
        self.cache_image = image
        self.cache_views = {capture_height: image}
        return image if capture_height == height else self._view(height)

    def _view(self, height):
        view = self.cache_views.get(height)
        if view is None:
            view = self.cache_image.crop((0, 0, self.width, height))
            self.cache_views[height] = view
        return view

    def close(self):
        try:
            if self.bitmap:
                if self.old_bitmap:
                    self.g.SelectObject(self.memdc, self.old_bitmap)
                self.g.DeleteObject(self.bitmap)
                self.bitmap = None
            if self.memdc:
                self.g.DeleteDC(self.memdc)
                self.memdc = None
        except Exception:  # noqa: BLE001
            pass


class ScreenBackgroundSampler:
    """Capture the latest island rectangle off the UI thread at a bounded rate."""

    def __init__(self, width):
        self.width = max(1, int(width))
        self._condition = threading.Condition()
        self._request = None
        self._latest = None
        self._closed = False
        self.last_error = ""
        self.last_capture_ms = 0.0
        self._thread = threading.Thread(
            target=self._run, name="GlassBackgroundSampler", daemon=True)
        self._thread.start()

    def request(self, x, y, height):
        request = (int(x), int(y), self.width, max(1, int(height)))
        with self._condition:
            if self._closed:
                return
            self._request = request
            self._condition.notify()

    def get(self, x, y, height):
        rect = (int(x), int(y), self.width)
        height = max(1, int(height))
        with self._condition:
            latest = self._latest
        if latest is None:
            return None
        latest_rect, image = latest
        if latest_rect != rect or image.height < height:
            return None
        return image if image.height == height else image.crop(
            (0, 0, self.width, height))

    def _run(self):
        capture = None
        last_capture_at = 0.0
        try:
            while True:
                with self._condition:
                    while self._request is None and not self._closed:
                        self._condition.wait()
                    if self._closed:
                        return
                    delay = ScreenBackgroundCapture.REFRESH_SECONDS - (
                        time.perf_counter() - last_capture_at)
                    while delay > 0:
                        self._condition.wait(timeout=delay)
                        if self._closed:
                            return
                        delay = ScreenBackgroundCapture.REFRESH_SECONDS - (
                            time.perf_counter() - last_capture_at)
                    request = self._request
                    self._request = None

                if request is None:
                    continue
                if capture is None:
                    capture = ScreenBackgroundCapture(self.width)
                x, y, _width, height = request
                previous_capture_at = capture.last_capture_at
                image = capture.capture(x, y, height)
                last_capture_at = (capture.last_capture_at
                                   if capture.last_capture_at > previous_capture_at
                                   else time.perf_counter())
                self.last_capture_ms = capture.last_capture_ms
                if image is not None:
                    with self._condition:
                        self._latest = ((x, y, self.width), image)
                self.last_error = ""
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
        finally:
            if capture is not None:
                capture.close()

    def close(self):
        with self._condition:
            self._closed = True
            self._condition.notify_all()
        if self._thread.is_alive() and threading.current_thread() is not self._thread:
            self._thread.join(timeout=0.5)


class CapsuleThemeRenderer:
    """Procedural glass palettes and edge lights clipped to the live capsule mask."""

    def __init__(self, scale=1.0):
        self.scale = float(scale)
        self._background = None
        self._background_small = None
        self._base_key = None
        self._base_rgb = None
        self._refract_source = None
        self._refracted = None
        self._refract_size = None
        self._refract_at = 0.0
        self.last_material_ms = 0.0

    def _small_background(self, background, size):
        if background is None:
            if (self._background is None and self._background_small is not None
                    and self._background_small.size == size):
                return self._background_small
            self._background = None
            self._background_small = Image.new("RGB", size, (113, 158, 184))
            self._base_key = None
            return self._background_small
        if background is self._background and self._background_small is not None:
            if self._background_small.size == size:
                return self._background_small
        source = background if background.mode == "RGB" else background.convert("RGB")
        if source.size != size:
            source = source.resize(size, Image.Resampling.BILINEAR)
        # A subpixel polish softens desktop sampling noise without fogging the glass.
        source = source.filter(ImageFilter.GaussianBlur(
            max(0.25, GLASS_BLUR_RADIUS * 0.5 * self.scale)))
        self._background = background
        self._background_small = source
        self._base_key = None
        return source

    @staticmethod
    def _refract(source, mask, scale):
        """A restrained, edge-normal mesh bend over the captured desktop."""
        width, height = source.size
        cell = max(10, int(round(22 * scale)))
        xs = list(range(0, width, cell)) + [width]
        ys = list(range(0, height, cell)) + [height]
        soft = mask.filter(ImageFilter.GaussianBlur(max(1.0, 2.6 * scale)))
        field = soft.resize((len(xs), len(ys)), Image.Resampling.BILINEAR)
        values = list(field.getdata())
        cols, rows = len(xs), len(ys)
        offsets = []
        for row in range(rows):
            for col in range(cols):
                value = values[row * cols + col] / 255.0
                gx = (values[row * cols + min(cols - 1, col + 1)]
                      - values[row * cols + max(0, col - 1)]) * 0.5
                gy = (values[min(rows - 1, row + 1) * cols + col]
                      - values[max(0, row - 1) * cols + col]) * 0.5
                length = math.hypot(gx, gy)
                if length < 1e-5:
                    offsets.append((0.0, 0.0))
                    continue
                edge_weight = _clamp((0.98 - value) / 0.52) * value
                shift = GLASS_REFRACTION_STRENGTH * scale * edge_weight
                offsets.append((-gx / length * shift, -gy / length * shift))

        def source_point(x, y, offset):
            return (min(width - 1.0, max(0.0, x + offset[0])),
                    min(height - 1.0, max(0.0, y + offset[1])))

        mesh = []
        for row in range(rows - 1):
            for col in range(cols - 1):
                x0, x1 = xs[col], xs[col + 1]
                y0, y1 = ys[row], ys[row + 1]
                p00, p10 = offsets[row*cols+col], offsets[row*cols+col+1]
                p11 = offsets[(row+1)*cols+col+1]
                p01 = offsets[(row+1)*cols+col]
                # Pillow QUAD coordinates are UL, LL, LR, UR.
                quad = (*source_point(x0, y0, p00),
                        *source_point(x0, y1, p01),
                        *source_point(x1, y1, p11),
                        *source_point(x1, y0, p10))
                mesh.append(((x0, y0, x1, y1), quad))
        return source.transform(source.size, Image.Transform.MESH, mesh,
                                resample=Image.Resampling.BILINEAR)

    def _procedural_base(self, theme, background, x, y, phase):
        height, width = background.shape[:2]
        xx = np.broadcast_to(x, (height, width))
        yy = np.broadcast_to(y, (height, width))
        bg_mix = {
            THEME_MILK: 0.10, THEME_CHROME: 0.10, THEME_BLUE_FLOW: 0.07,
            THEME_RAINBOW: 0.06, THEME_DROPLET: 0.0, THEME_RGB_NEON: 0.07,
            THEME_TEAL_BREATH: 0.06, THEME_SPECTRUM: 0.06,
            THEME_AURORA: 0.06,
        }.get(theme, 0.0)

        if theme == THEME_MILK:
            top = np.array((253, 254, 253), dtype=np.float32)
            bottom = np.array((226, 241, 249), dtype=np.float32)
            tint = top[None, None, :] * (1.0 - 0.18*yy[..., None])
            tint += bottom[None, None, :] * (0.18*yy[..., None])
        elif theme == THEME_CHROME:
            top = np.array((11, 21, 31), dtype=np.float32)
            bottom = np.array((19, 38, 52), dtype=np.float32)
            tint = top[None, None, :] * (1.0-yy[..., None])
            tint += bottom[None, None, :] * yy[..., None]
            metal = np.exp(-((yy - 0.095) / 0.055) ** 2) * (
                0.12 + 0.11*np.exp(-((xx-0.38)/0.34)**2))
            tint += np.array((190, 211, 227), dtype=np.float32) * metal[..., None]
        elif theme == THEME_BLUE_FLOW:
            top = np.array((4, 48, 107), dtype=np.float32)
            bottom = np.array((5, 78, 151), dtype=np.float32)
            tint = top[None, None, :] * (1.0-yy[..., None])
            tint += bottom[None, None, :] * yy[..., None]
        elif theme == THEME_RAINBOW:
            tint = np.empty((height, width, 3), dtype=np.float32)
            tint[:] = (249, 251, 251)
            for center, color, spread in (
                    (0.24, (159, 219, 250), 0.25),
                    (0.55, (241, 192, 247), 0.27),
                    (0.82, (202, 190, 250), 0.23)):
                weight = 0.26 * np.exp(-((xx-center)/spread)**2
                                       - ((yy-0.52)/0.80)**2)
                tint += (np.array(color, dtype=np.float32)-249) * weight[..., None]
        elif theme == THEME_DROPLET:
            # A clear water lens with a cool body tint and slow-moving glints.
            tint = (background * 0.86
                    + np.array((194, 228, 245), dtype=np.float32) * 0.14)
            glint_center = 0.68 + 0.045 * math.sin(2*math.pi*(phase % 7.0)/7.0)
            specular = np.exp(-((xx-glint_center)/0.19)**2
                              - ((yy-0.085)/0.032)**2) * 0.38
            specular += np.exp(-((xx-0.88)/0.09)**2
                               - ((yy-0.18)/0.075)**2) * 0.14
            ribbon_y = 0.115 + 0.018*np.sin(2*np.pi*(xx*0.82 + phase/18.0))
            ribbon = np.exp(-((yy-ribbon_y)/0.016)**2)
            ribbon *= np.clip((xx-0.12)/0.14, 0.0, 1.0)
            ribbon *= np.clip((0.91-xx)/0.16, 0.0, 1.0) * 0.25
            tint += (255.0-tint) * specular[..., None]
            tint += (255.0-tint) * ribbon[..., None]
            lower_lip = np.exp(-((yy-0.955)/0.048)**2) * 0.36
            tint = tint * (1.0-lower_lip[..., None])
            tint += np.array((42, 91, 124), dtype=np.float32) * lower_lip[..., None]
        elif theme == THEME_RGB_NEON:
            top = np.array((10, 16, 31), dtype=np.float32)
            bottom = np.array((20, 27, 43), dtype=np.float32)
            tint = top[None, None, :] * (1.0-yy[..., None])
            tint += bottom[None, None, :] * yy[..., None]
        elif theme == THEME_TEAL_BREATH:
            top = np.array((5, 34, 41), dtype=np.float32)
            bottom = np.array((8, 48, 53), dtype=np.float32)
            tint = top[None, None, :] * (1.0-yy[..., None])
            tint += bottom[None, None, :] * yy[..., None]
        elif theme == THEME_SPECTRUM:
            tint = np.empty((height, width, 3), dtype=np.float32)
            tint[:] = (250, 251, 250)
            for center, color, spread, weight_max in (
                    (0.12, (255, 218, 155), 0.23, 0.36),
                    (0.44, (164, 235, 215), 0.26, 0.27),
                    (0.82, (247, 162, 220), 0.24, 0.38)):
                weight = weight_max * np.exp(-((xx-center)/spread)**2
                                              - ((yy-0.5)/0.82)**2)
                tint += (np.array(color, dtype=np.float32)-250) * weight[..., None]
        else:  # THEME_AURORA
            top = np.array((4, 18, 26), dtype=np.float32)
            bottom = np.array((7, 27, 34), dtype=np.float32)
            tint = top[None, None, :] * (1.0-yy[..., None])
            tint += bottom[None, None, :] * yy[..., None]

        if bg_mix:
            tint = tint * (1.0-bg_mix) + background * bg_mix

        if theme == THEME_BLUE_FLOW:
            flow_phase = (phase % 18.0) * 0.45
            curve = (0.45 + 0.15*np.sin(2*np.pi*(xx*0.75 + flow_phase*0.05))
                     + 0.04*xx)
            right_weight = np.clip((xx-0.50)*2.5, 0.0, 1.0)
            ribbon = np.exp(-((yy-curve)/0.030)**2) * right_weight * 0.52
            halo = np.exp(-((yy-curve)/0.095)**2) * right_weight * 0.13
            tint += np.array((28, 142, 255), dtype=np.float32) * ribbon[..., None]
            tint += np.array((5, 72, 164), dtype=np.float32) * halo[..., None]
        elif theme == THEME_DROPLET:
            caustic = np.exp(-((yy-0.895)/0.018)**2)
            caustic *= 0.08 + 0.10*np.exp(-((xx-0.66)/0.30)**2)
            tint += np.array((115, 207, 233), dtype=np.float32) * caustic[..., None]
        elif theme == THEME_AURORA:
            flow_phase = (phase % 26.0) / 26.0
            curve = (0.49 + 0.19*np.sin(2*np.pi*(yy*0.78 + flow_phase*0.22))
                     + 0.16*yy)
            envelope = np.clip((yy+0.16)/0.32, 0.0, 1.0) * np.clip(
                (1.12-yy)/0.34, 0.0, 1.0)
            core = np.exp(-((xx-curve)/0.028)**2) * envelope
            halo = np.exp(-((xx-curve)/0.085)**2) * envelope
            tint += np.array((12, 210, 132), dtype=np.float32) * (core*0.78)[..., None]
            tint += np.array((2, 103, 88), dtype=np.float32) * (halo*0.55)[..., None]

        return np.clip(tint, 0, 255).astype(np.uint8)

    @staticmethod
    def _edge_palette(theme, width, phase, x_positions=None):
        x = (np.linspace(0.0, 1.0, width, dtype=np.float32)
             if x_positions is None else
             np.clip(np.asarray(x_positions, dtype=np.float32), 0.0, 1.0))
        if theme == THEME_CHROME:
            stops = [0.0, 0.25, 0.55, 0.78, 1.0]
            colors = [(116, 161, 190), (224, 236, 244), (112, 143, 165),
                      (226, 237, 243), (101, 146, 174)]
        elif theme == THEME_BLUE_FLOW:
            stops = [0.0, 0.28, 0.55, 0.80, 1.0]
            colors = [(16, 151, 255), (118, 211, 255), (68, 154, 255),
                      (134, 218, 255), (16, 121, 236)]
        elif theme == THEME_RGB_NEON:
            stops = [0.0, 0.22, 0.43, 0.62, 0.80, 1.0]
            colors = [(24, 167, 255), (60, 203, 255), (178, 80, 255),
                      (255, 94, 175), (255, 220, 96), (78, 244, 190)]
        elif theme == THEME_TEAL_BREATH:
            stops = [0.0, 0.28, 0.55, 0.78, 1.0]
            colors = [(33, 255, 222), (65, 255, 224), (23, 197, 182),
                      (77, 255, 222), (34, 225, 196)]
        elif theme == THEME_AURORA:
            stops = [0.0, 0.30, 0.58, 0.82, 1.0]
            colors = [(48, 191, 200), (120, 234, 211), (60, 192, 152),
                      (119, 227, 189), (39, 143, 166)]
        elif theme == THEME_MILK:
            stops, colors = [0.0, 1.0], [(255, 255, 255), (239, 250, 255)]
        elif theme == THEME_RAINBOW:
            stops, colors = [0.0, 1.0], [(237, 246, 255), (255, 247, 255)]
        elif theme == THEME_SPECTRUM:
            stops, colors = [0.0, 0.45, 1.0], [(255, 238, 201),
                (218, 250, 241), (255, 222, 245)]
        elif theme == THEME_DROPLET:
            stops = [0.0, 0.24, 0.52, 0.78, 1.0]
            colors = [(183, 226, 246), (240, 252, 255), (213, 242, 252),
                      (244, 253, 255), (148, 205, 232)]
        else:
            stops, colors = [0.0, 1.0], [(248, 253, 255), (239, 248, 253)]
        palette = np.stack([
            np.interp(x, stops, [color[channel] for color in colors])
            for channel in range(3)], axis=1)
        if theme == THEME_TEAL_BREATH:
            pulse = 0.66 + 0.34 * (0.5 + 0.5*math.sin(2*math.pi*phase/3.2))
            palette *= pulse
        return np.uint8(np.clip(palette, 0, 255))

    def render(self, background, mask, theme, phase=None):
        started = time.perf_counter()
        if np is None:
            return self._pillow_fallback(background, mask, theme)

        phase = time.perf_counter() if phase is None else float(phase)
        size = mask.size
        work_size = (max(1, (size[0]+2)//3), max(1, (size[1]+2)//3))
        edge_size = (max(1, (size[0]+1)//2), max(1, (size[1]+1)//2))
        source = self._small_background(background, work_size)
        now = time.perf_counter()
        if (theme == THEME_DROPLET and
                (source is not self._refract_source or self._refract_size != work_size
                 or self._refracted is None or now-self._refract_at >= 0.06)):
            self._refracted = self._refract(
                source, mask.resize(work_size, Image.Resampling.BILINEAR),
                max(0.5, self.scale/3.0))
            self._refract_source = source
            self._refract_size = work_size
            self._refract_at = now
        if theme == THEME_DROPLET and self._refracted is not None:
            source = self._refracted
        backdrop = np.asarray(source, dtype=np.float32)
        height, width = work_size[1], work_size[0]
        mask_work = mask.resize(work_size, Image.Resampling.BILINEAR)
        shape_bounds = mask_work.getbbox() or (0, 0, width, height)
        shape_width = max(1, shape_bounds[2]-shape_bounds[0]-1)
        shape_height = max(1, shape_bounds[3]-shape_bounds[1]-1)
        x_positions = np.clip((np.arange(width, dtype=np.float32)
                               - shape_bounds[0]) / shape_width, 0.0, 1.0)
        y_positions = np.clip((np.arange(height, dtype=np.float32)
                               - shape_bounds[1]) / shape_height, 0.0, 1.0)
        x = x_positions[None, :]
        y = y_positions[:, None]
        base_key = (id(background), theme, work_size, shape_bounds)
        if (theme not in THEME_ANIMATED_OPTIONS
                and base_key == self._base_key and self._base_rgb is not None):
            rgb = self._base_rgb.copy()
        else:
            rgb = self._procedural_base(theme, backdrop, x, y, phase)
            if theme not in THEME_ANIMATED_OPTIONS:
                self._base_key = base_key
                self._base_rgb = rgb.copy()

        if theme == THEME_MILK:
            stroke_alpha, glow_alpha = 50, 0
        elif theme == THEME_CHROME:
            stroke_alpha, glow_alpha = 148, 35
        elif theme == THEME_BLUE_FLOW:
            stroke_alpha, glow_alpha = 130, 42
        elif theme == THEME_RAINBOW:
            stroke_alpha, glow_alpha = 32, 0
        elif theme == THEME_DROPLET:
            stroke_alpha, glow_alpha = 220, 34
        elif theme == THEME_RGB_NEON:
            stroke_alpha, glow_alpha = 218, 104
        elif theme == THEME_TEAL_BREATH:
            pulse = 0.66 + 0.34 * (0.5 + 0.5*math.sin(2*math.pi*phase/3.2))
            stroke_alpha, glow_alpha = int(238*pulse), int(130*pulse)
        elif theme == THEME_SPECTRUM:
            stroke_alpha, glow_alpha = 34, 0
        else:
            stroke_alpha, glow_alpha = 118, 40

        edge_w, edge_h = edge_size
        mask_small = mask.resize(edge_size, Image.Resampling.BILINEAR)
        edge_bounds = mask_small.getbbox() or (0, 0, edge_w, edge_h)
        edge_width = max(1, edge_bounds[2]-edge_bounds[0]-1)
        edge_height = max(1, edge_bounds[3]-edge_bounds[1]-1)
        edge_x = np.clip((np.arange(edge_w, dtype=np.float32)-edge_bounds[0])
                         / edge_width, 0.0, 1.0)
        edge_y = np.clip((np.arange(edge_h, dtype=np.float32)-edge_bounds[1])
                         / edge_height, 0.0, 1.0)
        edge_rgb = np.broadcast_to(
            self._edge_palette(theme, edge_w, phase, edge_x)[None, :, :],
            (edge_h, edge_w, 3)).copy()
        # Build the rim at half resolution: the high resolution silhouette is
        # still applied to the final body, while the narrow optical effects do
        # not need full-window filters or multiple full-size composites.
        base_edge = Image.fromarray(rgb).resize(
            edge_size, Image.Resampling.BILINEAR)
        eroded = mask_small.filter(ImageFilter.MinFilter(3))
        dilated = mask_small.filter(ImageFilter.MaxFilter(3))
        inside_edge = ImageChops.subtract(mask_small, eroded).point(
            lambda value: min(255, value*2))
        outside_edge = ImageChops.subtract(dilated, mask_small).point(
            lambda value: min(255, value*2))

        stroke = np.asarray(inside_edge, dtype=np.float32) / 255.0
        stroke *= stroke_alpha / 255.0
        if theme == THEME_DROPLET:
            rows = edge_y[:, None]
            upper_lip = np.clip((0.57-rows)/0.46, 0.0, 1.0)
            lower_lip = np.clip((rows-0.55)/0.45, 0.0, 1.0)
            stroke *= 0.72 + 0.40*upper_lip + 0.08*lower_lip
            upper_mix = 0.56*upper_lip
            lower_mix = 0.78*lower_lip
            edge_rgb = (edge_rgb.astype(np.float32)
                        * (1.0-upper_mix[..., None]-lower_mix[..., None])
                        + np.array((255, 255, 255), dtype=np.float32)
                        * upper_mix[..., None]
                        + np.array((61, 137, 177), dtype=np.float32)
                        * lower_mix[..., None])
            edge_rgb = np.uint8(np.clip(edge_rgb, 0, 255))
        if theme == THEME_CHROME:
            top_sigma = max(0.008, 3.0*self.scale / edge_height)
            top_profile = (150.0 / 255.0) * np.exp(-(
                edge_y / top_sigma) ** 2)
            chrome_edge = (np.asarray(inside_edge, dtype=np.float32) / 255.0
                           * top_profile[:, None])
            stroke = np.maximum(stroke, chrome_edge)
        rgb = np.asarray(base_edge, dtype=np.float32)
        rgb = (rgb * (1.0-stroke[..., None])
               + edge_rgb.astype(np.float32) * stroke[..., None])
        body = Image.fromarray(np.uint8(np.clip(rgb, 0, 255))).resize(
            size, Image.Resampling.BILINEAR).convert("RGBA")
        body.putalpha(mask)

        # Narrow highlights follow the true silhouette; the soft component is
        # only a few pixels wide and never fogs the whole capsule.
        glow_full = None
        if glow_alpha:
            glow = outside_edge.filter(ImageFilter.GaussianBlur(
                max(0.3, 0.45*self.scale)))
            glow = glow.point(lambda value: int(value*glow_alpha/255))
            glow_layer = Image.fromarray(edge_rgb).convert("RGBA")
            glow_layer.putalpha(glow)
            glow_full = glow_layer.resize(size, Image.Resampling.BILINEAR)

        result = (Image.alpha_composite(glow_full, body)
                  if glow_full is not None else body)

        self.last_material_ms = (time.perf_counter()-started)*1000.0
        return result

    def _pillow_fallback(self, background, mask, theme):
        size = mask.size
        color = (17, 30, 43) if theme in THEME_DARK_OPTIONS else (242, 248, 251)
        base = Image.new("RGBA", size, color + (255,))
        base.putalpha(mask)
        edge = ImageChops.subtract(mask, mask.filter(ImageFilter.MinFilter(5)))
        stroke = Image.new("RGBA", size, (230, 245, 255, 0))
        stroke.putalpha(edge.point(lambda value: int(value*0.35)))
        return Image.alpha_composite(base, stroke)


class IslandRenderer:
    """Render the capsule and message detail as one antialiased RGBA silhouette."""

    SS = 2

    def __init__(self, scale=1.0):
        s = self.s = scale
        self.CW = int(round(420 * s))
        self.CH = int(round(144 * s))
        self.top = int(round(24 * s))
        self.bottom = int(round(22 * s))
        self.f_title = _load_font(16 * s, bold=True)
        self.f_sub = _load_font(13 * s)
        self.f_compact = _load_font(11 * s)
        self.f_tab = _load_font(13 * s)
        self.f_body_title = _load_font(13 * s, bold=True)
        self.f_body = _load_font(12 * s)
        self.f_small = _load_font(10 * s)
        self.icon_big = load_wechat_icon(int(round(36 * s)))
        self.icon_small = load_wechat_icon(int(round(22 * s)))
        self.last_layout = {}
        self.last_canvas_size = (self.CW, self.CH)
        self.last_body_scroll_max = 0
        self._wrap_cache = {}
        self._fit_cache = {}
        self._line_cache = {}
        self._char_width_cache = {}
        self._missing_glyph_signatures = {}
        self._glyph_support_cache = {}
        self.theme_renderer = CapsuleThemeRenderer(s)

    @staticmethod
    def _mask_signature(font, char):
        mask = font.getmask(char)
        return mask.size, bytes(mask)

    def _font_supports(self, font, char):
        key = (id(font), char)
        cached = self._glyph_support_cache.get(key)
        if cached is not None:
            return cached
        try:
            font_id = id(font)
            missing = self._missing_glyph_signatures.get(font_id)
            if missing is None:
                missing = self._mask_signature(font, "\U0010ffff")
                self._missing_glyph_signatures[font_id] = missing
            supported = self._mask_signature(font, char) != missing
        except Exception:  # Some bitmap fallback fonts do not expose mask bytes.
            supported = True
        if len(self._glyph_support_cache) >= 8192:
            self._glyph_support_cache.clear()
        self._glyph_support_cache[key] = supported
        return supported

    def _clean_render_text(self, text, font):
        """Drop invisible/control and missing-font glyphs without changing stored messages."""
        cleaned = []
        for char in str(text or ""):
            if char == "\r":
                continue
            if char == "\n":
                cleaned.append(char)
                continue
            if char.isspace():
                char = " "
                if not cleaned or cleaned[-1] in (" ", "\n"):
                    continue
            category = unicodedata.category(char)
            if category in {"Cc", "Cf", "Cs", "Co", "Cn"}:
                continue
            if char not in (" ", "\n") and not self._font_supports(font, char):
                continue
            cleaned.append(char)
        return "".join(cleaned).strip()

    def _text(self, draw, xy, text, font, fill, anchor="lm"):
        text = self._clean_render_text(text, font)
        if not text:
            return
        try:
            draw.text(xy, text, font=font, fill=fill, anchor=anchor)
        except (ValueError, TypeError):
            box = font.getbbox(text)
            x = xy[0] - (box[2] - box[0]) / 2 - box[0] if anchor == "mm" else xy[0]
            y = xy[1] - (box[3] - box[1]) / 2 - box[1] if anchor == "mm" else xy[1]
            draw.text((x, y), text, font=font, fill=fill)

    def _fit_text(self, draw, text, font, max_width):
        text = " ".join(self._clean_render_text(text, font).split())
        if max_width <= 0:
            return ""
        key = (text, id(font), int(round(max_width)))
        if key in self._fit_cache:
            return self._fit_cache[key]
        measure = getattr(draw, "textlength", None)
        width = (lambda value: measure(value, font=font)) if measure else (
            lambda value: font.getbbox(value)[2] - font.getbbox(value)[0])
        if width(text) <= max_width:
            result = text
        else:
            lo, hi = 0, len(text)
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if width(text[:mid].rstrip() + "…") <= max_width:
                    lo = mid
                else:
                    hi = mid - 1
            result = text[:lo].rstrip() + "…"
        if len(self._fit_cache) > 512:
            self._fit_cache.clear()
        self._fit_cache[key] = result
        return result

    def _wrap_text(self, draw, text, font, max_width):
        text = self._clean_render_text(text, font)
        key = (text, id(font), int(round(max_width)))
        cached = self._wrap_cache.get(key)
        if cached is not None:
            return cached
        lines = []
        font_size = max(1.0, float(getattr(font, "size", 12 * self.s)))
        for paragraph in text.replace("\r", "").split("\n"):
            if not paragraph:
                lines.append("")
                continue
            line = ""
            line_width = 0.0
            for char in paragraph:
                if ord(char) >= 0x2E80:
                    # CJK and emoji glyphs are full-width in the UI font; this
                    # avoids thousands of identical font-measurement calls.
                    char_width = font_size
                else:
                    width_key = (id(font), char)
                    char_width = self._char_width_cache.get(width_key)
                    if char_width is None:
                        try:
                            char_width = draw.textlength(char, font=font)
                        except AttributeError:
                            box = font.getbbox(char)
                            char_width = box[2] - box[0]
                        if len(self._char_width_cache) > 2048:
                            self._char_width_cache.clear()
                        self._char_width_cache[width_key] = char_width
                if line and line_width + char_width > max_width:
                    lines.append(line)
                    line, line_width = char, char_width
                else:
                    line += char
                    line_width += char_width
            lines.append(line)
        result = lines or [""]
        if len(self._wrap_cache) > 256:
            self._wrap_cache.clear()
        self._wrap_cache[key] = result
        return result

    @staticmethod
    def _blend(base, layer, alpha, blur, mask):
        if alpha <= 0.01:
            return base
        bounds = layer.getchannel("A").getbbox()
        if bounds is None:
            return base
        margin = int(math.ceil(max(0.0, blur) * 3.0)) if blur > 0.3 else 0
        left = max(0, bounds[0] - margin)
        top = max(0, bounds[1] - margin)
        right = min(layer.width, bounds[2] + margin)
        bottom = min(layer.height, bounds[3] + margin)
        bounds = (left, top, right, bottom)
        layer = layer.crop(bounds)
        if blur > 0.3:
            layer = layer.filter(ImageFilter.GaussianBlur(blur))
        a = layer.getchannel("A").point(lambda v: int(v * alpha))
        layer.putalpha(ImageChops.multiply(a, mask.crop(bounds)))
        base.alpha_composite(layer, dest=(left, top))
        return base

    def _draw_wrapped_lines(self, layer, xy, lines, font, fill, width,
                            line_height, offset, max_lines):
        """Reuse rasterized text rows during spring frames; only crop/compose moves."""
        draw = ImageDraw.Draw(layer)
        x0, y0 = int(round(xy[0])), int(round(xy[1]))
        tile_w = max(1, int(math.ceil(width)))
        tile_h = max(1, int(math.ceil(line_height)))
        for row, text in enumerate(lines[offset:offset + max_lines]):
            key = (text, id(font), fill, tile_w, tile_h)
            tile = self._line_cache.get(key)
            if tile is None:
                tile = Image.new("RGBA", (tile_w, tile_h), (0, 0, 0, 0))
                ImageDraw.Draw(tile).text((0, 0), text, font=font, fill=fill, anchor="lt")
                if len(self._line_cache) > 2048:
                    self._line_cache.clear()
                self._line_cache[key] = tile
            layer.paste(tile, (x0, y0 + row * tile_h), tile)

    @staticmethod
    def _rounded_mask(size, rect, radii, ss):
        """Draw a rounded rectangle with four independent corner radii."""
        width, height = size
        x1, y1, x2, y2 = rect
        bw, bh = max(1.0, x2 - x1), max(1.0, y2 - y1)
        tl, tr, br, bl = [max(0.0, float(r)) for r in radii]
        factor = min(1.0, bw / max(tl + tr, 1e-6), bh / max(tl + bl, 1e-6),
                     bw / max(bl + br, 1e-6), bh / max(tr + br, 1e-6))
        tl, tr, br, bl = tl * factor, tr * factor, br * factor, bl * factor
        pts = []
        for cx, cy, radius, start in (
                (x1 + tl, y1 + tl, tl, 180), (x2 - tr, y1 + tr, tr, 270),
                (x2 - br, y2 - br, br, 0), (x1 + bl, y2 - bl, bl, 90)):
            if radius <= 0.25:
                pts.append((cx, cy))
                continue
            for i in range(17):
                angle = math.radians(start + i * 90 / 16)
                pts.append((cx + radius * math.cos(angle), cy + radius * math.sin(angle)))
        big = Image.new("L", (width * ss, height * ss), 0)
        scaled = [(int(round(x * ss)), int(round(y * ss))) for x, y in pts]
        ImageDraw.Draw(big).polygon(scaled, fill=255)
        if ss >= 4:
            return big.resize((width, height), Image.Resampling.LANCZOS)
        return big.reduce(ss)

    def detail_height(self, vm, max_height):
        """Return the content-driven total surface height (device pixels)."""
        s = self.s
        max_height = max(int(max_height), int(70 * s))
        title_width = int(340 * s - 48 * s)
        body_width = int(340 * s - 70 * s)
        scratch = Image.new("RGB", (1, 1))
        draw = ImageDraw.Draw(scratch)
        base = int(70 * s)
        # Tab row and breathing room sit below the 70px capsule header.
        content_y = base + int(60 * s)
        if vm.get("tab") == "history":
            rows = vm.get("rows", [])
            visible_rows = min(6, max(1, len(rows)))
            row_h = 42 * s
            list_h = 20 * s + visible_rows * row_h + max(0, visible_rows - 1) * 4 * s
            selected_body = vm.get("selected_body") or ("暂无历史消息" if not rows else "")
            lines = self._wrap_text(draw, selected_body, self.f_body, body_width)
            body_h = min(len(lines) * 19 * s + 24 * s, 160 * s)
            detail_card_h = 12 * s + 22 * s + 9 * s + body_h + 12 * s
            natural = content_y + list_h + 12 * s + detail_card_h + 12 * s + 32 * s + 14 * s
        else:
            sender = vm.get("sender", "微信消息")
            body = vm.get("body", "") or "暂无当前消息"
            title_lines = self._wrap_text(draw, sender, self.f_body_title, title_width)
            body_lines = self._wrap_text(draw, body, self.f_body, body_width)
            body_lines_h = min(len(body_lines) * 20 * s + 24 * s, max_height)
            natural = (content_y + 12 * s + max(22 * s, len(title_lines) * 18 * s)
                       + 10 * s + body_lines_h + 10 * s + 30 * s + 14 * s)
        return max(int(70 * s), min(max_height, int(math.ceil(natural))))

    def _draw_detail(self, out, mask, w, h, surface_h, progress, opacity, detail,
                     hover_action, detail_offset=0.0, pressed_action=None,
                     theme_mix=0.0, theme=THEME_DEFAULT, background=None):
        if not detail or opacity <= 0.01 or progress <= 0.02:
            self.last_layout = {}
            self.last_body_scroll_max = 0
            return out
        s = self.s
        x0 = (self.CW - w) / 2.0
        y0 = float(self.top)
        alpha = max(0.0, min(1.0, opacity))
        vm = detail
        theme_mix = _clamp(float(theme_mix))
        if theme == THEME_DEFAULT:
            theme_mix = 0.0
        layer = Image.new("RGBA", out.size, (0, 0, 0, 0))
        d = ImageDraw.Draw(layer)
        content_top = y0 + h + 17 * s
        pad = 24 * s
        left, right = x0 + pad, x0 + w - pad
        layout = {}
        light_surface = theme in THEME_LIGHT_OPTIONS or theme == THEME_DROPLET
        if theme == THEME_DROPLET:
            # Keep typography stable while the sampled glass backdrop changes.
            primary_text = (79, 92, 101, 255)
            secondary_text = (102, 114, 122, 255)
            body_text = (86, 98, 106, 255)
            button_text = (70, 99, 83, 255)
        else:
            primary_text = ((31, 48, 61, 255) if light_surface
                            else (239, 243, 247, 255))
            secondary_text = ((83, 101, 115, 255) if light_surface
                              else (146, 157, 170, 255))
            body_text = ((46, 62, 75, 255) if light_surface
                         else (225, 231, 237, 255))
            button_text = ((39, 75, 65, 255) if light_surface
                           else (224, 239, 230, 255))
        slide = float(detail_offset)
        tab_y = content_top + slide
        tab_h = 32 * s
        cur_rect = (left, tab_y, left + 102 * s, tab_y + tab_h)
        hist_rect = (left + 102 * s, tab_y, left + 204 * s, tab_y + tab_h)
        close_rect = (right - 34 * s, tab_y - 1 * s, right, tab_y + tab_h + 1 * s)

        def button_state(action, normal, hover, pressed):
            if pressed_action == action:
                return pressed
            if hover_action == action:
                return hover
            return normal

        def draw_time(value):
            value = str(value or "")
            if len(value) >= 16 and value[10] in (" ", "T"):
                return value[11:16]
            return value[-5:] if len(value) >= 5 else value

        def draw_card(rect, fill, radius=14, outline=(34, 42, 51, 255)):
            d.rounded_rectangle(rect, radius=radius * s, fill=glass_fill(fill),
                                outline=glass_outline(outline),
                                width=max(1, int(round(0.8 * s))))

        def glass_fill(color):
            if theme_mix <= 0.001:
                return color
            r, g, b, a = color
            if light_surface:
                if g > r * 1.15:
                    tint = (150, 219, 190)
                else:
                    tint = (221, 233, 241)
                q = theme_mix
                return (int(r*(1-q)+tint[0]*q), int(g*(1-q)+tint[1]*q),
                        int(b*(1-q)+tint[2]*q),
                        int(a*(1-q)+118*q))
            tint = ((35, 91, 72) if g > r * 1.35 and g > b * 1.10
                    else (42, 57, 69))
            q = theme_mix
            opacity = (146 if g > r * 1.15 else 104) * q + a * (1-q)
            return (int(r*(1-q)+tint[0]*q), int(g*(1-q)+tint[1]*q),
                    int(b*(1-q)+tint[2]*q), max(1, int(round(opacity))))

        def glass_outline(color):
            if theme_mix <= 0.001:
                return color
            r, g, b, a = color
            if light_surface:
                tint = (255, 255, 255)
                q = 0.62 * theme_mix
                return (int(r*(1-q)+tint[0]*q), int(g*(1-q)+tint[1]*q),
                        int(b*(1-q)+tint[2]*q), int(a*(1.0-0.34*theme_mix)))
            t = 0.28 * theme_mix
            return (int(r*(1-t)+170*t), int(g*(1-t)+193*t),
                    int(b*(1-t)+215*t), int(round(a*(1.0-0.40*theme_mix))))

        for key, rect, label in (("current_tab", cur_rect, "当前消息"),
                                 ("history_tab", hist_rect, "历史消息")):
            active = vm.get("tab") == ("current" if key == "current_tab" else "history")
            if active:
                fill = button_state(key, (27, 46, 39, 255), (34, 57, 48, 255),
                                    (22, 39, 33, 255))
                draw_card(rect, fill, radius=16,
                          outline=(48, 79, 66, 255) if pressed_action != key else (58, 96, 79, 255))
            elif hover_action == key or pressed_action == key:
                fill = (30, 38, 47, 255) if pressed_action != key else (24, 32, 40, 255)
                d.rounded_rectangle(rect, radius=16 * s, fill=glass_fill(fill))
            self._text(d, ((rect[0] + rect[2]) / 2, (rect[1] + rect[3]) / 2), label,
                       self.f_tab,
                       ((42, 85, 67, 255) if light_surface else (244, 247, 245, 255))
                       if active else secondary_text, "mm")

        close_fill = button_state("close", (23, 28, 35, 255), (42, 49, 59, 255),
                                  (31, 38, 47, 255))
        d.ellipse(close_rect, fill=glass_fill(close_fill))
        self._text(d, ((close_rect[0] + close_rect[2]) / 2,
                       (close_rect[1] + close_rect[3]) / 2), "×", self.f_tab,
                   (222, 227, 233, 255), "mm")
        layout.update(current_tab=cur_rect, history_tab=hist_rect, close=close_rect)
        content_y = tab_y + tab_h + 12 * s

        if vm.get("tab") == "history":
            rows = vm.get("rows", [])
            visible = min(6, len(rows))
            row_h, row_gap = 42 * s, 4 * s
            card_h = 20 * s + visible * row_h + max(0, visible - 1) * row_gap
            list_rect = (left, content_y, right, content_y + max(46 * s, card_h))
            draw_card(list_rect, (20, 26, 33, 255), radius=16,
                      outline=(33, 42, 51, 255))
            offset = int(vm.get("history_scroll", 0))
            row_rects = []
            for visible_i, i in enumerate(range(offset, min(len(rows), offset + visible))):
                row_y = list_rect[1] + 10 * s + visible_i * (row_h + row_gap)
                rect = (left + 9 * s, row_y, right - 9 * s, row_y + row_h)
                row_rects.append(rect)
                action = f"history:{i}"
                selected = i == vm.get("selected_index")
                if pressed_action == action:
                    fill, outline = (39, 68, 58, 255), (63, 104, 87, 255)
                elif selected:
                    fill, outline = (34, 60, 50, 255), (53, 88, 73, 255)
                elif hover_action == action:
                    fill, outline = (34, 43, 53, 255), (48, 59, 71, 255)
                else:
                    fill, outline = (27, 34, 43, 255), (34, 42, 52, 255)
                d.rounded_rectangle(rect, radius=10 * s, fill=glass_fill(fill),
                                    outline=glass_outline(outline),
                                    width=max(1, int(round(0.7 * s))))
                marker_x = rect[0] + 17 * s
                marker_y = (rect[1] + rect[3]) / 2
                if rows[i].get("unread"):
                    d.ellipse((marker_x - 3.2*s, marker_y - 3.2*s,
                               marker_x + 3.2*s, marker_y + 3.2*s), fill=(92, 190, 143, 255))
                else:
                    d.ellipse((marker_x - 3*s, marker_y - 3*s,
                               marker_x + 3*s, marker_y + 3*s), outline=(123, 136, 149, 255),
                              width=max(1, int(round(s))))
                time_text = draw_time(rows[i].get("time", ""))
                time_width = 43 * s if time_text else 0
                text_left = rect[0] + 29 * s
                text_right = rect[2] - 12 * s - time_width
                title = f"{rows[i].get('sender', '微信消息')}  ·  {rows[i].get('body', '')}"
                title = self._fit_text(d, title, self.f_body, text_right - text_left)
                self._text(d, (text_left, marker_y), title, self.f_body,
                           body_text, "lm")
                if time_text:
                    self._text(d, (rect[2] - 11*s, marker_y), time_text, self.f_small,
                               secondary_text, "rm")
            layout["history_list"] = list_rect
            for i, rect in enumerate(row_rects, start=offset):
                layout[f"history:{i}"] = rect

            selected = (rows[vm.get("selected_index", -1)]
                        if 0 <= vm.get("selected_index", -1) < len(rows) else None)
            detail_top = list_rect[3] + 12 * s
            button_rect = (right - 132*s, surface_h + y0 - 42*s,
                           right, surface_h + y0 - 12*s)
            detail_bottom = max(detail_top + 74*s, button_rect[1] - 12*s)
            detail_card = (left, detail_top, right, detail_bottom)
            draw_card(detail_card, (20, 26, 33, 255), radius=14,
                      outline=(33, 42, 51, 255))
            sender = vm.get("selected_sender", "微信消息")
            sender = self._fit_text(d, sender, self.f_body_title, right-left-82*s)
            self._text(d, (left + 14*s, detail_top + 21*s), sender,
                       self.f_body_title, primary_text, "lm")
            selected_time = draw_time(vm.get("selected_time", ""))
            if selected_time:
                self._text(d, (right - 14*s, detail_top + 21*s), selected_time,
                           self.f_small, secondary_text, "rm")
            body_rect = (left + 10*s, detail_top + 39*s,
                         right - 10*s, detail_bottom - 10*s)
            draw_card(body_rect, (32, 41, 52, 255), radius=11,
                      outline=(45, 56, 68, 255))
            selected_body = vm.get("selected_body", "") or ("暂无历史消息" if not rows else "")
            lines = self._wrap_text(d, selected_body, self.f_body, right-left-46*s)
            max_lines = max(1, int((body_rect[3]-body_rect[1]-20*s)/(19*s)))
            offset_lines = int(vm.get("body_scroll", 0))
            self.last_body_scroll_max = max(0, len(lines)-max_lines)
            self._draw_wrapped_lines(
                layer, (body_rect[0]+13*s, body_rect[1]+11*s), lines,
                self.f_body, body_text, right-left-46*s,
                19*s, offset_lines, max_lines)
            layout["message_body"] = body_rect

            button_fill = button_state("mark_all_read", (35, 78, 59, 255),
                                       (46, 97, 72, 255), (26, 59, 45, 255))
            draw_card(button_rect, button_fill, radius=16,
                      outline=(58, 100, 82, 255) if pressed_action == "mark_all_read"
                      else (45, 83, 68, 255))
            cx = (button_rect[0]+button_rect[2])/2
            cy = (button_rect[1]+button_rect[3])/2
            d.line(((cx-49*s, cy), (cx-44*s, cy+4*s), (cx-35*s, cy-5*s)),
                   fill=(215, 239, 224, 255), width=max(1, int(round(2*s))),
                   joint="curve")
            self._text(d, (cx+8*s, cy), "全部标为已读", self.f_tab,
                       button_text, "mm")
            layout["mark_all_read"] = button_rect
        else:
            sender = vm.get("sender", "微信消息")
            body = vm.get("body", "") or "暂无当前消息"
            card_rect = (left, content_y, right,
                         max(content_y+128*s, y0+surface_h-10*s))
            draw_card(card_rect, (20, 26, 33, 255), radius=15,
                      outline=(34, 43, 53, 255))
            title = self._fit_text(d, sender, self.f_body_title, right-left-100*s)
            self._text(d, (card_rect[0]+14*s, card_rect[1]+21*s), title,
                       self.f_body_title, primary_text, "lm")
            time_text = draw_time(vm.get("time", ""))
            if time_text:
                self._text(d, (card_rect[2]-14*s, card_rect[1]+21*s), time_text,
                           self.f_small, secondary_text, "rm")
            button_rect = (card_rect[2]-96*s, card_rect[3]-42*s,
                           card_rect[2]-12*s, card_rect[3]-12*s)
            body_rect = (card_rect[0]+10*s, card_rect[1]+39*s,
                         card_rect[2]-10*s, button_rect[1]-10*s)
            if body_rect[3] <= body_rect[1]+32*s:
                body_rect = (card_rect[0]+10*s, card_rect[1]+39*s,
                             card_rect[2]-10*s, body_rect[1]+44*s)
            draw_card(body_rect, (32, 41, 52, 255), radius=11,
                      outline=(45, 56, 68, 255))
            lines = self._wrap_text(d, body, self.f_body, right-left-46*s)
            max_lines = max(1, int((body_rect[3]-body_rect[1]-20*s)/(20*s)))
            offset_lines = int(vm.get("body_scroll", 0))
            self.last_body_scroll_max = max(0, len(lines)-max_lines)
            self._draw_wrapped_lines(
                layer, (body_rect[0]+13*s, body_rect[1]+11*s), lines,
                self.f_body, body_text, right-left-46*s,
                20*s, offset_lines, max_lines)
            layout["message_body"] = body_rect

            if vm.get("unread"):
                button_fill = button_state("mark_read", (35, 78, 59, 255),
                                           (46, 97, 72, 255), (26, 59, 45, 255))
                draw_card(button_rect, button_fill, radius=15,
                          outline=(58, 100, 82, 255) if pressed_action == "mark_read"
                          else (45, 83, 68, 255))
                self._text(d, ((button_rect[0]+button_rect[2])/2,
                               (button_rect[1]+button_rect[3])/2), "标记已读",
                           self.f_small, button_text, "mm")
                layout["mark_read"] = button_rect
            else:
                draw_card(button_rect, (25, 31, 38, 255), radius=15,
                          outline=(37, 44, 53, 255))
                self._text(d, ((button_rect[0]+button_rect[2])/2,
                               (button_rect[1]+button_rect[3])/2), "已读",
                           self.f_small, secondary_text, "mm")
        layout["header"] = (x0, y0, x0+w, y0+h)
        for name in ("header", "current_tab", "history_tab", "close",
                     "message_body", "history_list", "mark_read", "mark_all_read"):
            if name in layout:
                layout[name + "_rect"] = layout[name]
        self.last_layout = layout
        layer.putalpha(layer.getchannel("A").point(lambda v: int(v * alpha)))
        return self._blend(out, layer, 1.0, 0, mask)

    def _adaptive_glass_text_color(self, background, xy, fallback, theme_mix,
                                   theme=THEME_DEFAULT):
        if theme_mix <= 0.01 or theme == THEME_DEFAULT:
            return fallback
        if theme == THEME_DROPLET:
            target = (79, 92, 101, 255)
            q = _clamp(theme_mix)
            return tuple(int(round(fallback[i]*(1-q) + target[i]*q))
                         for i in range(4))
        if theme in THEME_LIGHT_OPTIONS:
            target = (30, 48, 62, 255)
            q = _clamp(theme_mix)
            return tuple(int(round(fallback[i]*(1-q) + target[i]*q))
                         for i in range(4))
        if theme in THEME_DARK_OPTIONS:
            target = (244, 249, 252, 255)
            q = _clamp(theme_mix)
            return tuple(int(round(fallback[i]*(1-q) + target[i]*q))
                         for i in range(4))
        if background is None:
            return fallback
        rgb = background.convert("RGB") if background.mode != "RGB" else background
        x = min(max(0, int(round(xy[0]))), rgb.width - 1)
        y = min(max(0, int(round(xy[1]))), rgb.height - 1)
        r, g, b = rgb.getpixel((x, y))
        luma = (0.2126*r + 0.7152*g + 0.0722*b) / 255.0
        target = (22, 31, 42, 255) if luma > 0.57 else (250, 252, 255, 255)
        q = _clamp(theme_mix)
        return tuple(int(round(fallback[i]*(1-q) + target[i]*q)) for i in range(4))

    def render(self, w, h, ea=0.0, ca=0.0, pending=False, hover_dot=True,
               source_label="", message_summary="", message_sender="", *,
               detail=None, shape_progress=0.0, detail_opacity=0.0,
               surface_height=None, hover_action=None, detail_offset=0.0,
               pressed_action=None, background=None, theme_mix=0.0,
               theme=THEME_DEFAULT):
        s, CW = self.s, self.CW
        w = max(float(w), 8 * s)
        h = max(float(h), 8 * s)
        p = max(0.0, min(1.0, float(shape_progress)))
        theme_mix = _clamp(float(theme_mix))
        material_mix = theme_mix if theme != THEME_DEFAULT else 0.0
        small_shape = _clamp((52 * s - max(w, h)) / (16 * s))
        # The idle camera hole is only about 25px across. Render that tiny
        # silhouette at 4x so its circular edge survives the final downsample.
        ss = 4 if small_shape > 0.5 else self.SS
        surface_h = max(h, float(surface_height if surface_height is not None else h))
        # Keep the native layered window close to visible pixels so transparent
        # canvas margins do not intercept clicks below the island.
        canvas_h = max(1, int(math.ceil(self.top + surface_h + self.bottom)))
        self.last_canvas_size = (CW, canvas_h)
        x0 = (CW - w) / 2.0
        y0 = float(self.top)
        top_r = h / 2.0 + (38 * s - h / 2.0) * p
        bot_r = h / 2.0 + (24 * s - h / 2.0) * p
        mask = self._rounded_mask((CW, canvas_h),
                                  (x0, y0, x0 + w, y0 + surface_h),
                                  (top_r, top_r, bot_r, bot_r), ss)

        # Build one soft shadow from the complete silhouette, including the detail morph.
        idle_scale = min(1.0, min(w, h) / (36 * s))
        shadow_scale = 1.0 - (1.0 - idle_scale) * small_shape
        shadow_offset = (6.0 - 2.5 * small_shape) * s * shadow_scale
        default_shadow_blur = (9.0 - 3.0 * small_shape) * s * shadow_scale
        shadow_blur = default_shadow_blur * (1.0-material_mix) + 2.0*s*material_mix
        shadow_offset = shadow_offset * (1.0-material_mix) + 2.0*s*material_mix
        default_shadow_alpha = 0.42 + 0.08 * small_shape
        shadow_alpha = (default_shadow_alpha * (1.0 - material_mix)
                        + GLASS_SHADOW_STRENGTH * material_mix)
        shadow = Image.new("L", (CW, canvas_h), 0)
        shadow.paste(mask, (0, int(round(shadow_offset))))
        shadow = shadow.filter(ImageFilter.GaussianBlur(shadow_blur)).point(
            lambda v: int(v * shadow_alpha))
        out = Image.new("RGBA", (CW, canvas_h), (0, 0, 0, 0))
        # Both silhouette and shadow are black. Their visible union is simply
        # the stronger alpha at each pixel, avoiding a full-frame composite.
        out.putalpha(ImageChops.lighter(shadow, mask))
        if theme_mix > 0.001 and theme != THEME_DEFAULT:
            material = self.theme_renderer.render(
                background, mask, theme, time.perf_counter())
            shadow_only = ImageChops.subtract(shadow, mask)
            glass_out = Image.new("RGBA", (CW, canvas_h), (0, 0, 0, 0))
            glass_out.putalpha(shadow_only)
            glass_out = Image.alpha_composite(glass_out, material)
            out = (glass_out if theme_mix >= 0.999
                   else Image.blend(out, glass_out, theme_mix))

        # Header stays anchored to the capsule header height as the surface grows below it.
        cy = y0 + h / 2.0
        camera_alpha = small_shape * (1.0 - max(ea, ca))
        if camera_alpha > 0.01:
            detail_lens = Image.new("RGBA", (CW * ss, canvas_h * ss), (0, 0, 0, 0))
            d = ImageDraw.Draw(detail_lens)
            cx = x0 + w / 2.0
            camera_scale = idle_scale
            for radius, fill in ((16.0 * s, (20, 25, 30, 255)),
                                 (14.4 * s, (3, 5, 8, 255))):
                r = radius * camera_scale * ss
                d.ellipse((cx * ss-r, cy * ss-r, cx * ss+r, cy * ss+r), fill=fill)
            detail_lens = detail_lens.resize((CW, canvas_h), Image.LANCZOS)
            detail_lens.putalpha(detail_lens.getchannel("A").point(
                lambda v: int(v * camera_alpha)))
            out = Image.alpha_composite(out, detail_lens)

        if ca > 0.01:
            layer = Image.new("RGBA", (CW, canvas_h), (0, 0, 0, 0))
            ic = self.icon_small
            layer.paste(ic, (int(x0 + 12 * s), int(cy - ic.height / 2.0)), ic)
            d = ImageDraw.Draw(layer)
            dot_r = 4.5 * s
            dx = x0 + w - 19 * s
            label_left = x0 + 12 * s + ic.width + 8 * s
            label_right = dx - dot_r - 8 * s
            label = (f"{message_sender or '微信消息'}：{message_summary}"
                     if message_summary else source_label or "有新消息待查看")
            self._text(d, ((label_left + label_right) / 2.0, cy),
                       self._fit_text(d, label, self.f_compact, label_right-label_left),
                       self.f_compact,
                       self._adaptive_glass_text_color(
                           background, ((label_left + label_right) / 2.0, cy),
                           (190, 190, 198, 255), theme_mix, theme), "mm")
            if pending or message_summary:
                d.ellipse((dx-dot_r, cy-dot_r, dx+dot_r, cy+dot_r), fill=(46,204,113,255))
            out = self._blend(out, layer, ca, 0, mask)

        if ea > 0.01:
            layer = Image.new("RGBA", (CW, canvas_h), (0, 0, 0, 0))
            ic = self.icon_big
            lx = x0 + 14 * s
            layer.paste(ic, (int(lx), int(cy - ic.height / 2.0)), ic)
            d = ImageDraw.Draw(layer)
            tx = lx + ic.width + 12 * s
            title = (message_sender or "微信消息") if message_summary else "微信"
            subtitle = (message_summary if message_summary else
                        f"{source_label} · 点击打开" if source_label else "有新提醒 · 点击打开")
            max_text_width = max(20 * s, x0 + w - 30 * s - tx)
            self._text(d, (tx, cy - 10 * s), self._fit_text(d, title, self.f_title, max_text_width),
                       self.f_title, self._adaptive_glass_text_color(
                           background, (tx, cy - 10*s), (255,255,255,255),
                           theme_mix, theme))
            self._text(d, (tx, cy + 11 * s), self._fit_text(d, subtitle, self.f_sub, max_text_width),
                       self.f_sub, self._adaptive_glass_text_color(
                           background, (tx, cy + 11*s), (152,152,160,255),
                           theme_mix, theme))
            r = 4.5 * s
            dx = x0 + w - 24 * s
            if pending or message_summary:
                d.ellipse((dx-r,cy-r,dx+r,cy+r), fill=(46,204,113,255))
            out = self._blend(out, layer, ea, 0, mask)
        if detail and shape_progress > 0.01:
            out = self._draw_detail(out, mask, w, h, surface_h, p, detail_opacity,
                                    detail, hover_action, detail_offset, pressed_action,
                                    theme_mix, theme, background)
        else:
            self.last_layout = {}
        return out

    @staticmethod
    def to_bgra(img):
        """RGBA -> premultiplied BGRA bytes for UpdateLayeredWindow."""
        return img.convert("RGBa").tobytes("raw", "BGRa")


class LayeredSurface:
    """UpdateLayeredWindow surface with a reusable, grow-only DIB capacity."""

    def __init__(self, hwnd, width, height):
        u = _u
        g = ctypes.WinDLL("gdi32", use_last_error=True)
        self.u, self.g = u, g
        self.hwnd, self.w = hwnd, int(width)
        self.capacity_h = 0

        class BLENDFUNCTION(ctypes.Structure):
            _fields_ = [("BlendOp", ctypes.c_ubyte), ("BlendFlags", ctypes.c_ubyte),
                        ("SourceConstantAlpha", ctypes.c_ubyte), ("AlphaFormat", ctypes.c_ubyte)]

        class BITMAPINFOHEADER(ctypes.Structure):
            _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG),
                        ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD),
                        ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                        ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                        ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
                        ("biClrImportant", wintypes.DWORD)]

        class BITMAPINFO(ctypes.Structure):
            _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wintypes.DWORD * 1)]

        self._bitmap_info = BITMAPINFO
        self._bitmap_header = BITMAPINFOHEADER
        u.UpdateLayeredWindow.argtypes = [
            wintypes.HWND, wintypes.HDC, ctypes.POINTER(wintypes.POINT),
            ctypes.POINTER(wintypes.SIZE), wintypes.HDC, ctypes.POINTER(wintypes.POINT),
            wintypes.COLORREF, ctypes.POINTER(BLENDFUNCTION), wintypes.DWORD]
        u.UpdateLayeredWindow.restype = wintypes.BOOL
        g.CreateCompatibleDC.argtypes = [wintypes.HDC]
        g.CreateCompatibleDC.restype = wintypes.HDC
        g.CreateDIBSection.argtypes = [
            wintypes.HDC, ctypes.POINTER(BITMAPINFO), wintypes.UINT,
            ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE, wintypes.DWORD]
        g.CreateDIBSection.restype = wintypes.HBITMAP
        g.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
        g.SelectObject.restype = wintypes.HGDIOBJ
        g.DeleteObject.argtypes = [wintypes.HGDIOBJ]
        g.DeleteDC.argtypes = [wintypes.HDC]
        self.hdc = g.CreateCompatibleDC(None)
        if not self.hdc:
            raise ctypes.WinError(ctypes.get_last_error())
        self.bitmap = None
        self.bits = None
        self.old = None
        self._blend = BLENDFUNCTION(0, 0, 255, 1)
        self._first = True
        self._ensure_capacity(height)

    def _ensure_capacity(self, height):
        if height <= self.capacity_h:
            return
        new_h = max(128, int(math.ceil(height / 128.0) * 128))
        bmi = self._bitmap_info()
        bmi.bmiHeader.biSize = ctypes.sizeof(self._bitmap_header)
        bmi.bmiHeader.biWidth = self.w
        bmi.bmiHeader.biHeight = -new_h
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32
        bmi.bmiHeader.biCompression = 0
        bits = ctypes.c_void_p()
        bitmap = self.g.CreateDIBSection(self.hdc, ctypes.byref(bmi), 0,
                                         ctypes.byref(bits), None, 0)
        if not bitmap or not bits.value:
            raise ctypes.WinError(ctypes.get_last_error())
        old_bitmap, old_selection = self.bitmap, self.old
        selected_old = self.g.SelectObject(self.hdc, bitmap)
        if not selected_old:
            self.g.DeleteObject(bitmap)
            raise ctypes.WinError(ctypes.get_last_error())
        self.bitmap = bitmap
        self.bits = bits.value
        self.old = old_selection or selected_old
        self.capacity_h = new_h
        if old_bitmap:
            self.g.DeleteObject(old_bitmap)

    def update(self, data, x, y, width=None, height=None):
        width = int(width or self.w)
        height = int(height or (len(data) // (4 * width)))
        if width != self.w:
            raise ValueError("LayeredSurface width is fixed")
        self._ensure_capacity(height)
        ctypes.memmove(self.bits, data, width * height * 4)
        pt_dst = wintypes.POINT(int(x), int(y))
        size = wintypes.SIZE(width, height)
        pt_src = wintypes.POINT(0, 0)
        ok = self.u.UpdateLayeredWindow(
            self.hwnd, None, ctypes.byref(pt_dst), ctypes.byref(size), self.hdc,
            ctypes.byref(pt_src), 0, ctypes.byref(self._blend), 2)
        if not ok and self._first:
            raise ctypes.WinError(ctypes.get_last_error())
        self._first = False

    def close(self):
        try:
            if self.bitmap:
                self.g.SelectObject(self.hdc, self.old)
                self.g.DeleteObject(self.bitmap)
                self.bitmap = None
            if self.hdc:
                self.g.DeleteDC(self.hdc)
                self.hdc = None
        except Exception:  # noqa: BLE001
            pass


class LayeredCapsule:
    """仿 iOS 灵动岛：纯黑胶囊 + 阴影 + 弹簧形变 + 内容模糊淡入；可拖动，右键恢复到顶部。"""

    # 逻辑尺寸（会乘以 DPI 缩放）
    W_IDLE, H_IDLE = 28, 28
    W_COMPACT, H_COMPACT = 180, 34
    W_EXP, H_EXP = 340, 70
    PREVIEW_MS = 5000
    DRAG_THRESHOLD = 4  # 鼠标移动超过这个像素数才算拖动，否则算点击
    FRAME_INTERVAL = 1.0 / 60.0

    def __init__(self, events, scale=None, hide_idle=False, message_store=None,
                 receive_token=None, receive_port=DEFAULT_RECEIVE_PORT):
        import tkinter as tk
        self.tk = tk
        self.events = events
        self.hide_idle = hide_idle
        self.receive_token = receive_token or get_receive_token()
        self.receive_port = receive_port
        self.update_check_in_progress = False

        if scale is None:
            try:
                _u.GetDpiForSystem.restype = wintypes.UINT
                scale = _u.GetDpiForSystem() / 96.0
            except Exception:  # noqa: BLE001
                scale = 1.0
        self.s = scale
        S = scale

        self.root = tk.Tk()
        self.root.title("WeChat Capsule")
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        self.root.configure(bg="black")
        self.external_message = None
        self.external_sender = ""
        self.external_summary = ""
        self.message_center = MessageCenter(
            self.root, message_store or MessageStore(), self._on_external_message,
            self._panel_anchor, scale=S, on_detail_change=self._on_detail_change)
        self.renderer = IslandRenderer(S)
        self.theme = load_theme()
        self.theme_var = tk.StringVar(self.root, value=self.theme)
        self.theme_mix = Spring(1.0 if self.theme != THEME_DEFAULT else 0.0)
        self.background_sampler = None
        self.background_capture_error = ""
        self.background_capture_retry_at = 0.0
        self.glass_refresh_job = None
        if self.theme != THEME_DEFAULT:
            try:
                self.background_sampler = ScreenBackgroundSampler(self.renderer.CW)
            except Exception as exc:  # noqa: BLE001
                self.background_capture_error = str(exc)
        CW, CH = self.renderer.CW, self.renderer.CH
        self.sw = self.root.winfo_screenwidth()

        # 位置：xspr = 胶囊中心 x，yspr = 胶囊顶部 y（均为屏幕像素）；优先使用上次保存的位置
        saved = load_position()
        cx, ty = self._clamp_pos(*saved) if saved else self._default_pos()
        self.xspr = Spring(cx)
        self.yspr = Spring(ty)
        self.press = None
        self.dragging = False
        self.last_detail_click = None

        self.root.geometry(f"{CW}x{CH}+{int(cx - CW / 2)}+{int(ty - self.renderer.top)}")
        self.root.update()

        # 设为分层窗口
        _u.GetParent.argtypes = [wintypes.HWND]
        _u.GetParent.restype = wintypes.HWND
        get = getattr(_u, "GetWindowLongPtrW", None) or _u.GetWindowLongW
        setl = getattr(_u, "SetWindowLongPtrW", None) or _u.SetWindowLongW
        get.argtypes = [wintypes.HWND, ctypes.c_int]
        get.restype = ctypes.c_ssize_t
        setl.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t]
        setl.restype = ctypes.c_ssize_t
        _u.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        wid = self.root.winfo_id()
        self.hwnd = _u.GetParent(wid) or wid
        ex = get(self.hwnd, -20)  # GWL_EXSTYLE
        setl(self.hwnd, -20, ex | 0x00080000 | 0x00000080)  # WS_EX_LAYERED | WS_EX_TOOLWINDOW
        try:
            self.surface = LayeredSurface(self.hwnd, CW, CH)
        except Exception:
            self.root.destroy()
            raise

        # 动画状态
        self.state = "idle"        # idle / compact / expanded (PREVIEW)
        self.pending = False
        self.pending_windows = {}   # 主窗口 HWND -> PID；负数表示未解析主窗；0 表示手动提醒
        self.source_label = ""
        self.last_opened_hwnd = None
        self.hover = False
        self.wspr = Spring(S * self.W_IDLE)
        self.hspr = Spring(S * self.H_IDLE)
        self.dspr = Spring(0.0, stiffness=125.0, damping=27.0)  # detail height beyond header
        self.pspr = Spring(0.0, stiffness=130.0, damping=27.0)  # silhouette morph progress
        self.ospr = Spring(0.0, stiffness=150.0, damping=30.0)  # detail content opacity
        self.offset_spr = Spring(0.0, stiffness=160.0, damping=30.0)
        self.detail_was_open = False
        self.hover_action = None
        self.pressed_action = None
        self.outside_click_job = None
        self.outside_click_button_down = False
        self.canvas_width, self.canvas_height = CW, CH
        self.canvas_origin = (int(cx - CW / 2), int(ty - self.renderer.top))
        self.ea = 0.0
        self.ca = 0.0
        self.job = None
        self.last = time.perf_counter()
        self.collapse_job = None
        self.visible = True

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="恢复到顶部", command=self._reset_position)
        self.menu.add_command(label="模拟一次提醒", command=self._on_flash)
        self.menu.add_command(label="消息记录", command=self.message_center.show_history)
        self.menu.add_command(label="复制接口", command=self._copy_receive_endpoint)
        self.menu.add_command(label="查看文档", command=open_documentation)
        self.menu.add_command(label="GitHub", command=open_github)
        self.menu.add_command(label="检查更新",
                              command=self._check_for_updates)
        self.menu.add_separator()
        theme_menu = tk.Menu(self.menu, tearoff=0)
        theme_menu.add_radiobutton(
            label="默认黑色", variable=self.theme_var, value=THEME_DEFAULT,
            command=lambda: self.set_theme(THEME_DEFAULT))
        theme_menu.add_separator()
        for theme_id, label in THEME_MENU_LABELS:
            theme_menu.add_radiobutton(
                label=label, variable=self.theme_var, value=theme_id,
                command=lambda selected=theme_id: self.set_theme(selected))
        self.menu.add_cascade(label="样式", menu=theme_menu)
        self.menu.add_separator()
        self.menu.add_command(label="退出", command=self.quit)
        self.root.bind("<ButtonPress-1>", self._on_press)
        self.root.bind("<B1-Motion>", self._on_motion)
        self.root.bind("<ButtonRelease-1>", self._on_release)
        self.root.bind("<Button-3>", self._on_right_click)
        self.root.bind("<Enter>", self._on_enter)
        self.root.bind("<Leave>", self._on_leave)
        self.root.bind("<Motion>", self._on_pointer_motion)
        self.root.bind("<MouseWheel>", self._on_wheel)
        self.root.bind("<Button-4>", self._on_wheel)
        self.root.bind("<Button-5>", self._on_wheel)

        try:
            # 预热：第一次画文字/模糊较慢，提前画一帧，避免首次弹出时卡顿
            self.renderer.render(S * self.W_EXP, S * self.H_EXP, 1.0, 1.0, True)
            self._push()
        except Exception:
            self.surface.close()
            self.root.destroy()
            raise
        if self.hide_idle:
            self._set_visible(False)
        self.root.after(80, self._poll)
        self.root.after(2000, self._keep_on_top)
        self.root.after(0, self.message_center.restore_unread)
        if self.theme != THEME_DEFAULT:
            self._start_glass_refresh()

    # -- 位置
    def _default_pos(self):
        # 保持胶囊本体原有的顶部留白；renderer.top 现在表示画布内边距。
        return self.sw / 2.0, 10.0 * self.s

    def _panel_anchor(self):
        return self.xspr.x, self.yspr.x, self.s, self.hspr.x, self.wspr.x

    def _clamp_pos(self, cx, ty):
        """限制在虚拟桌面内，保证胶囊不会被拖到看不见的地方。"""
        vx, vy, vw, vh = virtual_screen()
        S = getattr(self, "s", 1.0)
        cx = min(max(cx, vx + 40 * S), vx + vw - 40 * S)
        ty = min(max(ty, vy), vy + vh - 40 * S)
        return cx, ty

    def _reset_position(self):
        save_position(None)
        cx, ty = self._default_pos()
        self.xspr.set_target(cx, 260.0, 30.0)
        self.yspr.set_target(ty, 260.0, 30.0)
        self._set_visible(True)
        self._kick()

    # -- 渲染
    def _push(self):
        panel = self.message_center.panel
        detail = panel.view_model() if panel else None
        header_h = max(8 * self.s, self.hspr.x)
        extra_h = max(0.0, self.dspr.x)
        surface_h = min(header_h + extra_h,
                        max(header_h, self._max_surface_height()))
        progress = max(0.0, min(1.0, self.pspr.x))
        x = int(round(self.xspr.x - self.renderer.CW / 2.0))
        y = int(round(self.yspr.x - self.renderer.top))
        canvas_h = max(1, int(math.ceil(
            self.renderer.top + surface_h + self.renderer.bottom)))
        theme_mix = _clamp(self.theme_mix.x)
        background = None
        if theme_mix > 0.001:
            if (self.background_sampler is None
                    and time.perf_counter() >= self.background_capture_retry_at):
                try:
                    self.background_sampler = ScreenBackgroundSampler(self.renderer.CW)
                    self.background_capture_error = ""
                except Exception as exc:  # noqa: BLE001
                    self.background_capture_error = str(exc)
                    self.background_capture_retry_at = time.perf_counter() + 2.0
            if self.background_sampler is not None:
                try:
                    background = self.background_sampler.get(x, y, canvas_h)
                    self.background_sampler.request(x, y, canvas_h)
                    if self.background_sampler.last_error:
                        self.background_capture_error = self.background_sampler.last_error
                        self.background_sampler.close()
                        self.background_sampler = None
                        self.background_capture_retry_at = time.perf_counter() + 2.0
                except Exception as exc:  # noqa: BLE001
                    self.background_capture_error = str(exc)
                    self.background_sampler.close()
                    self.background_sampler = None
                    self.background_capture_retry_at = time.perf_counter() + 2.0
        # A single dynamically sized RGBA frame contains the header, detail, mask and shadow.
        img = self.renderer.render(
            self.wspr.x, header_h, self.ea, self.ca,
            self.pending or bool(self.external_message),
            source_label=self.source_label,
            message_summary=self.external_summary,
            message_sender=self.external_sender,
            detail=detail, shape_progress=progress,
            detail_opacity=max(0.0, min(1.0, self.ospr.x)),
            surface_height=surface_h, hover_action=self.hover_action,
            detail_offset=self.offset_spr.x,
            pressed_action=self.pressed_action,
            background=background, theme_mix=theme_mix, theme=self.theme,
        )
        self.canvas_origin = (x, y)
        self.canvas_width, self.canvas_height = img.size
        if panel:
            panel.body_scroll_max = self.renderer.last_body_scroll_max
            panel.body_scroll = min(panel.body_scroll, panel.body_scroll_max)
        self.surface.update(self.renderer.to_bgra(img), x, y,
                            width=img.width, height=img.height)

    def set_theme(self, theme):
        theme = normalize_theme(theme)
        self.theme = theme
        self.theme_var.set(theme)
        save_config_fields({"theme": theme})
        if theme != THEME_DEFAULT:
            if self.background_sampler is None:
                try:
                    self.background_sampler = ScreenBackgroundSampler(self.renderer.CW)
                    self.background_capture_error = ""
                except Exception as exc:  # noqa: BLE001
                    self.background_capture_error = str(exc)
                    self.background_capture_retry_at = time.perf_counter() + 2.0
            self._start_glass_refresh()
            target = 1.0
        else:
            if self.glass_refresh_job is not None:
                try:
                    self.root.after_cancel(self.glass_refresh_job)
                except Exception:  # noqa: BLE001
                    pass
                self.glass_refresh_job = None
            if self.background_sampler is not None:
                self.background_sampler.close()
                self.background_sampler = None
            target = 0.0
        k, c = Spring.coefficients(22.0, 0.92)
        self.theme_mix.set_target(target, k, c)
        self._kick()

    def _start_glass_refresh(self):
        if self.glass_refresh_job is None:
            self.glass_refresh_job = self.root.after(80, self._refresh_glass_background)

    def _refresh_glass_background(self):
        self.glass_refresh_job = None
        if self.theme == THEME_DEFAULT:
            return
        if self.visible:
            self._push()
            delay = 50 if self.theme in THEME_ANIMATED_OPTIONS else 80
        else:
            delay = 400
        self.glass_refresh_job = self.root.after(delay, self._refresh_glass_background)

    def _on_detail_change(self):
        panel = self.message_center.panel
        if not panel:
            return
        self._set_outside_click_watch(panel.is_open)
        if panel.is_open:
            self._cancel_collapse()
            if not self.detail_was_open:
                # Start from the current preview geometry; preserve existing spring velocity.
                if self.dspr.x < 1 and self.pspr.x < 0.02:
                    self.offset_spr.x = max(self.offset_spr.x, 8 * self.s)
                self._go("expanded")
                self.detail_was_open = True
            vm = panel.view_model()
            max_surface = self._max_surface_height()
            target_h = self.renderer.detail_height(vm, max_surface)
            open_k, open_c = Spring.coefficients(24.0, 0.68)
            self.dspr.set_target(max(0.0, target_h - self.H_EXP * self.s), open_k, open_c)
            self.pspr.set_target(1.0, open_k, open_c)
            self.ospr.set_target(1.0, *Spring.coefficients(30.0, 0.84))
            self.offset_spr.set_target(0.0, *Spring.coefficients(26.0, 0.78))
        else:
            self.hover_action = None
            self.pressed_action = None
            close_k, close_c = Spring.coefficients(27.0, 0.72)
            self.dspr.set_target(0.0, close_k, close_c)
            self.pspr.set_target(0.0, close_k, close_c)
            self.ospr.set_target(0.0, *Spring.coefficients(35.0, 0.84))
            self.offset_spr.set_target(8 * self.s, *Spring.coefficients(28.0, 0.78))
        self._kick()

    def _set_outside_click_watch(self, enabled):
        """Observe outside clicks only while the detail surface is open."""
        if enabled:
            if self.outside_click_job is None:
                self.outside_click_button_down = bool(
                    _u.GetAsyncKeyState(VK_LBUTTON) & 0x8000)
                self.outside_click_job = self.root.after(
                    16, self._poll_outside_click)
        elif self.outside_click_job is not None:
            try:
                self.root.after_cancel(self.outside_click_job)
            except Exception:  # noqa: BLE001
                pass
            self.outside_click_job = None
            self.outside_click_button_down = bool(
                _u.GetAsyncKeyState(VK_LBUTTON) & 0x8000)

    def _point_inside_island(self, px, py):
        """Match clicks against the visible rounded panel, excluding transparent corners."""
        w = max(8 * self.s, float(self.wspr.x))
        h = max(8 * self.s, float(self.hspr.x))
        surface_h = min(h + max(0.0, float(self.dspr.x)),
                        max(h, self._max_surface_height()))
        left = float(self.xspr.x) - w / 2.0
        top = float(self.yspr.x)
        right, bottom = left + w, top + surface_h
        if px < left or px > right or py < top or py > bottom:
            return False

        progress = _clamp(float(self.pspr.x))
        top_r = h / 2.0 + (38 * self.s - h / 2.0) * progress
        bottom_r = h / 2.0 + (24 * self.s - h / 2.0) * progress
        radius_scale = min(
            1.0, w / max(2.0 * top_r, 1e-6),
            surface_h / max(top_r + bottom_r, 1e-6),
            w / max(top_r + bottom_r, 1e-6),
        )
        top_r *= radius_scale
        bottom_r *= radius_scale
        corners = (
            (left + top_r, top + top_r, top_r, px < left + top_r and py < top + top_r),
            (right - top_r, top + top_r, top_r, px > right - top_r and py < top + top_r),
            (right - bottom_r, bottom - bottom_r, bottom_r,
             px > right - bottom_r and py > bottom - bottom_r),
            (left + bottom_r, bottom - bottom_r, bottom_r,
             px < left + bottom_r and py > bottom - bottom_r),
        )
        for cx, cy, radius, in_corner in corners:
            if in_corner and (px - cx) ** 2 + (py - cy) ** 2 > radius ** 2:
                return False
        return True

    def _poll_outside_click(self):
        self.outside_click_job = None
        panel = self.message_center.panel
        if not panel or not panel.is_open:
            self.outside_click_button_down = False
            return

        button_down = bool(_u.GetAsyncKeyState(VK_LBUTTON) & 0x8000)
        if button_down and not self.outside_click_button_down:
            point = wintypes.POINT()
            if _u.GetCursorPos(ctypes.byref(point)) and not self._point_inside_island(
                    point.x, point.y):
                self.outside_click_button_down = True
                panel.close()
                return
        self.outside_click_button_down = button_down
        self.outside_click_job = self.root.after(16, self._poll_outside_click)

    def _max_surface_height(self):
        _vx, vy, _vw, virtual_h = virtual_screen()
        available = (vy + virtual_h - self.yspr.x - self.renderer.top
                     - self.renderer.bottom - 8 * self.s)
        return max(self.H_EXP * self.s, min(virtual_h * 0.88, available))

    def _set_visible(self, visible):
        if visible != self.visible:
            self.visible = visible
            _u.ShowWindow(self.hwnd, 4 if visible else 0)  # SW_SHOWNOACTIVATE / SW_HIDE

    # -- 动画
    def _kick(self):
        if self.job is None:
            now = time.perf_counter()
            self.last = now
            self.next_frame = now + self.FRAME_INTERVAL
            self.job = self.root.after(0, self._tick)

    def _tick(self):
        t0 = time.perf_counter()
        # Spring.step is an analytic integrator, so use the real elapsed time.
        # Capping dt makes a delayed frame artificially slow down the motion.
        dt = max(1e-4, t0 - self.last)
        self.last = t0
        springs = (self.wspr, self.hspr, self.dspr, self.pspr, self.ospr,
                   self.offset_spr, self.xspr, self.yspr, self.theme_mix)
        for spring in springs:
            spring.step(dt)

        # Preserve the existing fade timing for compact and preview content.
        S = self.s
        e = _clamp((self.wspr.x - S * self.W_COMPACT) /
                   (S * (self.W_EXP - self.W_COMPACT)))
        ea_t = 1.0 if (self.state == "expanded" and e > 0.5) else 0.0
        ca_t = 1.0 if (self.state == "compact" and e < 0.35) else 0.0
        for name, target in (("ea", ea_t), ("ca", ca_t)):
            cur = getattr(self, name)
            rate = 14.0 if target > cur else 24.0
            cur += (target - cur) * (-math.expm1(-dt * rate))
            if abs(cur - target) < 0.01:
                cur = target
            setattr(self, name, cur)

        moving = (any(not spring.at_rest for spring in springs)
                  or self.ea not in (0.0, 1.0) or self.ca not in (0.0, 1.0))
        if not moving and self.ea in (0.0, 1.0) and self.ca in (0.0, 1.0):
            for spring in springs:
                spring.snap()
            moving = False
        self._push()

        panel = self.message_center.panel
        if (self.detail_was_open and panel and not panel.is_open
                and self.pspr.target == 0 and self.pspr.at_rest
                and self.dspr.at_rest and self.ospr.at_rest):
            self.detail_was_open = False
            if self._pointer_over_header():
                self._go("expanded")
            else:
                self._go("compact" if self.pending or self.external_message else "idle")
            moving = True

        if not moving:
            self.job = None
            if self.hide_idle and self.state == "idle":
                self._set_visible(False)
        else:
            now = time.perf_counter()
            while self.next_frame <= now:
                self.next_frame += self.FRAME_INTERVAL
            delay = max(1, int((self.next_frame - now) * 1000.0 + 0.5))
            self.next_frame += self.FRAME_INTERVAL
            self.job = self.root.after(delay, self._tick)

    def _go(self, state):
        self.state = state
        S = self.s
        if state == "expanded":
            w, h = self.W_EXP, self.H_EXP
            k, c = Spring.coefficients(27.0, 0.70)
        elif state == "compact":
            w, h = self.W_COMPACT, self.H_COMPACT
            k, c = Spring.coefficients(28.0, 0.72)
        else:
            w, h = self.W_IDLE, self.H_IDLE
            k, c = Spring.coefficients(28.0, 0.72)
        if state != "idle" or self.visible is False:
            self._set_visible(True)
        self.wspr.set_target(S * w, k, c)
        self.hspr.set_target(S * h, k, c)
        self._kick()

    # -- 状态
    def _cancel_collapse(self):
        if self.collapse_job:
            self.root.after_cancel(self.collapse_job)
            self.collapse_job = None

    def _schedule_collapse(self, ms):
        self._cancel_collapse()
        self.collapse_job = self.root.after(ms, self._collapse)

    def _collapse(self):
        self.collapse_job = None
        if self.message_center.panel and self.message_center.panel.is_open:
            return
        self.hover = False
        self._go("compact" if self.pending or self.external_message else "idle")

    def _on_external_message(self, message):
        self.external_message = message
        self.external_sender, self.external_summary = (
            extract_message_details(message["content"]) if message else ("", ""))
        self.hover = False
        self._cancel_collapse()
        if message:
            self._go("expanded")
            if not (self.message_center.panel and self.message_center.panel.is_open):
                self._schedule_collapse(self.PREVIEW_MS)
        elif self.message_center.panel and self.message_center.panel.is_open:
            # Reading the last unread item must not collapse the open detail surface.
            self._go("expanded")
        else:
            self._go("compact" if self.pending else "idle")

    def _on_flash(self, hwnd=0, pid=0):
        key = int(hwnd or 0)
        if key in self.pending_windows:  # 同一窗口的重复闪动合并
            return
        self.pending_windows[key] = int(pid or 0)
        self.pending = True
        self.source_label = wechat_source_label(pid)
        self._go("expanded")
        self._schedule_collapse(self.PREVIEW_MS)

    def _clear(self, hwnd=0, pid=0):
        key = int(hwnd or 0)
        removed = False
        if key and 0 in self.pending_windows:
            self.pending_windows.pop(0, None)
            removed = True
        if key in self.pending_windows:
            self.pending_windows.pop(key, None)
            removed = True
        elif key == 0 and 0 in self.pending_windows:
            self.pending_windows.pop(0, None)
            removed = True
        else:
            # 激活事件偶尔可能指向同一进程的代理窗口；只有唯一候选时才回退按 PID 清除。
            candidates = [handle for handle, owner_pid in self.pending_windows.items()
                          if handle and pid and owner_pid == int(pid)]
            if len(candidates) == 1:
                self.pending_windows.pop(candidates[0], None)
                removed = True
        if not removed:
            return
        self.pending = bool(self.pending_windows)
        self.source_label = pending_wechat_source_label(self.pending_windows)
        self.hover = False
        self._cancel_collapse()
        if self.message_center.panel and self.message_center.panel.is_open:
            self._go("expanded")
            return
        if self.pending or self.external_message:
            self._go("compact")
            return
        self._go("idle")

    # -- 交互：悬停 / 点击 / 拖动
    def _on_enter(self, _e):
        if self.dragging:
            return
        if self.message_center.panel and self.message_center.panel.is_open:
            return
        if (self.pending or self.external_message) and self.state == "compact":
            self.hover = True
            self._cancel_collapse()
            self._go("expanded")

    def _on_leave(self, _e):
        if self.dragging or (self.message_center.panel and self.message_center.panel.is_open):
            return
        if self.hover and self.state == "expanded":
            self._schedule_collapse(500)

    def _pointer_over_header(self):
        try:
            px = int(self.root.winfo_pointerx())
            py = int(self.root.winfo_pointery())
        except Exception:
            return False
        left = self.xspr.x - self.wspr.x / 2
        return (left <= px <= left + self.wspr.x
                and self.yspr.x <= py <= self.yspr.x + self.hspr.x)

    def _hit_detail(self, x, y):
        layout = self.renderer.last_layout
        for name in ("close", "current_tab", "history_tab", "mark_read", "mark_all_read"):
            rect = layout.get(name)
            if rect and rect[0] <= x <= rect[2] and rect[1] <= y <= rect[3]:
                return name
        for name, rect in layout.items():
            if name.startswith("history:") and rect[0] <= x <= rect[2] and rect[1] <= y <= rect[3]:
                return name
        body = layout.get("message_body")
        if body and body[0] <= x <= body[2] and body[1] <= y <= body[3]:
            return "body"
        header = layout.get("header")
        if header and header[0] <= x <= header[2] and header[1] <= y <= header[3]:
            return "header"
        return "detail_bg"

    def _perform_detail_action(self, action):
        panel = self.message_center.panel
        if not panel:
            return
        if action == "close":
            panel.close()
        elif action == "current_tab":
            panel.select_tab("current")
        elif action == "history_tab":
            panel.select_tab("history")
        elif action == "mark_read":
            panel.mark_current_read()
        elif action == "mark_all_read":
            panel.mark_all_read()
        elif action.startswith("history:"):
            panel.select_history(int(action.split(":", 1)[1]))
        elif action == "header":
            panel.close()

    def _on_pointer_motion(self, event):
        panel = self.message_center.panel
        if not panel or not panel.is_open:
            return
        x = event.x_root - self.canvas_origin[0]
        y = event.y_root - self.canvas_origin[1]
        action = self._hit_detail(x, y)
        hover = self._is_detail_button(action)
        pressed = None
        if self.press and hover and action == self.press.get("action"):
            pressed = action
        if hover != self.hover_action or pressed != self.pressed_action:
            self.hover_action = hover
            self.pressed_action = pressed
            self._push()

    @staticmethod
    def _is_detail_button(action):
        if action in ("close", "current_tab", "history_tab", "mark_read", "mark_all_read"):
            return action
        return action if isinstance(action, str) and action.startswith("history:") else None

    def _on_wheel(self, event):
        panel = self.message_center.panel
        if not panel or not panel.is_open:
            return
        # Client coordinates are in the same coordinate space as renderer layout;
        # this avoids screen/DPI rounding drift after dragging the layered window.
        x = getattr(event, "x", 0)
        y = getattr(event, "y", 0)
        delta = int(getattr(event, "delta", 0) or 0)
        if not delta:
            number = getattr(event, "num", None)
            delta = 120 if number == 4 else -120 if number == 5 else 0
        if not delta:
            return
        layout = self.renderer.last_layout
        if panel.active_tab == "history":
            region = "history" if "history_list" in layout and self._in_rect(x, y, layout["history_list"]) else "body"
        else:
            region = "body"
        panel.scroll(region, delta)
        return "break"

    @staticmethod
    def _in_rect(x, y, rect):
        return rect[0] <= x <= rect[2] and rect[1] <= y <= rect[3]

    def _on_press(self, e):
        x = e.x_root - self.canvas_origin[0]
        y = e.y_root - self.canvas_origin[1]
        panel = self.message_center.panel
        action = self._hit_detail(x, y) if panel and panel.is_open else None
        self.press = {
            "x": e.x_root, "y": e.y_root, "ox": self.xspr.x, "oy": self.yspr.x,
            "action": action, "detail_open": bool(panel and panel.is_open),
        }
        self.dragging = False
        self.pressed_action = self._is_detail_button(action)
        if self.pressed_action:
            self._push()

    def _on_motion(self, e):
        if self.press is None:
            return
        px, py = self.press["x"], self.press["y"]
        ox, oy = self.press["ox"], self.press["oy"]
        dx, dy = e.x_root - px, e.y_root - py
        if (not self.dragging and self.press["action"] in (None, "header")
                and max(abs(dx), abs(dy)) > self.DRAG_THRESHOLD * self.s):
            self.dragging = True
        if self.dragging:
            cx, ty = self._clamp_pos(ox + dx, oy + dy)
            for spring, value in ((self.xspr, cx), (self.yspr, ty)):  # 拖动时直接跟手，不走弹簧
                spring.x = spring.target = value
                spring.v = 0.0
            self._push()
            self.message_center.update_position()
        elif self.press and self.pressed_action:
            x = e.x_root - self.canvas_origin[0]
            y = e.y_root - self.canvas_origin[1]
            action = self._hit_detail(x, y)
            pressed = action if action == self.press.get("action") else None
            if pressed != self.pressed_action:
                self.pressed_action = pressed
                self._push()

    def _on_release(self, e):
        if self.press is None:
            return
        press = self.press
        was_drag = self.dragging
        action = press["action"]
        now = time.perf_counter()
        if (not was_drag and is_detail_double_click(
                self.last_detail_click, now, e.x_root, e.y_root,
                max_distance=10 * self.s)):
            self.last_detail_click = None
            self.press = None
            self.dragging = False
            if self.pressed_action is not None:
                self.pressed_action = None
                self._push()
            _, hwnd = mark_all_read_and_open_wechat(
                self.message_center, self.pending_windows, self.last_opened_hwnd)
            if hwnd is not None:
                self.last_opened_hwnd = hwnd
            return
        if was_drag or not press.get("detail_open"):
            self.last_detail_click = None
        else:
            self.last_detail_click = (now, e.x_root, e.y_root)
        if not was_drag and action is None and self.message_center.panel and self.message_center.panel.is_open:
            x = e.x_root - self.canvas_origin[0]
            y = e.y_root - self.canvas_origin[1]
            action = self._hit_detail(x, y)
        self.press = None
        self.dragging = False
        had_pressed = self.pressed_action is not None
        self.pressed_action = None
        if had_pressed:
            self._push()
        if was_drag:
            save_position((self.xspr.x, self.yspr.x))
        elif action and action != "detail_bg":
            self._perform_detail_action(action)
        elif action == "detail_bg":
            return
        elif self.external_message:
            self.message_center.toggle_current(self.external_message["id"])
        else:
            opened, hwnd = open_wechat_target(
                self.pending_windows, self.last_opened_hwnd)
            if hwnd is not None:
                self.last_opened_hwnd = hwnd

    def _on_right_click(self, event):
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _copy_receive_endpoint(self):
        try:
            copy_receive_endpoint(self.root, self.receive_token, self.receive_port)
        except Exception as exc:  # noqa: BLE001
            if sys.stderr is not None:
                print(f"复制消息接口失败：{exc}", file=sys.stderr)

    def _check_for_updates(self):
        if self.update_check_in_progress:
            return
        self.update_check_in_progress = True
        check_github_release_async(self.events)

    def _poll(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "flash":
                    self._on_flash(*payload)
                elif kind == "activated":
                    self._clear(*payload)
                elif kind == "tray_restore":
                    self._reset_position()
                elif kind == "tray_messages":
                    self.message_center.show_history()
                elif kind == "tray_copy_interface":
                    self._copy_receive_endpoint()
                elif kind == "tray_documentation":
                    open_documentation()
                elif kind == "tray_github":
                    open_github()
                elif kind == "tray_check_updates":
                    self._check_for_updates()
                elif kind == "update_result":
                    self.update_check_in_progress = False
                    show_update_result(payload)
                elif kind == "message_received":
                    self.message_center.receive(payload)
                elif kind == "tray_exit":
                    self.quit()
                    return
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    def _keep_on_top(self):
        self.root.attributes("-topmost", True)
        self.root.after(2000, self._keep_on_top)

    def quit(self):
        self._set_outside_click_watch(False)
        if self.glass_refresh_job is not None:
            try:
                self.root.after_cancel(self.glass_refresh_job)
            except Exception:  # noqa: BLE001
                pass
            self.glass_refresh_job = None
        if self.background_sampler is not None:
            self.background_sampler.close()
            self.background_sampler = None
        self.surface.close()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ----------------------------------------------------------------------------
# 备用 UI（tkinter，未安装 Pillow 时使用）
# ----------------------------------------------------------------------------
class TkCapsule:
    KEY = "#010101"          # 透明色键
    H = 34
    W_IDLE = 92
    W_COMPACT = 180
    W_PREVIEW = 340
    TOP = 8
    PREVIEW_MS = 5000

    BG = "#15171a"
    FG = "#e8eaed"
    FG_DIM = "#8a9099"
    GREEN = "#2ecc71"
    GREY = "#555b63"
    FONT = ("Microsoft YaHei UI", 10)

    def __init__(self, events, message_store=None, receive_token=None,
                 receive_port=DEFAULT_RECEIVE_PORT):
        import tkinter as tk
        self.tk = tk
        self.events = events
        self.receive_token = receive_token or get_receive_token()
        self.receive_port = receive_port
        self.update_check_in_progress = False

        self.root = tk.Tk()
        self.root.title("WeChat Capsule")
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        self.root.configure(bg=self.KEY)
        self.external_message = None
        self.external_sender = ""
        self.external_summary = ""
        self.message_center = MessageCenter(
            self.root, message_store or MessageStore(), self._on_external_message,
            self._panel_anchor, scale=1.0, on_detail_change=self._on_detail_change)
        try:
            self.root.attributes("-transparentcolor", self.KEY)
        except tk.TclError:
            pass

        self.sw = self.root.winfo_screenwidth()
        self.cx = self.sw // 2
        self.ty = self.TOP
        self._press = None
        self._dragging = False
        self.last_detail_click = None
        self.canvas = tk.Canvas(self.root, bg=self.KEY, highlightthickness=0,
                                bd=0, height=self.H)
        self.canvas.pack(fill="both", expand=True)

        self.pending = False
        self.pending_windows = {}   # 主窗口 HWND -> PID；负数表示未解析主窗；0 表示手动提醒
        self.source_label = ""
        self.last_opened_hwnd = None
        self.w = float(self.W_IDLE)
        self.target = float(self.W_IDLE)
        self.panel_h = float(self.H)
        self.target_panel_h = float(self.H)
        self.detail_full_h = float(self.H)
        self.tk_layout = {}
        self.tk_detail_visible = False
        self.anim = None
        self.anim_last = time.perf_counter()
        self.collapse_job = None

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="恢复到顶部", command=self._reset_position)
        self.menu.add_command(label="模拟一次提醒", command=lambda: self._on_flash())
        self.menu.add_command(label="消息记录", command=self.message_center.show_history)
        self.menu.add_command(label="复制接口", command=self._copy_receive_endpoint)
        self.menu.add_command(label="查看文档", command=open_documentation)
        self.menu.add_command(label="GitHub", command=open_github)
        self.menu.add_command(label="检查更新",
                              command=self._check_for_updates)
        self.menu.add_separator()
        self.menu.add_command(label="退出", command=self.quit)

        self.canvas.bind("<ButtonPress-1>", self._on_press)
        self.canvas.bind("<B1-Motion>", self._on_motion)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)
        self.canvas.bind("<Button-3>", self._on_right_click)
        self.canvas.bind("<MouseWheel>", self._on_wheel)
        self.canvas.bind("<Button-4>", self._on_wheel)
        self.canvas.bind("<Button-5>", self._on_wheel)

        self._place()
        self._draw()
        self.root.after(80, self._poll)
        self.root.after(2000, self._keep_on_top)
        self.root.after(0, self.message_center.restore_unread)

    # -- 绘制
    def _rounded(self, x1, y1, x2, y2, r, **kw):
        pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
               x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
        return self.canvas.create_polygon(pts, smooth=True, **kw)

    def _place(self):
        w = max(int(self.w), 20)
        x = int(self.cx - w / 2)
        h = max(self.H, int(math.ceil(self.panel_h)))
        self.canvas.configure(width=w, height=h)
        self.root.geometry(f"{w}x{h}+{x}+{self.ty}")
        self.message_center.update_position()

    def _panel_anchor(self):
        return self.cx, self.ty, 1.0, float(self.H), self.w

    @staticmethod
    def _wrap_canvas_text(text, max_units):
        lines = []
        for paragraph in str(text or "").replace("\r", "").split("\n"):
            if not paragraph:
                lines.append("")
                continue
            line, units = "", 0.0
            for char in paragraph:
                char_units = 1.0 if ord(char) > 255 else 0.55
                if line and units + char_units > max_units:
                    lines.append(line)
                    line, units = char, char_units
                else:
                    line += char
                    units += char_units
            lines.append(line)
        return lines or [""]

    def _morphed_points(self, width, height, progress):
        tl = tr = self.H / 2 + (34 - self.H / 2) * progress
        br = bl = self.H / 2 + (22 - self.H / 2) * progress
        pts = []
        for cx, cy, radius, start in ((tl, tl, tl, 180),
                                      (width-tr, tr, tr, 270),
                                      (width-br, height-br, br, 0),
                                      (bl, height-bl, bl, 90)):
            for i in range(9):
                angle = math.radians(start + i * 90 / 8)
                pts.append((cx + radius * math.cos(angle), cy + radius * math.sin(angle)))
        return [coord for point in pts for coord in point]

    def _on_detail_change(self):
        panel = self.message_center.panel
        if not panel:
            return
        if panel.is_open:
            self.tk_detail_visible = True
            self._set_target(self.W_PREVIEW)
            vm = panel.view_model()
            rows = vm.get("rows", [])
            if vm.get("tab") == "history":
                body = vm.get("selected_body", "")
                lines = len(self._wrap_canvas_text(body, 31))
                desired = self.H + 60 + min(6, len(rows)) * 36 + min(8, lines) * 19 + 80
            else:
                body = vm.get("body", "")
                lines = len(self._wrap_canvas_text(body, 31))
                desired = self.H + 165 + min(16, lines) * 20
            max_height = max(self.H, self.root.winfo_screenheight() - self.ty - 8)
            self.target_panel_h = min(desired, max_height)
            self.detail_full_h = max(self.H + 1, self.target_panel_h)
        else:
            self.target_panel_h = float(self.H)
            self._set_target(self.target)
        self._place()
        self._draw()

    def _draw(self):
        c = self.canvas
        c.delete("all")
        w = max(int(self.w), 20)
        h = max(self.H, int(self.panel_h))
        panel = self.message_center.panel
        detail_open = bool(panel and (panel.is_open or self.tk_detail_visible))
        progress = min(1.0, max(0.0, (h - self.H) / max(1, self.detail_full_h - self.H)))
        c.create_polygon(self._morphed_points(w, h, progress), fill="#000000",
                         outline="", smooth=False)
        self.tk_layout = {}
        has_message = bool(self.external_message)
        dot_color = self.GREEN if self.pending or has_message else self.GREY
        cy = self.H // 2
        c.create_oval(14, cy - 5, 24, cy + 5, fill=dot_color, outline="")
        if self.w > 210:
            if has_message:
                subtitle = (f"{self.external_sender or '微信消息'}："
                            f"{self.external_summary}")
            elif self.source_label:
                subtitle = f"{self.source_label} · 点击打开"
            else:
                subtitle = "微信有新提醒 · 点击打开"
            c.create_text(34, cy, anchor="w", fill=self.FG, font=self.FONT,
                          text=truncate_display_text(subtitle, max(8, int((w - 48) / 10))))
        elif self.w > 120:
            preview = (f"{self.external_sender or '微信消息'}：{self.external_summary}"
                       if has_message else self.source_label or "有新消息待查看")
            c.create_text(34, cy, anchor="w",
                          fill=self.FG if self.pending or has_message else self.FG_DIM,
                          font=self.FONT,
                          text=truncate_display_text(preview, max(8, int((w - 48) / 10))))
        elif self.w > 70:
            c.create_text(34, cy, anchor="w",
                          fill=self.FG if self.pending else self.FG_DIM,
                          font=self.FONT, text="微信")
        if detail_open:
            vm = panel.view_model()
            left, right = 22, w - 22
            y = self.H + 17
            cur = (left, y, left + 96, y + 28)
            hist = (left + 96, y, left + 192, y + 28)
            close = (right - 28, y, right, y + 28)
            self.tk_layout.update(current_tab=cur, history_tab=hist, close=close,
                                  header=(0, 0, w, self.H))
            c.create_text(cur[0] + 2, y + 14, anchor="w", text="当前消息",
                          fill="#f4f5f7" if vm["tab"] == "current" else "#8b929b",
                          font=("Microsoft YaHei UI", 11))
            c.create_text(hist[0] + 2, y + 14, anchor="w", text="历史消息",
                          fill="#f4f5f7" if vm["tab"] == "history" else "#8b929b",
                          font=("Microsoft YaHei UI", 11))
            c.create_text((close[0] + close[2]) / 2, y + 13, text="×",
                          fill="#b8bec7", font=("Microsoft YaHei UI", 14))
            y += 42
            if vm["tab"] == "history":
                rows = vm.get("rows", [])
                visible = min(6, len(rows))
                start = vm.get("history_scroll", 0)
                for j, index in enumerate(range(start, min(len(rows), start + visible))):
                    row_y = y + j * 30
                    rect = (left, row_y, right, row_y + 28)
                    self.tk_layout[f"history:{index}"] = rect
                    selected = index == vm.get("selected_index")
                    c.create_rectangle(*rect, fill="#263c32" if selected else "#121417", outline="")
                    row = rows[index]
                    marker = "●" if row.get("unread") else "○"
                    c.create_text(left + 8, row_y + 14, anchor="w", fill="#e3e7ec",
                                  font=("Microsoft YaHei UI", 9),
                                  text=truncate_display_text(f"{marker} {row['sender']} · {row['body']}", max(8, int((w-65)/9))))
                y += max(30, visible * 30) + 8
                sender, body = vm.get("selected_sender", "微信消息"), vm.get("selected_body", "")
                c.create_text(left + 2, y, anchor="nw", fill="#f1f3f5",
                              font=("Microsoft YaHei UI", 11, "bold"), text=sender)
                y += 24
                body_rect = (left, y, right, h - 48)
                self.tk_layout["message_body"] = body_rect
                c.create_rectangle(*body_rect, fill="#121417", outline="")
                lines = self._wrap_canvas_text(body, 26)
                visible_lines = max(1, int((body_rect[3]-body_rect[1]-18) / 17))
                start = vm.get("body_scroll", 0)
                c.create_text(left + 10, y + 9, anchor="nw",
                              fill="#e1e5ea", font=("Microsoft YaHei UI", 10),
                              text="\n".join(lines[start:start+visible_lines]))
                btn = (right - 108, h - 38, right, h - 10)
                self.tk_layout["mark_all_read"] = btn
                c.create_rectangle(*btn, fill="#191c20", outline="")
                c.create_text((btn[0]+btn[2])/2, (btn[1]+btn[3])/2, text="全部标为已读",
                              fill="#c7cdd5", font=("Microsoft YaHei UI", 9))
            else:
                sender = vm.get("sender", "微信消息")
                body = vm.get("body", "") or "暂无当前消息"
                c.create_text(left + 2, y, anchor="nw", width=right-left,
                              fill="#f1f3f5", font=("Microsoft YaHei UI", 11, "bold"), text=sender)
                y += 28
                body_rect = (left, y, right, h - 48)
                self.tk_layout["message_body"] = body_rect
                c.create_rectangle(*body_rect, fill="#121417", outline="")
                lines = self._wrap_canvas_text(body, 26)
                visible_lines = max(1, int((body_rect[3]-body_rect[1]-18) / 18))
                start = vm.get("body_scroll", 0)
                c.create_text(left + 10, y + 9, anchor="nw",
                              fill="#e1e5ea", font=("Microsoft YaHei UI", 10),
                              text="\n".join(lines[start:start+visible_lines]))
                if vm.get("unread"):
                    btn = (right - 82, h - 38, right, h - 10)
                    self.tk_layout["mark_read"] = btn
                    c.create_rectangle(*btn, fill="#19261f", outline="")
                    c.create_text((btn[0]+btn[2])/2, (btn[1]+btn[3])/2, text="标记已读",
                                  fill="#c5e0cf", font=("Microsoft YaHei UI", 9))

    # -- 动画
    def _set_target(self, target):
        self.target = float(target)
        if self.anim is None:
            self.anim_last = time.perf_counter()
            self.anim = self.root.after(0, self._animate)

    def _animate(self):
        self.anim = None
        now = time.perf_counter()
        dt = max(0.0, now - self.anim_last)
        self.anim_last = now
        diff = self.target - self.w
        height_diff = self.target_panel_h - self.panel_h
        if abs(diff) < 0.5 and abs(height_diff) < 0.8:
            self.w = self.target
            self.panel_h = self.target_panel_h
        else:
            self.w += diff * (-math.expm1(-20.0 * dt))
            self.panel_h += height_diff * (-math.expm1(-15.0 * dt))
            self.anim = self.root.after(16, self._animate)
        if not (self.message_center.panel and self.message_center.panel.is_open) and self.panel_h <= self.H + 1:
            self.tk_detail_visible = False
        self._place()
        self._draw()

    # -- 状态
    def _on_flash(self, hwnd=0, pid=0):
        key = int(hwnd or 0)
        if key in self.pending_windows:  # 同一窗口的重复闪动合并
            return
        self.pending_windows[key] = int(pid or 0)
        self.pending = True
        self.source_label = wechat_source_label(pid)
        self._set_target(self.W_PREVIEW)
        if self.collapse_job:
            self.root.after_cancel(self.collapse_job)
        self.collapse_job = self.root.after(self.PREVIEW_MS, self._collapse)

    def _on_external_message(self, message):
        self.external_message = message
        self.external_sender, self.external_summary = (
            extract_message_details(message["content"]) if message else ("", ""))
        if self.collapse_job:
            self.root.after_cancel(self.collapse_job)
            self.collapse_job = None
        if message:
            self._set_target(self.W_PREVIEW)
            self.collapse_job = self.root.after(self.PREVIEW_MS, self._collapse)
        elif self.message_center.panel and self.message_center.panel.is_open:
            self._set_target(self.W_PREVIEW)
        else:
            self._set_target(self.W_COMPACT if self.pending else self.W_IDLE)
        self._draw()

    def _collapse(self):
        self.collapse_job = None
        if self.message_center.panel and self.message_center.panel.is_open:
            return
        self._set_target(self.W_COMPACT if self.pending or self.external_message
                          else self.W_IDLE)

    def _clear(self, hwnd=0, pid=0):
        key = int(hwnd or 0)
        removed = False
        if key and 0 in self.pending_windows:
            self.pending_windows.pop(0, None)
            removed = True
        if key in self.pending_windows:
            self.pending_windows.pop(key, None)
            removed = True
        elif key == 0 and 0 in self.pending_windows:
            self.pending_windows.pop(0, None)
            removed = True
        else:
            candidates = [handle for handle, owner_pid in self.pending_windows.items()
                          if handle and pid and owner_pid == int(pid)]
            if len(candidates) == 1:
                self.pending_windows.pop(candidates[0], None)
                removed = True
        if not removed:
            return
        self.pending = bool(self.pending_windows)
        self.source_label = pending_wechat_source_label(self.pending_windows)
        if self.collapse_job:
            self.root.after_cancel(self.collapse_job)
            self.collapse_job = None
        self._set_target(self.W_PREVIEW if self.message_center.panel and self.message_center.panel.is_open
                         else self.W_COMPACT if self.pending or self.external_message else self.W_IDLE)
        self._draw()

    # -- 交互
    def _on_press(self, e):
        self._press = (e.x_root, e.y_root, self.cx, self.ty, e.y < self.H)
        self._dragging = False

    def _on_motion(self, e):
        if self._press is None:
            return
        px, py, ox, oy, allow_drag = self._press
        if not allow_drag:
            return
        dx, dy = e.x_root - px, e.y_root - py
        if not self._dragging and (abs(dx) > 4 or abs(dy) > 4):
            self._dragging = True
        if self._dragging:
            self.cx = ox + dx
            self.ty = max(0, oy + dy)
            self._place()

    def _on_release(self, e):
        if self._press is None:
            return
        was_drag = self._dragging
        self._press = None
        self._dragging = False
        if not was_drag:
            self._on_click(e)

    def _reset_position(self):
        self.cx = self.sw // 2
        self.ty = self.TOP
        self._place()

    def _on_click(self, event):
        panel = self.message_center.panel
        now = time.perf_counter()
        if is_detail_double_click(
                self.last_detail_click, now, event.x_root, event.y_root):
            self.last_detail_click = None
            opened, hwnd = mark_all_read_and_open_wechat(
                self.message_center, self.pending_windows, self.last_opened_hwnd)
            if hwnd is not None:
                self.last_opened_hwnd = hwnd
            if not opened:
                self._toast_error()
            return
        if panel and panel.is_open:
            self.last_detail_click = (now, event.x_root, event.y_root)
            x, y = event.x, event.y
            action = None
            for key in ("close", "current_tab", "history_tab", "mark_read", "mark_all_read"):
                rect = self.tk_layout.get(key)
                if rect and rect[0] <= x <= rect[2] and rect[1] <= y <= rect[3]:
                    action = key
                    break
            if action is None:
                for key, rect in self.tk_layout.items():
                    if key.startswith("history:") and rect[0] <= x <= rect[2] and rect[1] <= y <= rect[3]:
                        action = key
                        break
            if action == "close":
                panel.close()
            elif action == "current_tab":
                panel.select_tab("current")
            elif action == "history_tab":
                panel.select_tab("history")
            elif action == "mark_read":
                panel.mark_current_read()
            elif action == "mark_all_read":
                panel.mark_all_read()
            elif action and action.startswith("history:"):
                panel.select_history(int(action.split(":", 1)[1]))
            elif action is None and y < self.H:
                panel.close()
            return
        self.last_detail_click = None
        if self.external_message:
            self.message_center.toggle_current(self.external_message["id"])
            return
        opened, hwnd = open_wechat_target(
            self.pending_windows, self.last_opened_hwnd)
        if hwnd is not None:
            self.last_opened_hwnd = hwnd
        if not opened:
            self._toast_error()

    def _on_wheel(self, event):
        panel = self.message_center.panel
        if not panel or not panel.is_open:
            return
        delta = int(getattr(event, "delta", 0) or 0)
        if not delta:
            number = getattr(event, "num", None)
            delta = 120 if number == 4 else -120 if number == 5 else 0
        if not delta:
            return
        rect = self.tk_layout.get("message_body")
        region = "body"
        for key, candidate in self.tk_layout.items():
            if key.startswith("history:") and candidate[0] <= event.x <= candidate[2] and candidate[1] <= event.y <= candidate[3]:
                panel.scroll("history", delta)
                return "break"
        if rect and rect[0] <= event.x <= rect[2] and rect[1] <= event.y <= rect[3]:
            panel.scroll(region, delta)
            return "break"

    def _toast_error(self):
        # 简单反馈：把胶囊短暂展开并显示错误
        c = self.canvas
        c.create_text(self.w / 2, self.H / 2, fill="#ff6b6b", font=self.FONT,
                      text="未能唤起微信，请从托盘打开")
        self.root.after(1500, self._draw)

    def _on_right_click(self, event):
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _copy_receive_endpoint(self):
        try:
            copy_receive_endpoint(self.root, self.receive_token, self.receive_port)
        except Exception as exc:  # noqa: BLE001
            if sys.stderr is not None:
                print(f"复制消息接口失败：{exc}", file=sys.stderr)

    def _check_for_updates(self):
        if self.update_check_in_progress:
            return
        self.update_check_in_progress = True
        check_github_release_async(self.events)

    def _poll(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "flash":
                    self._on_flash(*payload)
                elif kind == "activated":
                    self._clear(*payload)
                elif kind == "tray_restore":
                    self._reset_position()
                elif kind == "tray_messages":
                    self.message_center.show_history()
                elif kind == "tray_copy_interface":
                    self._copy_receive_endpoint()
                elif kind == "tray_documentation":
                    open_documentation()
                elif kind == "tray_github":
                    open_github()
                elif kind == "tray_check_updates":
                    self._check_for_updates()
                elif kind == "update_result":
                    self.update_check_in_progress = False
                    show_update_result(payload)
                elif kind == "message_received":
                    self.message_center.receive(payload)
                elif kind == "tray_exit":
                    self.quit()
                    return
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    def _keep_on_top(self):
        self.root.attributes("-topmost", True)
        self.root.lift()
        self.root.after(2000, self._keep_on_top)

    def quit(self):
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ----------------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------------
def list_wechat_processes():
    try:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                             capture_output=True, text=True,
                             encoding="gbk", errors="replace").stdout
    except Exception:  # noqa: BLE001
        return []
    rows = []
    for line in out.splitlines():
        low = line.lower()
        if "weixin" in low or "wechat" in low:
            rows.append(line.split('","')[0].strip('"'))
    return rows


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def get_lan_ip():
    """返回当前首选局域网 IPv4 地址，供远程发送端配置接口地址。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    finally:
        sock.close()
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = item[4][0]
            if not ip.startswith(("127.", "169.254.")):
                return ip
    except OSError:
        pass
    return "127.0.0.1"


def show_startup_error(message):
    try:
        if sys.stderr is not None:
            print(message, file=sys.stderr)
    except Exception:  # noqa: BLE001
        pass
    try:
        ctypes.windll.user32.MessageBoxW(None, message, "微信消息胶囊", 0x10)
    except Exception:  # noqa: BLE001
        pass


CODE_NAMES = {HSHELL_FLASH: "FLASH", HSHELL_REDRAW: "REDRAW",
              HSHELL_WINDOWACTIVATED: "ACTIVATED",
              HSHELL_RUDEAPPACTIVATED: "ACTIVATED"}


def run_probe(names, seconds, show_all):
    """只读诊断：打印事件，不弹 UI。"""
    counts = {"flash": 0, "activated": 0, "redraw": 0, "all_flash": 0}

    def on_event(kind, payload):
        if kind != "raw":
            return
        code, exe, wechat, title, hwnd, pid, main_hwnd = payload
        if code == HSHELL_FLASH:
            counts["all_flash"] += 1
        if wechat:
            if code == HSHELL_FLASH:
                counts["flash"] += 1
            elif code == HSHELL_REDRAW:
                counts["redraw"] += 1
            else:
                counts["activated"] += 1
        # 默认只显示微信事件；--all 时显示所有程序的 FLASH / 激活事件
        if wechat or (show_all and code != HSHELL_REDRAW):
            tag = "WECHAT" if wechat else "other "
            extra = f"  title={title!r}" if title else ""
            print(f"[{time.strftime('%H:%M:%S')}] {tag} "
                  f"{CODE_NAMES.get(code, hex(code)):9s} {exe} "
                  f"hwnd=0x{hwnd:X} pid={pid} "
                  f"main=0x{main_hwnd:X}{extra}")

    print("== 环境信息 ==")
    print(f"Python: {sys.version.split()[0]} ({struct.calcsize('P') * 8} 位)  {sys.executable}")
    print(f"本脚本是否管理员运行: {is_admin()}")
    procs = list_wechat_processes()
    print("检测到的微信相关进程:", ", ".join(sorted(set(procs))) or "（没有！微信没在运行？）")
    print("匹配的进程名:", ", ".join(sorted(names)))

    listener = ShellHookListener(names, on_event, probe=True)
    listener.start()
    listener.ready.wait(5)
    if listener.error:
        print("注册 Shell Hook 失败：", listener.error)
        return 1
    print(f"\n== 监听中（{seconds} 秒，Ctrl+C 提前结束）==")
    print("请让别人给你发微信，并确保微信不在前台、任务栏上有微信图标。")
    if show_all:
        print("（--all 已开启：其他程序的闪烁/激活事件也会显示）")
    print("提示：先随便切换几次窗口（Alt+Tab）。如果下面的心跳一直是 0，"
          "说明 Hook 本身没收到任何系统消息。")
    deadline = time.time() + seconds
    try:
        while time.time() < deadline:
            time.sleep(min(5, max(0.1, deadline - time.time())))
            codes = ", ".join(hex(c) for c in sorted(listener.seen_codes)) or "无"
            print(f"[心跳] 累计收到 Shell 消息 {listener.total} 条，类型: {codes}")
    except KeyboardInterrupt:
        pass
    listener.stop()
    print(f"\n结果：微信 flash={counts['flash']}  redraw={counts['redraw']}  "
          f"activated={counts['activated']}  |  所有程序 flash={counts['all_flash']}")
    if counts["flash"] == 0:
        if counts["all_flash"] > 0:
            print("→ Shell Hook 本身工作正常（收到了其他程序的闪烁），"
                  "但微信没有发出闪烁，或进程名/标题没匹配上。")
        else:
            print("→ 一次闪烁都没收到。可能是：测试期间没有程序闪烁；"
                  "或 Windows 设置里关闭了任务栏闪烁。")
    return 0 if counts["flash"] else 2


def main():
    global ICON_OVERRIDE
    parser = argparse.ArgumentParser(
        description="微信提醒胶囊；同时启动局域网消息接收接口")
    parser.add_argument("--probe", action="store_true", help="只在控制台打印事件")
    parser.add_argument("--all", action="store_true",
                        help="probe 时同时显示其他程序的闪烁/激活事件")
    parser.add_argument("--seconds", type=int, default=60, help="probe 时长（秒）")
    parser.add_argument("--exe", action="append", default=[],
                        help="额外匹配的进程名，如 Weixin.exe，可重复")
    parser.add_argument("--scale", type=float, default=None,
                        help="界面缩放倍数（默认按系统 DPI 自动）")
    parser.add_argument("--hide-idle", action="store_true",
                        help="没有提醒时隐藏胶囊，有提醒才弹出")
    parser.add_argument("--icon", default=None,
                        help="自定义图标 PNG 路径（默认使用内嵌的微信图标）")
    parser.add_argument("--tk", action="store_true",
                        help="强制使用简易 tkinter 界面（不依赖 Pillow）")
    parser.add_argument("--receive-host", default=DEFAULT_RECEIVE_HOST,
                        help="消息接口绑定地址（默认 0.0.0.0，允许局域网访问）")
    parser.add_argument("--receive-port", type=int, default=DEFAULT_RECEIVE_PORT,
                        help="消息接口端口（默认 8080）")
    parser.add_argument("--receive-token", default=None,
                        help="覆盖本机首次启动时随机生成并保存的消息接口令牌")
    args = parser.parse_args()
    ICON_OVERRIDE = args.icon

    if sys.platform != "win32":
        print("此脚本只能在 Windows 上运行。")
        return 1

    try:  # 高 DPI 下避免模糊
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001
        pass

    load_win32()
    names = set(DEFAULT_EXE_NAMES) | {n.lower() for n in args.exe}

    if args.probe:
        return run_probe(names, args.seconds, args.all)

    events = queue.Queue()
    try:
        args.receive_token = get_receive_token(args.receive_token)
        message_store = MessageStore()
        receiver = EmbeddedMessageServer(
            (args.receive_host, args.receive_port), args.receive_token,
            message_store,
            lambda message: events.put(("message_received", message)),
        )
    except (OSError, sqlite3.Error, ValueError) as exc:
        address = f"{args.receive_host}:{args.receive_port}"
        show_startup_error(
            f"局域网消息接口无法启动（{address}）：{exc}\n\n"
            "请确认端口未被占用。"
        )
        return 1

    receiver_thread = threading.Thread(
        target=receiver.serve_forever, daemon=True, name="LocalMessageReceiver")
    receiver_thread.start()
    lan_ip = get_lan_ip()
    try:
        if sys.stdout is not None:
            print(f"消息接口已启动：http://{lan_ip}:{args.receive_port}/receive")
    except Exception:  # noqa: BLE001
        pass

    listener = ShellHookListener(
        names, lambda kind, payload: events.put((kind, payload)), tray_enabled=True
    )
    listener.start()
    app = None
    interrupted = False
    try:
        listener.ready.wait(5)
        if listener.error:
            show_startup_error(f"注册 Shell Hook 或托盘图标失败：{listener.error}")
            return 1

        app = None
        if HAVE_PIL and not args.tk:
            try:
                app = LayeredCapsule(events, scale=args.scale,
                                     hide_idle=args.hide_idle,
                                     message_store=message_store,
                                     receive_token=args.receive_token,
                                     receive_port=args.receive_port)
            except Exception:  # noqa: BLE001
                if sys.stdout is not None:
                    print("Pillow 分层窗口初始化失败，退回 tkinter 界面：")
                if sys.stderr is not None:
                    traceback.print_exc()
        elif not HAVE_PIL:
            if sys.stdout is not None:
                print("提示：安装 Pillow 可获得更接近 iOS 灵动岛的效果：pip install pillow")
        if app is None:
            app = TkCapsule(events, message_store=message_store,
                            receive_token=args.receive_token,
                            receive_port=args.receive_port)
        app.run()
    except KeyboardInterrupt:
        # 控制台 Ctrl+C 是正常退出操作，不应把它作为未处理异常打印 traceback。
        interrupted = True
    finally:
        listener.stop()
        if interrupted and app is not None:
            # Ctrl+C 退出时也释放分层窗口的 GDI 资源。
            try:
                app.quit()
            except Exception:  # noqa: BLE001
                pass
        receiver.shutdown()
        receiver.server_close()
        receiver_thread.join(timeout=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
