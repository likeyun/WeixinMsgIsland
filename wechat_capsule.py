#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wechat_capsule.py —— 微信提醒胶囊（Windows；Pillow 可选，UI Automation 用于精确唤起账号）

原理：
  用 RegisterShellHookWindow 注册一个隐藏窗口，接收系统广播的 HSHELL_FLASH
  （某窗口请求任务栏关注 = 图标闪烁）。通过闪烁窗口所属进程的可执行文件名
  判断是否为微信（Weixin.exe / WeChat.exe），并按窗口句柄分别跟踪提醒。

  提醒来源是 Shell Hook；有提醒时显示绿点，不统计未读条数。

运行（推荐先 pip install pillow，获得抗锯齿/阴影/弹簧动画）：
  pythonw wechat_capsule.py           # 后台运行，可从右下角托盘菜单退出
  python wechat_capsule.py            # 调试运行（保留控制台）
  python wechat_capsule.py --hide-idle     # 无提醒时隐藏，有提醒才弹出
  python wechat_capsule.py --probe    # 只在控制台打印事件，用于诊断兼容性
  python wechat_capsule.py --probe --all   # 同时显示其他程序的闪烁事件，判断 Hook 本身是否工作
  python wechat_capsule.py --exe my.exe   # 额外匹配其他进程名（可多次指定）

操作：
  左键点击胶囊      点击对应账号的微信托盘项；无目标时通过 weixin:// 打开微信
  按住左键拖动      把胶囊拖到屏幕任意位置（位置会被记住）
  右键点击胶囊      菜单：恢复到顶部 / 模拟提醒 / 退出
  点击托盘图标      菜单：恢复胶囊位置 / 退出程序
  微信窗口被激活    自动清除提醒点
"""
import argparse
import base64
import ctypes
import io
import json
import math
import os
import queue
import struct
import subprocess
import sys
import threading
import time
import traceback
from ctypes import wintypes

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
            _u.AppendMenuW(menu, MF_STRING, TRAY_CMD_RESTORE, "恢复胶囊位置")
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


def load_position():
    """读取上次拖动后的位置：(胶囊中心 x, 胶囊顶部 y)，没有则返回 None。"""
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return float(data["cx"]), float(data["ty"])
    except Exception:  # noqa: BLE001
        return None


def save_position(pos):
    """保存位置；pos 为 None 时删除记录（即恢复默认的顶部居中）。"""
    try:
        if pos is None:
            if os.path.exists(CONFIG_PATH):
                os.remove(CONFIG_PATH)
        else:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump({"cx": pos[0], "ty": pos[1]}, f)
    except OSError:
        pass


def virtual_screen():
    """整个虚拟桌面（多显示器）的 (x, y, 宽, 高)。"""
    try:
        gm = _u.GetSystemMetrics
        return gm(76), gm(77), gm(78), gm(79)
    except Exception:  # noqa: BLE001
        return 0, 0, 1920, 1080


class Spring:
    """阻尼弹簧：欠阻尼时会有轻微过冲，这正是 iOS 灵动岛"Q弹"感的来源。"""

    def __init__(self, value, stiffness=420.0, damping=24.0):
        self.x = float(value)
        self.v = 0.0
        self.target = float(value)
        self.k = stiffness
        self.c = damping

    def set_target(self, target, stiffness=None, damping=None):
        self.target = float(target)
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
        return abs(self.x - self.target) < 0.05 and abs(self.v) < 0.5

    def snap(self):
        self.x = self.target
        self.v = 0.0


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


class IslandRenderer:
    """把"当前宽高 + 内容透明度"渲染成一张带阴影的 RGBA 图（纯 Pillow，可脱离 Windows 测试）。"""

    SS = 2  # 形状超采样倍数

    def __init__(self, scale=1.0):
        s = self.s = scale
        self.CW = int(round(420 * s))
        # 为柔和阴影预留透明留白，避免阴影在分层窗口边缘被截断。
        self.CH = int(round(144 * s))
        self.top = int(round(24 * s))
        self.f_title = _load_font(16 * s, bold=True)
        self.f_sub = _load_font(13 * s)
        self.f_compact = _load_font(11 * s)
        self.icon_big = load_wechat_icon(int(round(36 * s)))
        self.icon_small = load_wechat_icon(int(round(22 * s)))

    # -- 工具
    @staticmethod
    def _text(draw, xy, text, font, fill, anchor="lm"):
        try:
            draw.text(xy, text, font=font, fill=fill, anchor=anchor)
        except (ValueError, TypeError):
            if anchor == "mm":
                box = font.getbbox(text)
                x = xy[0] - (box[2] - box[0]) / 2 - box[0]
                y = xy[1] - (box[3] - box[1]) / 2 - box[1]
                draw.text((x, y), text, font=font, fill=fill)
            else:
                draw.text(xy, text, font=font, fill=fill)

    @staticmethod
    def _blend(base, layer, alpha, blur, mask):
        if alpha <= 0.01:
            return base
        if blur > 0.3:
            layer = layer.filter(ImageFilter.GaussianBlur(blur))
        a = layer.getchannel("A").point(lambda v: int(v * alpha))
        layer.putalpha(ImageChops.multiply(a, mask))
        return Image.alpha_composite(base, layer)

    # -- 主渲染
    def render(self, w, h, ea=0.0, ca=0.0, pending=False, hover_dot=True,
               source_label=""):
        s, ss, CW, CH = self.s, self.SS, self.CW, self.CH
        w = max(w, 8 * s)
        h = max(h, 8 * s)
        x0 = (CW - w) / 2.0
        y0 = float(self.top)

        big = Image.new("L", (CW * ss, CH * ss), 0)
        ImageDraw.Draw(big).rounded_rectangle(
            [int(x0 * ss), int(y0 * ss), int((x0 + w) * ss) - 1, int((y0 + h) * ss) - 1],
            radius=int(h / 2.0 * ss), fill=255)
        mask = big.reduce(ss)

        # 圆点使用更收敛的投影，展开后平滑过渡到胶囊的柔和阴影。
        small_shape = _clamp((52 * s - max(w, h)) / (16 * s))
        idle_scale = min(1.0, min(w, h) / (36 * s))
        shadow_scale = 1.0 - (1.0 - idle_scale) * small_shape
        shadow_offset = (6.0 - 2.5 * small_shape) * s * shadow_scale
        shadow_blur = (9.0 - 3.0 * small_shape) * s * shadow_scale
        shadow_alpha = 0.42 + 0.08 * small_shape
        shadow = Image.new("L", (CW, CH), 0)
        shadow.paste(mask, (0, int(round(shadow_offset))))
        shadow = shadow.filter(ImageFilter.GaussianBlur(shadow_blur)).point(
            lambda v: int(v * shadow_alpha))
        out = Image.new("RGBA", (CW, CH), (0, 0, 0, 0))
        out.putalpha(shadow)

        # 纯黑胶囊本体
        pill = Image.new("RGBA", (CW, CH), (0, 0, 0, 255))
        pill.putalpha(mask)
        out = Image.alpha_composite(out, pill)

        cy = y0 + h / 2.0

        # 空闲态做成镜头孔：内凹暗圈、玻璃内缘和极轻的上下反光，
        # 并随尺寸与内容透明度淡出，避免动画展开时细节突然消失。
        camera_alpha = small_shape * (1.0 - max(ea, ca))
        if camera_alpha > 0.01:
            detail = Image.new("RGBA", (CW * ss, CH * ss), (0, 0, 0, 0))
            d = ImageDraw.Draw(detail)
            cx = x0 + w / 2.0
            camera_scale = idle_scale

            def ellipse_at(radius, fill):
                radius *= camera_scale
                box = [int(round((cx - radius) * ss)), int(round((cy - radius) * ss)),
                       int(round((cx + radius) * ss)), int(round((cy + radius) * ss))]
                d.ellipse(box, fill=fill)

            # 深石墨色的窄边形成微凹边缘，中心玻璃保持接近纯黑。
            ellipse_at(15.8 * s, (20, 25, 30, 255))
            ellipse_at(14.7 * s, (3, 5, 8, 255))
            # 顶部冷色反光与底部压暗，仅提供细微的材质层次。
            r = 15.25 * s * camera_scale * ss
            box = [int(round(cx * ss - r)), int(round(cy * ss - r)),
                   int(round(cx * ss + r)), int(round(cy * ss + r))]
            d.arc(box, start=205, end=335, fill=(100, 116, 128, 105),
                  width=max(1, int(round(0.8 * s * camera_scale * ss))))
            r = 14.2 * s * camera_scale * ss
            box = [int(round(cx * ss - r)), int(round(cy * ss - r)),
                   int(round(cx * ss + r)), int(round(cy * ss + r))]
            d.arc(box, start=25, end=155, fill=(0, 0, 0, 135),
                  width=max(1, int(round(0.8 * s * camera_scale * ss))))

            detail = detail.reduce(ss)
            detail.putalpha(detail.getchannel("A").point(
                lambda v: int(v * camera_alpha)))
            out = Image.alpha_composite(out, detail)

        # 紧凑内容：左侧小图标 + 居中文字 + 右侧绿点
        if ca > 0.01:
            layer = Image.new("RGBA", (CW, CH), (255, 255, 255, 0))
            ic = self.icon_small
            layer.paste(ic, (int(x0 + 12 * s), int(cy - ic.height / 2.0)), ic)
            d = ImageDraw.Draw(layer)
            dot_r = 4.5 * s
            dx = x0 + w - 19 * s
            label_left = x0 + 12 * s + ic.width + 8 * s
            label_right = dx - dot_r - 8 * s
            self._text(
                d, ((label_left + label_right) / 2.0, cy),
                source_label or "有新消息待查看",
                self.f_compact, (190, 190, 198, 255), anchor="mm",
            )
            if pending:
                d.ellipse([dx - dot_r, cy - dot_r, dx + dot_r, cy + dot_r],
                          fill=(46, 204, 113, 255))
            out = self._blend(out, layer, ca, (1 - ca) * 5 * s, mask)

        # 展开内容：大图标 + 标题 + 副标题
        if ea > 0.01:
            layer = Image.new("RGBA", (CW, CH), (255, 255, 255, 0))
            ic = self.icon_big
            lx = x0 + 14 * s
            layer.paste(ic, (int(lx), int(cy - ic.height / 2.0)), ic)
            d = ImageDraw.Draw(layer)
            tx = lx + ic.width + 12 * s
            self._text(d, (tx, cy - 10 * s), "微信", self.f_title, (255, 255, 255, 255))
            subtitle = (f"{source_label} · 点击打开" if source_label
                        else "有新提醒 · 点击打开")
            self._text(d, (tx, cy + 11 * s), subtitle, self.f_sub, (152, 152, 160, 255))
            r = 4.5 * s
            dx = x0 + w - 24 * s
            d.ellipse([dx - r, cy - r, dx + r, cy + r], fill=(46, 204, 113, 255))
            out = self._blend(out, layer, ea, (1 - ea) * 6 * s, mask)
        return out

    @staticmethod
    def to_bgra(img):
        """RGBA -> 预乘 alpha 的 BGRA 字节（UpdateLayeredWindow 需要）。"""
        r, g, b, a = img.convert("RGBa").split()
        return Image.merge("RGBA", (b, g, r, a)).tobytes()


class LayeredSurface:
    """把 BGRA 位图用 UpdateLayeredWindow 贴到一个 tk 顶层窗口上，获得逐像素透明。"""

    def __init__(self, hwnd, width, height):
        u = _u
        g = ctypes.WinDLL("gdi32", use_last_error=True)
        self.u, self.g = u, g
        self.hwnd, self.w, self.h = hwnd, width, height

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

        bmi = BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.bmiHeader.biWidth = width
        bmi.bmiHeader.biHeight = -height  # 负数 = 自上而下，与 Pillow 行序一致
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32
        bmi.bmiHeader.biCompression = 0  # BI_RGB
        self.hdc = g.CreateCompatibleDC(None)
        bits = ctypes.c_void_p()
        self.bitmap = g.CreateDIBSection(self.hdc, ctypes.byref(bmi), 0,
                                         ctypes.byref(bits), None, 0)
        if not self.bitmap or not bits.value:
            raise ctypes.WinError(ctypes.get_last_error())
        self.bits = bits.value
        self.old = g.SelectObject(self.hdc, self.bitmap)
        self._blend = BLENDFUNCTION(0, 0, 255, 1)  # AC_SRC_OVER, AC_SRC_ALPHA
        self._first = True

    def update(self, data, x, y):
        ctypes.memmove(self.bits, data, self.w * self.h * 4)
        pt_dst = wintypes.POINT(int(x), int(y))
        size = wintypes.SIZE(self.w, self.h)
        pt_src = wintypes.POINT(0, 0)
        ok = self.u.UpdateLayeredWindow(
            self.hwnd, None, ctypes.byref(pt_dst), ctypes.byref(size), self.hdc,
            ctypes.byref(pt_src), 0, ctypes.byref(self._blend), 2)  # ULW_ALPHA
        if not ok and self._first:
            raise ctypes.WinError(ctypes.get_last_error())
        self._first = False

    def close(self):
        try:
            self.g.SelectObject(self.hdc, self.old)
            self.g.DeleteObject(self.bitmap)
            self.g.DeleteDC(self.hdc)
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

    def __init__(self, events, scale=None, hide_idle=False):
        import tkinter as tk
        self.tk = tk
        self.events = events
        self.hide_idle = hide_idle

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
        self.renderer = IslandRenderer(S)
        CW, CH = self.renderer.CW, self.renderer.CH
        self.sw = self.root.winfo_screenwidth()

        # 位置：xspr = 胶囊中心 x，yspr = 胶囊顶部 y（均为屏幕像素）；优先使用上次保存的位置
        saved = load_position()
        cx, ty = self._clamp_pos(*saved) if saved else self._default_pos()
        self.xspr = Spring(cx)
        self.yspr = Spring(ty)
        self.press = None
        self.dragging = False

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
        self.state = "idle"        # idle / compact / expanded
        self.pending = False
        self.pending_windows = {}   # 主窗口 HWND -> PID；负数表示未解析主窗；0 表示手动提醒
        self.source_label = ""
        self.last_opened_hwnd = None
        self.hover = False
        self.wspr = Spring(S * self.W_IDLE)
        self.hspr = Spring(S * self.H_IDLE)
        self.ea = 0.0
        self.ca = 0.0
        self.job = None
        self.last = time.perf_counter()
        self.collapse_job = None
        self.visible = True

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="恢复到顶部", command=self._reset_position)
        self.menu.add_command(label="模拟一次提醒", command=self._on_flash)
        self.menu.add_separator()
        self.menu.add_command(label="退出", command=self.quit)
        self.root.bind("<ButtonPress-1>", self._on_press)
        self.root.bind("<B1-Motion>", self._on_motion)
        self.root.bind("<ButtonRelease-1>", self._on_release)
        self.root.bind("<Button-3>", self._on_right_click)
        self.root.bind("<Enter>", self._on_enter)
        self.root.bind("<Leave>", self._on_leave)

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

    # -- 位置
    def _default_pos(self):
        # 保持胶囊本体原有的顶部留白；renderer.top 现在表示画布内边距。
        return self.sw / 2.0, 10.0 * self.s

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
        img = self.renderer.render(
            self.wspr.x, self.hspr.x, self.ea, self.ca, self.pending,
            source_label=self.source_label,
        )
        x = int(round(self.xspr.x - self.renderer.CW / 2.0))
        y = int(round(self.yspr.x - self.renderer.top))
        self.surface.update(self.renderer.to_bgra(img), x, y)

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
        dt = t0 - self.last
        self.last = t0
        S = self.s
        for spring in (self.wspr, self.hspr, self.xspr, self.yspr):
            spring.step(dt)

        # 内容透明度：展开内容在宽度长到一半后才淡入；紧凑内容在收缩后才出现
        e = _clamp((self.wspr.x - S * self.W_COMPACT) / (S * (self.W_EXP - self.W_COMPACT)))
        ea_t = 1.0 if (self.state == "expanded" and e > 0.5) else 0.0
        ca_t = 1.0 if (self.state == "compact" and e < 0.35) else 0.0
        for name, target in (("ea", ea_t), ("ca", ca_t)):
            cur = getattr(self, name)
            rate = 14.0 if target > cur else 24.0
            cur += (target - cur) * (-math.expm1(-dt * rate))
            if abs(cur - target) < 0.01:
                cur = target
            setattr(self, name, cur)

        settled = (all(sp.at_rest for sp in (self.wspr, self.hspr, self.xspr, self.yspr))
                   and self.ea in (0.0, 1.0) and self.ca in (0.0, 1.0))
        if settled:
            for spring in (self.wspr, self.hspr, self.xspr, self.yspr):
                spring.snap()
        self._push()
        if settled:
            self.job = None
            if self.hide_idle and self.state == "idle":
                self._set_visible(False)
        else:
            now = time.perf_counter()
            while self.next_frame <= now:
                # 渲染偶尔超时后跳过错过的帧，避免连续补帧造成卡顿。
                self.next_frame += self.FRAME_INTERVAL
            delay = max(1, int((self.next_frame - now) * 1000.0 + 0.5))
            self.next_frame += self.FRAME_INTERVAL
            self.job = self.root.after(delay, self._tick)

    def _go(self, state):
        self.state = state
        S = self.s
        if state == "expanded":      # 弹出：偏 Q 弹（欠阻尼，有过冲）
            w, h, k, c = self.W_EXP, self.H_EXP, 420.0, 23.0
        elif state == "compact":     # 收回到紧凑：基本无过冲
            w, h, k, c = self.W_COMPACT, self.H_COMPACT, 400.0, 34.0
        else:                        # 回到空闲
            w, h, k, c = self.W_IDLE, self.H_IDLE, 400.0, 34.0
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
        self.hover = False
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
        if self.pending:
            self._go("compact")
            return
        self._go("idle")

    # -- 交互：悬停 / 点击 / 拖动
    def _on_enter(self, _e):
        if self.dragging:
            return
        if self.pending and self.state == "compact":
            self.hover = True
            self._cancel_collapse()
            self._go("expanded")

    def _on_leave(self, _e):
        if self.dragging:
            return
        if self.hover and self.state == "expanded":
            self._schedule_collapse(500)

    def _on_press(self, e):
        self.press = (e.x_root, e.y_root, self.xspr.x, self.yspr.x)
        self.dragging = False

    def _on_motion(self, e):
        if self.press is None:
            return
        px, py, ox, oy = self.press
        dx, dy = e.x_root - px, e.y_root - py
        if not self.dragging and max(abs(dx), abs(dy)) > self.DRAG_THRESHOLD * self.s:
            self.dragging = True
        if self.dragging:
            cx, ty = self._clamp_pos(ox + dx, oy + dy)
            for spring, value in ((self.xspr, cx), (self.yspr, ty)):  # 拖动时直接跟手，不走弹簧
                spring.x = spring.target = value
                spring.v = 0.0
            self._push()

    def _on_release(self, _e):
        if self.press is None:
            return
        was_drag = self.dragging
        self.press = None
        self.dragging = False
        if was_drag:
            save_position((self.xspr.x, self.yspr.x))
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
    W_PREVIEW = 250
    TOP = 8
    PREVIEW_MS = 5000

    BG = "#15171a"
    FG = "#e8eaed"
    FG_DIM = "#8a9099"
    GREEN = "#2ecc71"
    GREY = "#555b63"
    FONT = ("Microsoft YaHei UI", 10)

    def __init__(self, events):
        import tkinter as tk
        self.tk = tk
        self.events = events

        self.root = tk.Tk()
        self.root.title("WeChat Capsule")
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        self.root.configure(bg=self.KEY)
        try:
            self.root.attributes("-transparentcolor", self.KEY)
        except tk.TclError:
            pass

        self.sw = self.root.winfo_screenwidth()
        self.cx = self.sw // 2
        self.ty = self.TOP
        self._press = None
        self._dragging = False
        self.canvas = tk.Canvas(self.root, bg=self.KEY, highlightthickness=0,
                                bd=0, height=self.H)
        self.canvas.pack(fill="both", expand=True)

        self.pending = False
        self.pending_windows = {}   # 主窗口 HWND -> PID；负数表示未解析主窗；0 表示手动提醒
        self.source_label = ""
        self.last_opened_hwnd = None
        self.w = float(self.W_IDLE)
        self.target = float(self.W_IDLE)
        self.anim = None
        self.anim_last = time.perf_counter()
        self.collapse_job = None

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="恢复到顶部", command=self._reset_position)
        self.menu.add_command(label="模拟一次提醒", command=lambda: self._on_flash())
        self.menu.add_separator()
        self.menu.add_command(label="退出", command=self.quit)

        self.canvas.bind("<ButtonPress-1>", self._on_press)
        self.canvas.bind("<B1-Motion>", self._on_motion)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)
        self.canvas.bind("<Button-3>", self._on_right_click)

        self._place()
        self._draw()
        self.root.after(80, self._poll)
        self.root.after(2000, self._keep_on_top)

    # -- 绘制
    def _rounded(self, x1, y1, x2, y2, r, **kw):
        pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
               x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
        return self.canvas.create_polygon(pts, smooth=True, **kw)

    def _place(self):
        w = max(int(self.w), 20)
        x = int(self.cx - w / 2)
        self.root.geometry(f"{w}x{self.H}+{x}+{self.ty}")

    def _draw(self):
        c = self.canvas
        c.delete("all")
        w = max(int(self.w), 20)
        h = self.H
        self._rounded(0, 0, w, h, h // 2, fill=self.BG, outline="")
        dot_color = self.GREEN if self.pending else self.GREY
        cy = h // 2
        c.create_oval(14, cy - 5, 24, cy + 5, fill=dot_color, outline="")
        if self.w > 210:
            subtitle = (f"{self.source_label} · 点击打开" if self.source_label
                        else "微信有新提醒 · 点击打开")
            c.create_text(34, cy, anchor="w", fill=self.FG, font=self.FONT,
                          text=subtitle)
        elif self.w > 120:
            c.create_text(34, cy, anchor="w",
                          fill=self.FG if self.pending else self.FG_DIM,
                          font=self.FONT,
                          text=self.source_label or "有新消息待查看")
        elif self.w > 70:
            c.create_text(34, cy, anchor="w",
                          fill=self.FG if self.pending else self.FG_DIM,
                          font=self.FONT, text="微信")

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
        if abs(diff) < 0.5:
            self.w = self.target
        else:
            self.w += diff * (-math.expm1(-20.0 * dt))
            self.anim = self.root.after(16, self._animate)
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

    def _collapse(self):
        self.collapse_job = None
        self._set_target(self.W_COMPACT if self.pending else self.W_IDLE)

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
        self._set_target(self.W_COMPACT if self.pending else self.W_IDLE)
        self._draw()

    # -- 交互
    def _on_press(self, e):
        self._press = (e.x_root, e.y_root, self.cx, self.ty)
        self._dragging = False

    def _on_motion(self, e):
        if self._press is None:
            return
        px, py, ox, oy = self._press
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

    def _on_click(self, _event):
        opened, hwnd = open_wechat_target(
            self.pending_windows, self.last_opened_hwnd)
        if hwnd is not None:
            self.last_opened_hwnd = hwnd
        if not opened:
            self._toast_error()

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
    parser = argparse.ArgumentParser(description="微信提醒胶囊（仅监听任务栏闪烁）")
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
    listener = ShellHookListener(
        names, lambda kind, payload: events.put((kind, payload)), tray_enabled=True
    )
    listener.start()
    listener.ready.wait(5)
    if listener.error:
        print("注册 Shell Hook 或托盘图标失败：", listener.error)
        return 1

    app = None
    if HAVE_PIL and not args.tk:
        try:
            app = LayeredCapsule(events, scale=args.scale, hide_idle=args.hide_idle)
        except Exception:  # noqa: BLE001
            print("Pillow 分层窗口初始化失败，退回 tkinter 界面：")
            traceback.print_exc()
    elif not HAVE_PIL:
        print("提示：安装 Pillow 可获得更接近 iOS 灵动岛的效果：pip install pillow")
    if app is None:
        app = TkCapsule(events)
    interrupted = False
    try:
        app.run()
    except KeyboardInterrupt:
        # 控制台 Ctrl+C 是正常退出操作，不应把它作为未处理异常打印 traceback。
        interrupted = True
    finally:
        listener.stop()
        if interrupted:
            # mainloop 被打断时也销毁窗口和分层位图资源。
            try:
                app.quit()
            except Exception:  # noqa: BLE001
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
