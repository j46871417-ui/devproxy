"""Native Windows tray on the Tk thread, with Explorer restart recovery."""
import ctypes as C
from ctypes import wintypes as W
import hashlib
import os


class GUID(C.Structure):
    _fields_ = [("Data1", W.DWORD), ("Data2", W.WORD), ("Data3", W.WORD), ("Data4", C.c_ubyte * 8)]


class NOTIFYICONDATA(C.Structure):
    _fields_ = [("cbSize", W.DWORD), ("hWnd", W.HWND), ("uID", W.UINT),
                ("uFlags", W.UINT), ("uCallbackMessage", W.UINT), ("hIcon", W.HANDLE),
                ("szTip", W.WCHAR * 128), ("dwState", W.DWORD), ("dwStateMask", W.DWORD),
                ("szInfo", W.WCHAR * 256), ("uVersion", W.UINT),
                ("szInfoTitle", W.WCHAR * 64), ("dwInfoFlags", W.DWORD),
                ("guidItem", GUID), ("hBalloonIcon", W.HANDLE)]


class SingleInstance:
    def __init__(self, identity):
        self.kernel = C.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateMutexW.argtypes = [C.c_void_p, W.BOOL, W.LPCWSTR]
        self.kernel.CreateMutexW.restype = W.HANDLE
        self.kernel.CloseHandle.argtypes = [W.HANDLE]
        digest = hashlib.sha256(os.path.abspath(identity).lower().encode()).hexdigest()[:24]
        self.handle = self.kernel.CreateMutexW(None, False, "Local\\DevProxy-" + digest)
        if not self.handle:
            raise C.WinError(C.get_last_error())
        self.acquired = C.get_last_error() != 183

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class WindowsTray:
    MESSAGE = 0x8000 + 42

    def __init__(self, root, events):
        self.events = events
        self.user = C.WinDLL("user32", use_last_error=True)
        self.shell = C.WinDLL("shell32", use_last_error=True)
        self.user.GetParent.argtypes = [W.HWND]
        self.user.GetParent.restype = W.HWND
        self.user.LoadIconW.argtypes = [W.HINSTANCE, C.c_void_p]
        self.user.LoadIconW.restype = W.HANDLE
        self.user.RegisterWindowMessageW.argtypes = [W.LPCWSTR]
        self.user.RegisterWindowMessageW.restype = W.UINT
        self.user.CreatePopupMenu.restype = W.HMENU
        self.user.AppendMenuW.argtypes = [W.HMENU, W.UINT, C.c_size_t, W.LPCWSTR]
        self.user.TrackPopupMenu.argtypes = [W.HMENU, W.UINT, C.c_int, C.c_int, C.c_int, W.HWND, C.c_void_p]
        self.user.TrackPopupMenu.restype = W.UINT
        self.user.DestroyMenu.argtypes = [W.HMENU]
        self.user.SetForegroundWindow.argtypes = [W.HWND]
        self.user.GetCursorPos.argtypes = [C.POINTER(W.POINT)]
        self.shell.Shell_NotifyIconW.argtypes = [W.DWORD, C.POINTER(NOTIFYICONDATA)]
        self.shell.Shell_NotifyIconW.restype = W.BOOL
        root.update_idletasks()
        self.hwnd = self.user.GetParent(root.winfo_id()) or root.winfo_id()
        self.taskbar_created = self.user.RegisterWindowMessageW("TaskbarCreated")
        self.proc_type = C.WINFUNCTYPE(C.c_ssize_t, W.HWND, W.UINT, W.WPARAM, W.LPARAM)
        self.callback = self.proc_type(self.window_proc)
        self.set_proc = self.user.SetWindowLongPtrW if C.sizeof(C.c_void_p) == 8 else self.user.SetWindowLongW
        self.set_proc.argtypes = [W.HWND, C.c_int, C.c_ssize_t]
        self.set_proc.restype = C.c_ssize_t
        self.user.CallWindowProcW.argtypes = [C.c_void_p, W.HWND, W.UINT, W.WPARAM, W.LPARAM]
        self.user.CallWindowProcW.restype = C.c_ssize_t
        self.previous = self.set_proc(self.hwnd, -4, C.cast(self.callback, C.c_void_p).value)
        if not self.previous:
            raise C.WinError(C.get_last_error())
        self.data = NOTIFYICONDATA()
        self.data.cbSize = C.sizeof(self.data)
        self.data.hWnd, self.data.uID = self.hwnd, 1
        self.data.uFlags = 1 | 2 | 4
        self.data.uCallbackMessage = self.MESSAGE
        self.data.hIcon = self.user.LoadIconW(None, C.c_void_p(32512))
        self.data.szTip = "DevProxy — фоновый прокси для приложений"
        self.closed = False
        self.available = bool(self.shell.Shell_NotifyIconW(0, C.byref(self.data)))
        root.bind("<Destroy>", lambda event: self.close() if event.widget is root else None, add="+")

    def window_proc(self, hwnd, message, wparam, lparam):
        try:
            if message == self.taskbar_created:
                self.available = bool(self.shell.Shell_NotifyIconW(0, C.byref(self.data)))
            elif message == self.MESSAGE:
                if lparam in (0x202, 0x203):
                    self.events.put(("tray", "show"))
                elif lparam == 0x205:
                    self.menu()
                return 0
        except Exception:
            self.events.put(("tray_error",))
        return self.user.CallWindowProcW(C.c_void_p(self.previous), hwnd, message, wparam, lparam)

    def menu(self):
        menu = self.user.CreatePopupMenu()
        try:
            for number, label in ((1, "Открыть DevProxy"), (2, "Запустить настроенные приложения"),
                                  (3, "Отключить постоянный режим"), (4, "Выход — остановить приложения")):
                self.user.AppendMenuW(menu, 0, number, label)
            point = W.POINT()
            self.user.GetCursorPos(C.byref(point))
            self.user.SetForegroundWindow(self.hwnd)
            number = self.user.TrackPopupMenu(menu, 0x100 | 0x2, point.x, point.y, 0, self.hwnd, None)
            action = {1: "show", 2: "launch", 3: "disable", 4: "exit"}.get(number)
            if action:
                self.events.put(("tray", action))
        finally:
            self.user.DestroyMenu(menu)

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.shell.Shell_NotifyIconW(2, C.byref(self.data))
        self.set_proc(self.hwnd, -4, self.previous)
