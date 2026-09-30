"""Виртуальный сетевой адаптер (TUN): Linux — /dev/net/tun, Windows — драйвер Wintun (wintun.dll).

Общий интерфейс: name, read(timeout) -> bytes | None, write(packet), close().
"""
import os
import sys


def open_tun(name="minivpn0"):
    if sys.platform.startswith("linux"):
        return LinuxTun(name)
    if sys.platform == "win32":
        return WintunTun(name)
    raise OSError(f"платформа {sys.platform} не поддерживается (нужны Linux или Windows)")


class LinuxTun:
    TUNSETIFF = 0x400454CA
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    def __init__(self, name):
        import fcntl
        import struct
        self.fd = os.open("/dev/net/tun", os.O_RDWR)
        try:
            ifr = struct.pack("16sH", name.encode()[:15], self.IFF_TUN | self.IFF_NO_PI)
            res = fcntl.ioctl(self.fd, self.TUNSETIFF, ifr)
        except OSError:
            os.close(self.fd)
            raise
        self.name = res[:16].rstrip(b"\x00").decode()
        os.set_blocking(self.fd, False)

    def fileno(self):
        return self.fd

    def read(self, timeout=None):
        import select
        if timeout is not None and not select.select([self.fd], [], [], timeout)[0]:
            return None
        try:
            return os.read(self.fd, 65535)
        except BlockingIOError:
            return None

    def write(self, packet):
        try:
            os.write(self.fd, packet)
        except (BlockingIOError, OSError):
            pass  # очередь адаптера переполнена или он опущен — пакет теряется, как в обычной сети

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def find_wintun():
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [os.environ.get("MINIVPN_WINTUN", ""),
                  os.path.join(here, "wintun.dll"),
                  os.path.join(os.path.dirname(here), "wintun.dll"),
                  os.path.join(os.path.dirname(sys.executable), "wintun.dll"),
                  os.path.join(os.getcwd(), "wintun.dll")]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    raise FileNotFoundError(
        "не найден wintun.dll: скачайте https://www.wintun.net, возьмите bin/amd64/wintun.dll "
        "и положите рядом с папкой minivpn (или укажите путь в переменной MINIVPN_WINTUN)")


class WintunTun:
    RING_CAPACITY = 0x400000
    ERROR_NO_MORE_ITEMS = 259
    ERROR_HANDLE_EOF = 38
    WAIT_OBJECT_0 = 0

    def __init__(self, name):
        import ctypes
        from ctypes import wintypes
        self._ct = ctypes
        dll = ctypes.WinDLL(find_wintun(), use_last_error=True)
        self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        H, P = wintypes.HANDLE, ctypes.POINTER(ctypes.c_ubyte)
        sig = {
            "WintunCreateAdapter": (H, [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]),
            "WintunCloseAdapter": (None, [H]),
            "WintunStartSession": (H, [H, wintypes.DWORD]),
            "WintunEndSession": (None, [H]),
            "WintunGetReadWaitEvent": (H, [H]),
            "WintunReceivePacket": (P, [H, ctypes.POINTER(wintypes.DWORD)]),
            "WintunReleaseReceivePacket": (None, [H, P]),
            "WintunAllocateSendPacket": (P, [H, wintypes.DWORD]),
            "WintunSendPacket": (None, [H, P]),
        }
        for fn, (res, args) in sig.items():
            f = getattr(dll, fn)
            f.restype, f.argtypes = res, args
        self._k32.WaitForSingleObject.restype = wintypes.DWORD
        self._k32.WaitForSingleObject.argtypes = [H, wintypes.DWORD]
        self.dll = dll
        self.adapter = dll.WintunCreateAdapter(name, "MiniVPN", None)
        if not self.adapter:
            raise OSError(ctypes.get_last_error(), "WintunCreateAdapter: нужны права администратора")
        self.session = dll.WintunStartSession(self.adapter, self.RING_CAPACITY)
        if not self.session:
            err = ctypes.get_last_error()
            dll.WintunCloseAdapter(self.adapter)
            raise OSError(err, "WintunStartSession")
        self.event = dll.WintunGetReadWaitEvent(self.session)
        self.name = name

    def read(self, timeout=None):
        ct = self._ct
        size = ct.c_ulong(0)
        while self.session:
            ptr = self.dll.WintunReceivePacket(self.session, ct.byref(size))
            if ptr:
                data = ct.string_at(ptr, size.value)
                self.dll.WintunReleaseReceivePacket(self.session, ptr)
                return data
            err = ct.get_last_error()
            if err != self.ERROR_NO_MORE_ITEMS:
                raise OSError(err, "WintunReceivePacket")
            ms = 0xFFFFFFFF if timeout is None else int(timeout * 1000)
            if self._k32.WaitForSingleObject(self.event, ms) != self.WAIT_OBJECT_0:
                return None
        return None

    def write(self, packet):
        if not self.session:
            return
        ptr = self.dll.WintunAllocateSendPacket(self.session, len(packet))
        if not ptr:
            return  # кольцо переполнено — пакет теряется
        self._ct.memmove(ptr, packet, len(packet))
        self.dll.WintunSendPacket(self.session, ptr)

    def close(self):
        if self.session:
            s, self.session = self.session, None
            self.dll.WintunEndSession(s)
        if self.adapter:
            a, self.adapter = self.adapter, None
            self.dll.WintunCloseAdapter(a)
