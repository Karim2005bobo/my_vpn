"""Графический клиент MiniVPN (Tkinter): профили, подключение, статус, трафик, журнал.

    python -m minivpn.gui
"""
import logging
import os
import queue
import shutil
import subprocess
import sys
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .client import CONNECTED, CONNECTING, DISCONNECTED, DISCONNECTING, ERROR, RECONNECTING, VPNClient
from .netconfig import is_admin
from .profiles import ProfileStore

log = logging.getLogger("minivpn")

STATE_VIEW = {
    DISCONNECTED: ("Отключено", "#9aa3ad", "Подключить"),
    CONNECTING: ("Подключение…", "#f0ad2c", "Отмена"),
    CONNECTED: ("Подключено", "#2eb872", "Отключить"),
    RECONNECTING: ("Восстановление связи…", "#f0ad2c", "Отключить"),
    DISCONNECTING: ("Отключение…", "#f0ad2c", "Подождите"),
    ERROR: ("Ошибка", "#e05555", "Подключить"),
}

BG = "#f4f6f9"
CARD = "#ffffff"
FG = "#1f2933"
MUTED = "#6b7785"
ACCENT = "#3b6ff5"


def fmt_bytes(n):
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


def fmt_duration(sec):
    sec = int(sec)
    return f"{sec // 3600:02d}:{sec % 3600 // 60:02d}:{sec % 60:02d}"


class QueueHandler(logging.Handler):
    def __init__(self, q):
        super().__init__()
        self.q = q

    def emit(self, record):
        self.q.put(self.format(record))


def restart_elevated():
    """Перезапуск GUI с правами администратора (UAC в Windows, pkexec/sudo в Linux)."""
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if sys.platform == "win32":
        import ctypes
        params = "-m minivpn.gui"
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, pkg_parent, 1)
        return rc > 32
    env = [f"PYTHONPATH={pkg_parent}", f"PKEXEC_UID={os.getuid()}", f"MINIVPN_CONFIG_DIR={ProfileStore().dir}"]
    for var in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR"):
        if os.environ.get(var):
            env.append(f"{var}={os.environ[var]}")
    if shutil.which("pkexec"):
        subprocess.Popen(["pkexec", "env", *env, sys.executable, "-m", "minivpn.gui"], cwd=pkg_parent)
        return True
    return False


class App:
    def __init__(self, root):
        self.root = root
        self.store = ProfileStore()
        self.profiles = self.store.load()
        self.settings = self.store.settings()
        self.client = None
        self.client_profile = None
        self.log_queue = queue.Queue()
        self._prev = (0, 0, time.monotonic())
        self._speed = (0.0, 0.0)
        self._closing = False
        self.admin = is_admin()

        handler = QueueHandler(self.log_queue)
        handler.setFormatter(logging.Formatter("%(asctime)s  %(message)s", "%H:%M:%S"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)

        root.title("MiniVPN")
        root.geometry("820x560")
        root.minsize(720, 500)
        root.configure(bg=BG)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._style()
        self._build()
        self._refresh_profiles()
        sel = self.settings.get("last_profile")
        names = [p["name"] for p in self.profiles]
        if sel in names:
            self.listbox.selection_set(names.index(sel))
        elif names:
            self.listbox.selection_set(0)
        self._on_select()
        self._render_state(DISCONNECTED, None)
        self.root.after(200, self._poll)
        log.info("MiniVPN %s", __version__)
        if not self.admin:
            log.info("нет прав администратора — для подключения нажмите «Подключить», "
                     "приложение предложит перезапуск с правами")

    # --- интерфейс

    def _style(self):
        st = ttk.Style(self.root)
        if "clam" in st.theme_names():
            st.theme_use("clam")
        st.configure(".", background=BG, foreground=FG, font=("Segoe UI", 10))
        st.configure("Card.TFrame", background=CARD)
        st.configure("Card.TLabel", background=CARD, foreground=FG)
        st.configure("Muted.TLabel", background=CARD, foreground=MUTED, font=("Segoe UI", 9))
        st.configure("Value.TLabel", background=CARD, foreground=FG, font=("Segoe UI", 10, "bold"))
        st.configure("Title.TLabel", background=BG, foreground=FG, font=("Segoe UI", 11, "bold"))
        st.configure("State.TLabel", background=CARD, foreground=FG, font=("Segoe UI", 16, "bold"))
        st.configure("Card.TCheckbutton", background=CARD, foreground=FG)
        st.map("Card.TCheckbutton", background=[("active", CARD)])
        st.configure("Big.TButton", font=("Segoe UI", 12, "bold"), padding=(24, 10), foreground="#ffffff",
                     background=ACCENT, borderwidth=0)
        st.map("Big.TButton", background=[("disabled", "#b8c4d6"), ("active", "#2f5cd6")])
        st.configure("TButton", padding=(10, 5))

    def _build(self):
        root = self.root
        main = ttk.Frame(root, padding=14)
        main.pack(fill="both", expand=True)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(1, weight=1)

        # профили
        left = ttk.Frame(main)
        left.grid(row=0, column=0, rowspan=2, sticky="nsw", padx=(0, 14))
        ttk.Label(left, text="Профили", style="Title.TLabel").pack(anchor="w", pady=(0, 6))
        box = tk.Frame(left, bg=CARD, highlightthickness=1, highlightbackground="#dde3ea")
        box.pack(fill="both", expand=True)
        self.listbox = tk.Listbox(box, width=26, activestyle="none", borderwidth=0, highlightthickness=0,
                                  font=("Segoe UI", 10), selectbackground=ACCENT, selectforeground="#ffffff",
                                  bg=CARD, fg=FG, exportselection=False)
        self.listbox.pack(fill="both", expand=True, padx=4, pady=4)
        self.listbox.bind("<<ListboxSelect>>", lambda e: self._on_select())
        self.listbox.bind("<Double-Button-1>", lambda e: self.toggle())
        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=(8, 0))
        ttk.Button(btns, text="＋ Добавить", command=self.add_dialog).pack(side="left", expand=True, fill="x")
        self.btn_remove = ttk.Button(btns, text="Удалить", command=self.remove_profile)
        self.btn_remove.pack(side="left", expand=True, fill="x", padx=(6, 0))

        # статус
        card = ttk.Frame(main, style="Card.TFrame", padding=18)
        card.grid(row=0, column=1, sticky="nsew")
        card.columnconfigure(1, weight=1)
        self.canvas = tk.Canvas(card, width=76, height=76, bg=CARD, highlightthickness=0)
        self.canvas.grid(row=0, column=0, rowspan=2, padx=(0, 16))
        self.ring = self.canvas.create_oval(4, 4, 72, 72, width=6, outline="#9aa3ad")
        self.dot = self.canvas.create_oval(24, 24, 52, 52, width=0, fill="#9aa3ad")
        self.lbl_state = ttk.Label(card, text="Отключено", style="State.TLabel")
        self.lbl_state.grid(row=0, column=1, sticky="sw")
        self.lbl_sub = ttk.Label(card, text="", style="Muted.TLabel", wraplength=400)
        self.lbl_sub.grid(row=1, column=1, columnspan=2, sticky="nw", pady=(4, 0))
        self.btn_connect = ttk.Button(card, text="Подключить", style="Big.TButton", command=self.toggle)
        self.btn_connect.grid(row=0, column=2, sticky="e")

        info = ttk.Frame(card, style="Card.TFrame")
        info.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(18, 0))
        self.values = {}
        fields = [("server", "Сервер"), ("ip", "Адрес в VPN"), ("uptime", "Время подключения"),
                  ("handshake", "Обмен ключами"), ("down", "Принято"), ("up", "Отправлено")]
        for i, (key, title) in enumerate(fields):
            r, c = divmod(i, 2)
            cell = ttk.Frame(info, style="Card.TFrame")
            cell.grid(row=r, column=c, sticky="w", padx=(0, 40), pady=4)
            ttk.Label(cell, text=title, style="Muted.TLabel").pack(anchor="w")
            self.values[key] = ttk.Label(cell, text="—", style="Value.TLabel")
            self.values[key].pack(anchor="w")
        info.columnconfigure(0, weight=1)
        info.columnconfigure(1, weight=1)

        opts = ttk.Frame(card, style="Card.TFrame")
        opts.grid(row=3, column=0, columnspan=3, sticky="w", pady=(14, 0))
        self.var_full = tk.BooleanVar(value=self.settings.get("full_tunnel", True))
        self.var_dns = tk.BooleanVar(value=self.settings.get("set_dns", True))
        self.chk_full = ttk.Checkbutton(opts, text="Весь трафик через VPN", variable=self.var_full,
                                        style="Card.TCheckbutton", command=self._save_settings)
        self.chk_full.pack(side="left")
        self.chk_dns = ttk.Checkbutton(opts, text="DNS сервера VPN", variable=self.var_dns,
                                       style="Card.TCheckbutton", command=self._save_settings)
        self.chk_dns.pack(side="left", padx=(18, 0))

        # журнал
        logf = ttk.Frame(main)
        logf.grid(row=1, column=1, sticky="nsew", pady=(14, 0))
        ttk.Label(logf, text="Журнал", style="Title.TLabel").pack(anchor="w", pady=(0, 6))
        box = tk.Frame(logf, bg=CARD, highlightthickness=1, highlightbackground="#dde3ea")
        box.pack(fill="both", expand=True)
        self.log_text = tk.Text(box, height=8, wrap="word", borderwidth=0, highlightthickness=0, bg=CARD,
                                fg=FG, font=("Consolas", 9), state="disabled")
        sb = ttk.Scrollbar(box, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)

    # --- профили

    def _refresh_profiles(self):
        self.listbox.delete(0, "end")
        for p in self.profiles:
            self.listbox.insert("end", f"  {p['name']}")

    def _selected(self):
        sel = self.listbox.curselection()
        return self.profiles[sel[0]] if sel else None

    def _on_select(self):
        p = self._selected()
        if not self.client:
            self.values["server"].configure(text=f"{p['host']}:{p['port']}" if p else "—")
        self._update_controls()

    def _save_settings(self):
        p = self._selected()
        self.settings.update(full_tunnel=self.var_full.get(), set_dns=self.var_dns.get(),
                             last_profile=p["name"] if p else None)
        try:
            self.store.save(self.profiles, self.settings)
        except OSError as e:
            log.error("не удалось сохранить настройки: %s", e)

    def add_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Добавить профиль")
        dlg.configure(bg=BG)
        dlg.transient(self.root)
        dlg.grab_set()
        frm = ttk.Frame(dlg, padding=14)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Вставьте строку подключения minivpn://… (её выдаёт команда add-client на сервере)\n"
                            "или загрузите файл .mvpn:").pack(anchor="w")
        text = tk.Text(frm, width=70, height=6, wrap="char", font=("Consolas", 9))
        text.pack(fill="both", expand=True, pady=8)
        text.focus_set()
        try:
            clip = self.root.clipboard_get()
            if clip.strip().startswith("minivpn://"):
                text.insert("1.0", clip.strip())
        except tk.TclError:
            pass

        def from_file():
            path = filedialog.askopenfilename(parent=dlg, title="Профиль MiniVPN",
                                              filetypes=[("Профиль MiniVPN", "*.mvpn"), ("Все файлы", "*.*")])
            if path:
                with open(path, encoding="utf-8") as f:
                    text.delete("1.0", "end")
                    text.insert("1.0", f.read().strip())

        def ok():
            try:
                prof = self.store.add(text.get("1.0", "end"))
            except (ValueError, KeyError) as e:
                messagebox.showerror("MiniVPN", f"Не удалось прочитать профиль:\n{e}", parent=dlg)
                return
            except OSError as e:
                messagebox.showerror("MiniVPN", f"Не удалось сохранить профиль:\n{e}", parent=dlg)
                return
            self.profiles = self.store.load()
            self._refresh_profiles()
            idx = [p["name"] for p in self.profiles].index(prof["name"])
            self.listbox.selection_clear(0, "end")
            self.listbox.selection_set(idx)
            self._on_select()
            log.info("профиль «%s» добавлен (%s:%s)", prof["name"], prof["host"], prof["port"])
            dlg.destroy()

        row = ttk.Frame(frm)
        row.pack(fill="x")
        ttk.Button(row, text="Из файла…", command=from_file).pack(side="left")
        ttk.Button(row, text="Отмена", command=dlg.destroy).pack(side="right")
        ttk.Button(row, text="Добавить", command=ok).pack(side="right", padx=6)
        dlg.bind("<Escape>", lambda e: dlg.destroy())

    def remove_profile(self):
        p = self._selected()
        if not p or (self.client and self.client_profile is p):
            return
        if not messagebox.askyesno("MiniVPN", f"Удалить профиль «{p['name']}»?"):
            return
        self.profiles.remove(p)
        self._save_settings()
        self._refresh_profiles()
        if self.profiles:
            self.listbox.selection_set(0)
        self._on_select()

    # --- подключение

    def toggle(self):
        if self.client and self.client.running:
            if self.client.state != DISCONNECTING:
                self.client.stop(wait=False)
            return
        p = self._selected()
        if not p:
            messagebox.showinfo("MiniVPN", "Сначала добавьте профиль подключения.")
            return
        if not self.admin:
            if messagebox.askyesno("MiniVPN", "Для создания VPN-интерфейса нужны права администратора.\n"
                                              "Перезапустить MiniVPN с правами администратора?"):
                if restart_elevated():
                    self.root.destroy()
                else:
                    messagebox.showerror("MiniVPN", "Запустите вручную: sudo python3 -m minivpn.gui")
            return
        self._save_settings()
        self.client_profile = p
        self._prev = (0, 0, time.monotonic())
        self.client = VPNClient(p, full_tunnel=self.var_full.get(), set_dns=self.var_dns.get())
        self.values["server"].configure(text=f"{p['host']}:{p['port']}")
        self.client.start()

    def _render_state(self, state, error):
        title, color, button = STATE_VIEW[state]
        self.lbl_state.configure(text=title)
        self.canvas.itemconfigure(self.ring, outline=color)
        self.canvas.itemconfigure(self.dot, fill=color)
        self.btn_connect.configure(text=button)
        if state == ERROR:
            self.lbl_sub.configure(text=error or "")
        elif state == CONNECTED and self.client:
            mode = "весь трафик через VPN" if self.client.full_tunnel else "только сеть VPN"
            self.lbl_sub.configure(text=f"{self.client_profile['name']} · {mode}")
        elif state in (CONNECTING, RECONNECTING) and self.client_profile:
            self.lbl_sub.configure(text=f"{self.client_profile['host']}:{self.client_profile['port']}")
        else:
            self.lbl_sub.configure(text="Выберите профиль и нажмите «Подключить»" if state == DISCONNECTED else "")
        self._update_controls()

    def _update_controls(self):
        busy = bool(self.client and self.client.running)
        for w in (self.chk_full, self.chk_dns, self.btn_remove):
            w.state(["disabled"] if busy else ["!disabled"])
        if busy and self.client.state == DISCONNECTING:
            self.btn_connect.state(["disabled"])
        elif busy or self._selected():
            self.btn_connect.state(["!disabled"])
        else:
            self.btn_connect.state(["disabled"])

    def _poll(self):
        while True:
            try:
                line = self.log_queue.get_nowait()
            except queue.Empty:
                break
            self.log_text.configure(state="normal")
            self.log_text.insert("end", line + "\n")
            if int(self.log_text.index("end-1c").split(".")[0]) > 1000:
                self.log_text.delete("1.0", "200.0")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

        c = self.client
        if c:
            self._render_state(c.state, c.error)
            now = time.monotonic()
            prx, ptx, pt = self._prev
            if now - pt >= 1:
                self._speed = ((c.rx - prx) / (now - pt), (c.tx - ptx) / (now - pt))
                self._prev = (c.rx, c.tx, now)
            v = self.values
            v["ip"].configure(text=c.config["ip"] if c.config and c.state != DISCONNECTED else "—")
            v["uptime"].configure(text=fmt_duration(time.time() - c.connected_since) if c.connected_since else "—")
            v["handshake"].configure(
                text=f"{int(time.time() - c.last_handshake)} с назад" if c.last_handshake and c.running else "—")
            v["down"].configure(text=f"{fmt_bytes(c.rx)}  ({fmt_bytes(self._speed[0])}/с)")
            v["up"].configure(text=f"{fmt_bytes(c.tx)}  ({fmt_bytes(self._speed[1])}/с)")
            if not c.running and c.state in (DISCONNECTED, ERROR):
                self.client = None
                self._speed = (0.0, 0.0)
                for key in ("ip", "uptime", "handshake", "down", "up"):
                    self.values[key].configure(text="—")
                self._update_controls()
        if self._closing and not (self.client and self.client.running):
            self.root.destroy()
            return
        self.root.after(250, self._poll)

    def on_close(self):
        if self.client and self.client.running:
            self._closing = True
            self.client.stop(wait=False)
            self.btn_connect.state(["disabled"])
        else:
            self.root.destroy()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
