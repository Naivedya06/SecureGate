import atexit
import ctypes
from ctypes import wintypes
import json
import math
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import tkinter as tk
from PIL import Image, ImageDraw, ImageTk
import pystray

if sys.platform.startswith("win"):
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

AZURE_SERVER_IP = "YOUR_AZURE_VM_IP"
AZURE_SERVER_PORT = 8443
LOCAL_PROXY_HOST = "127.0.0.1"
LOCAL_PROXY_PORT = 8080
FW_RULE_NAME = "SecureGate_Block_QUIC_UDP443"

BASE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
SERVER_CERT_PATH = os.path.join(BASE_DIR, "server.crt")
SESSION_FILE = os.path.join(os.path.expanduser("~"), ".securegate_session.json")

GATE_ENABLED = False
ACTIVE_TOKEN = ""
ACTIVE_USER = ""
REQUEST_COUNT = 0
COUNT_LOCK = threading.Lock()

INTERNET_OPTION_REFRESH = 37
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_PER_CONNECTION_OPTION = 75
INTERNET_PER_CONN_FLAGS = 1
INTERNET_PER_CONN_PROXY_SERVER = 2
INTERNET_PER_CONN_PROXY_BYPASS = 3
PROXY_TYPE_DIRECT = 0x00000001
PROXY_TYPE_PROXY = 0x00000002

CONTINENT_POLYS = [
    [(-168, 65), (-140, 70), (-95, 72), (-75, 62), (-65, 45), (-80, 25), (-95, 18), (-105, 22), (-122, 38), (-135, 55)],
    [(-52, 60), (-42, 82), (-20, 81), (-22, 68), (-44, 60)],
    [(-78, 10), (-60, 8), (-35, -6), (-40, -22), (-56, -38), (-68, -54), (-74, -46), (-72, -18), (-81, -4)],
    [(-10, 36), (0, 44), (-5, 54), (10, 62), (28, 70), (42, 66), (40, 46), (26, 38), (12, 38)],
    [(-17, 15), (-5, 35), (12, 37), (32, 31), (42, 12), (50, 11), (40, -12), (32, -32), (18, -34), (12, -16), (8, 4), (-8, 5)],
    [(28, 42), (42, 66), (75, 73), (115, 72), (165, 65), (142, 46), (122, 38), (120, 22), (105, 10), (96, 18), (80, 8), (68, 24), (52, 26), (36, 34)],
    [(114, -22), (130, -12), (144, -14), (153, -28), (146, -38), (130, -33), (115, -34)],
]


def _point_in_poly(lon: float, lat: float, poly: list) -> bool:
    inside = False
    n = len(poly)
    j = n - 1
    for i in range(n):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if ((yi > lat) != (yj > lat)) and (lon < (xj - xi) * (lat - yi) / (yj - yi + 1e-9) + xi):
            inside = not inside
        j = i
    return inside


def _build_globe_point_cloud():
    land = []
    ocean = []
    for lat in range(-78, 81, 3):
        phi = math.radians(lat)
        for lon in range(-180, 180, 3):
            lam = math.radians(lon)
            if any(_point_in_poly(lon, lat, p) for p in CONTINENT_POLYS):
                land.append((phi, lam))
            elif lat % 12 == 0 and lon % 12 == 0:
                ocean.append((phi, lam))
    return land, ocean


LAND_POINTS, OCEAN_POINTS = _build_globe_point_cloud()


class INTERNET_PER_CONN_OPTION_VALUE(ctypes.Union):
    _fields_ = [
        ("dwValue", wintypes.DWORD),
        ("pszValue", wintypes.LPWSTR),
        ("ftValue", wintypes.FILETIME),
    ]


class INTERNET_PER_CONN_OPTIONW(ctypes.Structure):
    _fields_ = [
        ("dwOption", wintypes.DWORD),
        ("Value", INTERNET_PER_CONN_OPTION_VALUE),
    ]


class INTERNET_PER_CONN_OPTION_LISTW(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("pszConnection", wintypes.LPWSTR),
        ("dwOptionCount", wintypes.DWORD),
        ("dwOptionError", wintypes.DWORD),
        ("pOptions", ctypes.POINTER(INTERNET_PER_CONN_OPTIONW)),
    ]


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def set_system_proxy(enable: bool):
    if not sys.platform.startswith("win"):
        return

    options = (INTERNET_PER_CONN_OPTIONW * 3)()
    options[0].dwOption = INTERNET_PER_CONN_FLAGS
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS

    if enable:
        options[0].Value.dwValue = PROXY_TYPE_PROXY | PROXY_TYPE_DIRECT
        options[1].Value.pszValue = f"{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}"
        options[2].Value.pszValue = "localhost;127.*;10.*;172.16.*;192.168.*;<local>"
    else:
        options[0].Value.dwValue = PROXY_TYPE_DIRECT
        options[1].Value.pszValue = ""
        options[2].Value.pszValue = ""

    opt_list = INTERNET_PER_CONN_OPTION_LISTW()
    opt_list.dwSize = ctypes.sizeof(INTERNET_PER_CONN_OPTION_LISTW)
    opt_list.pszConnection = None
    opt_list.dwOptionCount = 3
    opt_list.dwOptionError = 0
    opt_list.pOptions = options

    wininet = ctypes.windll.Wininet
    wininet.InternetSetOptionW(None, INTERNET_OPTION_PER_CONNECTION_OPTION, ctypes.byref(opt_list), opt_list.dwSize)
    wininet.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
    wininet.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)

    if is_admin():
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE_NAME}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if enable:
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={FW_RULE_NAME}",
                            "dir=out", "action=block", "protocol=UDP", "remoteport=443"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def open_tls_tunnel(timeout: float = 8.0) -> ssl.SSLSocket:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=SERVER_CERT_PATH)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    raw_sock = socket.create_connection((AZURE_SERVER_IP, AZURE_SERVER_PORT), timeout=timeout)
    return context.wrap_socket(raw_sock, server_hostname=AZURE_SERVER_IP)


def read_line(sock: socket.socket) -> str:
    buf = bytearray()
    while len(buf) < 2048:
        ch = sock.recv(1)
        if not ch or ch == b"\n":
            break
        buf.extend(ch)
    return buf.decode("utf-8", errors="replace").strip()


def send_gateway_signal(command_line: str) -> int:
    try:
        t0 = time.perf_counter()
        with open_tls_tunnel(timeout=3.0) as s:
            s.sendall(f"{command_line}\n".encode("utf-8"))
            resp = read_line(s)
        if resp in ("PONG", "BYE"):
            return max(1, int((time.perf_counter() - t0) * 1000))
    except Exception:
        pass
    return -1


def pipe_sockets(src: socket.socket, dst: socket.socket):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_browser_request(browser_sock: socket.socket):
    global REQUEST_COUNT
    tunnel_sock = None
    try:
        initial_data = browser_sock.recv(8192)
        if not initial_data or not ACTIVE_TOKEN:
            return

        first_line = initial_data.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        parts = first_line.split()
        if len(parts) < 2:
            return

        method, target = parts[0].upper(), parts[1]
        if method == "CONNECT":
            host, port_str = target.split(":")
            port = int(port_str)
            mode = "CONNECT"
        else:
            host, port = "", 80
            for line in initial_data.split(b"\r\n")[1:]:
                if line.lower().startswith(b"host:"):
                    host_val = line.split(b":", 1)[1].strip().decode("utf-8")
                    if ":" in host_val:
                        host, p = host_val.split(":")
                        port = int(p)
                    else:
                        host = host_val
                    break
            mode = "FORWARD"

        if not host:
            return

        with COUNT_LOCK:
            REQUEST_COUNT += 1

        tunnel_sock = open_tls_tunnel()
        tunnel_sock.sendall(f"AUTH {ACTIVE_TOKEN} {mode} {host} {port}\n".encode("utf-8"))

        resp = read_line(tunnel_sock)
        if resp != "OK":
            browser_sock.sendall(
                b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nSecure Gate Blocked: " + resp.encode()
            )
            return

        if method == "CONNECT":
            browser_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            tunnel_sock.sendall(initial_data)

        t1 = threading.Thread(target=pipe_sockets, args=(browser_sock, tunnel_sock), daemon=True)
        t2 = threading.Thread(target=pipe_sockets, args=(tunnel_sock, browser_sock), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except Exception:
        pass
    finally:
        if tunnel_sock:
            tunnel_sock.close()
        browser_sock.close()


def proxy_server_loop(stop_event: threading.Event):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(0.5)
        srv.bind((LOCAL_PROXY_HOST, LOCAL_PROXY_PORT))
        srv.listen(64)
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
                threading.Thread(target=handle_browser_request, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue


def create_tray_icon_image(connected: bool) -> Image.Image:
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    ring_col = (34, 197, 94, 255) if connected else (239, 68, 68, 255)
    inner_col = (74, 222, 128, 255) if connected else (248, 113, 113, 255)
    draw.ellipse((4, 4, 60, 60), fill=(9, 13, 22, 255), outline=ring_col, width=6)
    draw.ellipse((15, 15, 49, 49), outline=inner_col, width=2)
    draw.ellipse((23, 15, 41, 49), outline=inner_col, width=2)
    draw.line((15, 32, 49, 32), fill=inner_col, width=2)
    return img


def render_3d_globe_pil(angle: float, connected: bool, size: int = 240) -> Image.Image:
    ss = 3
    w = size * ss
    cx = cy = w // 2
    scale_f = w / 440.0
    ring_r = int(188 * scale_f)
    globe_r = int(150 * scale_f)
    tilt = 0.24

    img = Image.new("RGBA", (w, w), (9, 13, 22, 255))
    draw = ImageDraw.Draw(img, "RGBA")

    aura_rgb = (34, 197, 94) if connected else (239, 68, 68)
    for pad, alpha in ((22, 18), (15, 32), (9, 55)):
        p = int(pad * scale_f)
        draw.ellipse(
            (cx - ring_r - p, cy - ring_r - p, cx + ring_r + p, cy + ring_r + p),
            outline=(*aura_rgb, alpha),
            width=max(2, int(4 * scale_f)),
        )

    draw.ellipse((cx - ring_r, cy - ring_r, cx + ring_r, cy + ring_r),
                 outline=(*aura_rgb, 255), width=max(3, int(7 * scale_f)))
    track_inset = int(14 * scale_f)
    draw.ellipse((cx - ring_r + track_inset, cy - ring_r + track_inset,
                  cx + ring_r - track_inset, cy + ring_r - track_inset),
                 outline=(30, 41, 59, 185), width=max(1, int(2 * scale_f)))

    draw.ellipse((cx - globe_r, cy - globe_r, cx + globe_r, cy + globe_r), fill=(10, 17, 32, 255))
    light_rgb = (20, 60, 48) if connected else (55, 22, 30)
    for step in range(7):
        shrink = int(step * 16 * scale_f)
        off = int(step * 6 * scale_f)
        alpha = 26 + step * 9
        draw.ellipse(
            (cx - globe_r + shrink - off, cy - globe_r + shrink - off,
             cx + globe_r - shrink - off, cy + globe_r - shrink - off),
            fill=(*light_rgb, alpha),
        )

    cos_t, sin_t = math.cos(tilt), math.sin(tilt)
    ocean_r = 1.4 * scale_f

    for phi, lam0 in OCEAN_POINTS:
        lam = lam0 + angle
        x0 = math.cos(phi) * math.sin(lam)
        y0 = -math.sin(phi)
        z0 = math.cos(phi) * math.cos(lam)
        y = y0 * cos_t - z0 * sin_t
        z = y0 * sin_t + z0 * cos_t
        if z > 0.05:
            px = cx + x0 * globe_r
            py = cy + y * globe_r
            a = int(35 + 45 * z)
            draw.ellipse((px - ocean_r, py - ocean_r, px + ocean_r, py + ocean_r), fill=(71, 85, 105, a))

    visible_land = []
    back_r = 1.45 * scale_f
    for phi, lam0 in LAND_POINTS:
        lam = lam0 + angle
        x0 = math.cos(phi) * math.sin(lam)
        y0 = -math.sin(phi)
        z0 = math.cos(phi) * math.cos(lam)
        y = y0 * cos_t - z0 * sin_t
        z = y0 * sin_t + z0 * cos_t
        px = cx + x0 * globe_r
        py = cy + y * globe_r
        if z <= 0:
            draw.ellipse((px - back_r, py - back_r, px + back_r, py + back_r), fill=(25, 38, 56, 65))
        else:
            visible_land.append((z, px, py, x0, y))

    visible_land.sort(key=lambda item: item[0])
    for z, px, py, x0, y in visible_land:
        light_boost = max(0.0, (-0.45 * x0 - 0.45 * y + 0.75 * z))
        dot_r = (2.0 + 1.15 * z) * scale_f
        if connected:
            r = int(min(255, 22 + 95 * light_boost))
            g = int(min(255, 145 + 110 * z))
            b = int(min(255, 95 + 90 * light_boost))
        else:
            r = int(min(255, 165 + 90 * z))
            g = int(min(255, 48 + 95 * light_boost))
            b = int(min(255, 58 + 95 * light_boost))
        alpha = int(145 + 110 * z)
        draw.ellipse((px - dot_r, py - dot_r, px + dot_r, py + dot_r), fill=(r, g, b, alpha))

    rim_col = (74, 222, 128, 175) if connected else (248, 113, 113, 175)
    draw.ellipse((cx - globe_r, cy - globe_r, cx + globe_r, cy + globe_r),
                 outline=rim_col, width=max(2, int(3 * scale_f)))
    arc_in = int(6 * scale_f)
    draw.arc((cx - globe_r + arc_in, cy - globe_r + arc_in, cx + globe_r - arc_in, cy + globe_r - arc_in),
             start=195, end=255, fill=(255, 255, 255, 95), width=max(2, int(3 * scale_f)))

    return img.resize((size, size), Image.Resampling.LANCZOS)


class HighQualityGlobeButton(tk.Label):
    FRAME_COUNT = 60

    def __init__(self, parent, command, globe_size: int = 240, bg="#090d16"):
        self.size = globe_size
        self.command = command
        self.connected = False
        self.frame_idx = 0
        self.spin_burst = 0

        initial_pil = render_3d_globe_pil(0.0, False, self.size)
        self.initial_tk = ImageTk.PhotoImage(initial_pil)
        super().__init__(parent, image=self.initial_tk, bg=bg, bd=0, cursor="hand2")

        self.frames_disc = [self.initial_tk] + [None] * (self.FRAME_COUNT - 1)
        self.frames_conn = [None] * self.FRAME_COUNT
        self.cache_ready = False

        self.bind("<Button-1>", self._on_click)
        threading.Thread(target=self._precompute_frames, daemon=True).start()
        self._animate()

    def _precompute_frames(self):
        disc_pil = [None] * self.FRAME_COUNT
        conn_pil = [None] * self.FRAME_COUNT
        for i in range(self.FRAME_COUNT):
            ang = (2 * math.pi * i) / self.FRAME_COUNT
            if i > 0:
                disc_pil[i] = render_3d_globe_pil(ang, False, self.size)
            conn_pil[i] = render_3d_globe_pil(ang, True, self.size)

        def commit_to_tk():
            if not self.winfo_exists():
                return
            for i in range(self.FRAME_COUNT):
                if i > 0:
                    self.frames_disc[i] = ImageTk.PhotoImage(disc_pil[i])
                self.frames_conn[i] = ImageTk.PhotoImage(conn_pil[i])
            self.cache_ready = True
            self._apply_current_frame()

        self.after(0, commit_to_tk)

    def _on_click(self, _event=None):
        self.spin_burst = 24
        if self.command:
            self.command()

    def set_connected(self, state: bool):
        self.connected = state
        self._apply_current_frame()

    def _apply_current_frame(self):
        bank = self.frames_conn if self.connected else self.frames_disc
        img = bank[self.frame_idx]
        if img is not None:
            self.config(image=img)

    def _animate(self):
        if self.cache_ready:
            if self.spin_burst > 0:
                self.frame_idx = (self.frame_idx + 2) % self.FRAME_COUNT
                self.spin_burst -= 1
                self._apply_current_frame()
            elif self.connected:
                self.frame_idx = (self.frame_idx + 1) % self.FRAME_COUNT
                self._apply_current_frame()
        self.after(33, self._animate)


class SecureGateApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        try:
            dpi = self.root.winfo_fpixels("1i")
        except Exception:
            dpi = 96.0
        self.scale = max(1.0, dpi / 96.0)

        self.root.title("Secure Gate")
        self.root.geometry(f"{self.s(440)}x{self.s(590)}")
        self.root.resizable(False, False)
        self.root.configure(bg="#090d16")

        self.stop_event = threading.Event()
        threading.Thread(target=proxy_server_loop, args=(self.stop_event,), daemon=True).start()

        self.auth_mode = "LOGIN"
        self.pw_visible = False
        self.connected_since = None
        self.tray_icon = None

        self.container = tk.Frame(root, bg="#090d16")
        self.container.pack(fill="both", expand=True)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        if self._load_saved_session():
            self.show_dashboard()
        else:
            self.show_auth_screen()

    def s(self, px: int) -> int:
        return max(1, int(round(px * self.scale)))

    def _load_saved_session(self) -> bool:
        global ACTIVE_TOKEN, ACTIVE_USER
        try:
            if os.path.exists(SESSION_FILE):
                with open(SESSION_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("token") and data.get("username"):
                    ACTIVE_TOKEN = data["token"]
                    ACTIVE_USER = data["username"]
                    return True
        except Exception:
            pass
        return False

    def _save_session(self, username: str, token: str):
        with open(SESSION_FILE, "w", encoding="utf-8") as f:
            json.dump({"username": username, "token": token}, f)

    def _clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    def _tray_tooltip(self) -> str:
        state = "Connected" if GATE_ENABLED else "Disconnected"
        user_part = f" (@{ACTIVE_USER})" if ACTIVE_USER else ""
        return f"Secure Gate â€” {state}{user_part}"

    def minimize_to_tray(self):
        if self.tray_icon is None:
            menu = pystray.Menu(
                pystray.MenuItem("Open Secure Gate", self._on_tray_restore, default=True),
                pystray.MenuItem(
                    lambda item: "Disconnect Tunnel" if GATE_ENABLED else "Connect Tunnel",
                    self._on_tray_toggle,
                ),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Exit Secure Gate", self._on_tray_exit),
            )
            self.tray_icon = pystray.Icon(
                "SecureGate",
                create_tray_icon_image(GATE_ENABLED),
                self._tray_tooltip(),
                menu,
            )
            self.tray_icon.run_detached()
        self.root.withdraw()

    def _update_tray_visuals(self):
        if self.tray_icon is not None:
            try:
                self.tray_icon.icon = create_tray_icon_image(GATE_ENABLED)
                self.tray_icon.title = self._tray_tooltip()
                self.tray_icon.update_menu()
            except Exception:
                pass

    def _on_tray_restore(self, _icon=None, _item=None):
        self.root.after(0, self._restore_from_tray)

    def _restore_from_tray(self):
        if self.tray_icon is not None:
            try:
                self.tray_icon.stop()
            except Exception:
                pass
            self.tray_icon = None
        self.root.deiconify()
        self.root.state("normal")
        self.root.lift()
        self.root.focus_force()

    def _on_tray_toggle(self, _icon=None, _item=None):
        self.root.after(0, self.toggle_gate)

    def _on_tray_exit(self, _icon=None, _item=None):
        self.root.after(0, self.on_close)

    def show_auth_screen(self):
        self._clear_container()
        self.pw_visible = False

        tk.Label(self.container, text="SECURE GATE", font=("Segoe UI", 22, "bold"),
                 bg="#090d16", fg="#f8fafc").pack(pady=(self.s(48), self.s(4)))
        tk.Label(self.container, text="Zero-Trust Encrypted Cloud Gateway", font=("Segoe UI", 10),
                 bg="#090d16", fg="#64748b").pack(pady=(0, self.s(28)))

        card = tk.Frame(self.container, bg="#111827", padx=self.s(26), pady=self.s(24),
                        highlightbackground="#1e293b", highlightthickness=1)
        card.pack(padx=self.s(32), fill="x")

        self.auth_title = tk.Label(card, text="Sign In to Your Account", font=("Segoe UI", 13, "bold"),
                                   bg="#111827", fg="#f1f5f9")
        self.auth_title.pack(anchor="w", pady=(0, self.s(14)))

        tk.Label(card, text="USERNAME", font=("Segoe UI", 8, "bold"), bg="#111827", fg="#94a3b8").pack(anchor="w")
        user_box = tk.Frame(card, bg="#090d16", highlightbackground="#334155", highlightthickness=1)
        user_box.pack(fill="x", pady=(self.s(4), self.s(12)))
        self.user_entry = tk.Entry(user_box, font=("Segoe UI", 11), bg="#090d16", fg="#f8fafc",
                                   insertbackground="#f8fafc", relief="flat", bd=0)
        self.user_entry.pack(fill="x", padx=self.s(10), ipady=self.s(6))

        tk.Label(card, text="PASSWORD", font=("Segoe UI", 8, "bold"), bg="#111827", fg="#94a3b8").pack(anchor="w")
        pw_box = tk.Frame(card, bg="#090d16", highlightbackground="#334155", highlightthickness=1)
        pw_box.pack(fill="x", pady=(self.s(4), self.s(16)))
        self.pass_entry = tk.Entry(pw_box, font=("Segoe UI", 11), show="â€¢", bg="#090d16", fg="#f8fafc",
                                   insertbackground="#f8fafc", relief="flat", bd=0)
        self.pass_entry.pack(side="left", fill="x", expand=True, padx=(self.s(10), self.s(4)), ipady=self.s(6))
        self.pass_entry.bind("<Return>", lambda _e: self.submit_auth())

        self.eye_btn = tk.Button(pw_box, text="ðŸ‘", font=("Segoe UI", 11), bg="#090d16", fg="#94a3b8",
                                 activebackground="#090d16", activeforeground="#38bdf8",
                                 relief="flat", bd=0, cursor="hand2", padx=self.s(8),
                                 command=self.toggle_password_visibility)
        self.eye_btn.pack(side="right", fill="y")

        self.auth_error_lbl = tk.Label(card, text="", font=("Segoe UI", 9), bg="#111827", fg="#f87171")
        self.auth_error_lbl.pack(pady=(0, self.s(8)))

        self.auth_submit_btn = tk.Button(card, text="Sign In", font=("Segoe UI", 11, "bold"),
                                         bg="#38bdf8", fg="#020617", activebackground="#0284c7",
                                         relief="flat", cursor="hand2", command=self.submit_auth)
        self.auth_submit_btn.pack(fill="x", ipady=self.s(7))

        self.switch_mode_btn = tk.Button(self.container, text="New user? Create an account",
                                         font=("Segoe UI", 9), bg="#090d16", fg="#38bdf8",
                                         activebackground="#090d16", activeforeground="#7dd3fc",
                                         relief="flat", cursor="hand2", command=self.toggle_auth_mode)
        self.switch_mode_btn.pack(pady=self.s(16))

    def toggle_password_visibility(self):
        self.pw_visible = not self.pw_visible
        if self.pw_visible:
            self.pass_entry.config(show="")
            self.eye_btn.config(fg="#38bdf8")
        else:
            self.pass_entry.config(show="â€¢")
            self.eye_btn.config(fg="#94a3b8")

    def toggle_auth_mode(self):
        self.auth_error_lbl.config(text="")
        if self.auth_mode == "LOGIN":
            self.auth_mode = "REGISTER"
            self.auth_title.config(text="Create a New Account")
            self.auth_submit_btn.config(text="Register & Continue")
            self.switch_mode_btn.config(text="Already have an account? Sign In")
        else:
            self.auth_mode = "LOGIN"
            self.auth_title.config(text="Sign In to Your Account")
            self.auth_submit_btn.config(text="Sign In")
            self.switch_mode_btn.config(text="New user? Create an account")

    def submit_auth(self):
        username = self.user_entry.get().strip().lower()
        password = self.pass_entry.get().strip()
        if len(username) < 3 or len(password) < 4:
            self.auth_error_lbl.config(text="Username (3+ chars) and password (4+ chars) required.")
            return

        self.auth_submit_btn.config(state="disabled", text="Authenticating...")
        self.root.update()

        def worker():
            global ACTIVE_TOKEN, ACTIVE_USER
            try:
                with open_tls_tunnel(timeout=6.0) as s:
                    s.sendall(f"{self.auth_mode} {username} {password}\n".encode("utf-8"))
                    resp = read_line(s)
                if resp.startswith("OK "):
                    token = resp.split(" ", 1)[1].strip()
                    ACTIVE_TOKEN = token
                    ACTIVE_USER = username
                    self._save_session(username, token)
                    self.root.after(0, self.show_dashboard)
                elif resp == "ERR_USER_EXISTS":
                    self.root.after(0, lambda: self._auth_fail("Username already registered."))
                else:
                    self.root.after(0, lambda: self._auth_fail("Invalid username or password."))
            except Exception:
                self.root.after(0, lambda: self._auth_fail("Cannot reach Azure Gateway (check VM status)."))

        threading.Thread(target=worker, daemon=True).start()

    def _auth_fail(self, msg: str):
        self.auth_error_lbl.config(text=msg)
        label = "Sign In" if self.auth_mode == "LOGIN" else "Register & Continue"
        self.auth_submit_btn.config(state="normal", text=label)

    def show_dashboard(self):
        self._clear_container()

        top = tk.Frame(self.container, bg="#090d16")
        top.pack(fill="x", padx=self.s(22), pady=(self.s(18), self.s(4)))
        tk.Label(top, text="SECURE GATE", font=("Segoe UI", 14, "bold"),
                 bg="#090d16", fg="#f8fafc").pack(side="left")

        controls = tk.Frame(top, bg="#090d16")
        controls.pack(side="right")
        tk.Label(controls, text=f"@{ACTIVE_USER}", font=("Segoe UI", 9, "bold"),
                 bg="#090d16", fg="#38bdf8").pack(side="left", padx=(0, self.s(8)))

        tk.Button(controls, text="Hide to Tray", font=("Segoe UI", 8, "bold"),
                  bg="#0f2942", fg="#38bdf8", activebackground="#163b5c", activeforeground="#7dd3fc",
                  relief="flat", padx=self.s(8), pady=self.s(3), cursor="hand2",
                  command=self.minimize_to_tray).pack(side="left", padx=(0, self.s(6)))

        tk.Button(controls, text="Sign Out", font=("Segoe UI", 8), bg="#1e293b", fg="#cbd5e1",
                  activebackground="#334155", activeforeground="#f8fafc",
                  relief="flat", padx=self.s(8), pady=self.s(3), cursor="hand2",
                  command=self.logout).pack(side="left")

        self.globe = HighQualityGlobeButton(self.container, command=self.toggle_gate, globe_size=self.s(240))
        self.globe.pack(pady=(self.s(12), self.s(6)))

        self.status_lbl = tk.Label(self.container, text="DISCONNECTED", font=("Segoe UI", 14, "bold"),
                                   bg="#090d16", fg="#ef4444")
        self.status_lbl.pack()
        self.sub_lbl = tk.Label(self.container, text="Click the globe to route traffic through Azure TLS 1.3",
                                font=("Segoe UI", 9), bg="#090d16", fg="#64748b")
        self.sub_lbl.pack(pady=(self.s(2), self.s(16)))

        grid = tk.Frame(self.container, bg="#090d16")
        grid.pack(padx=self.s(22), fill="x")
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

        self.ping_val = self._metric_card(grid, 0, 0, "GATEWAY LATENCY", "-- ms")
        self.ip_val = self._metric_card(grid, 0, 1, "TUNNEL EXIT IP", AZURE_SERVER_IP)
        self.req_val = self._metric_card(grid, 1, 0, "TUNNELED REQUESTS", "0")
        self.time_val = self._metric_card(grid, 1, 1, "SESSION UPTIME", "00:00:00")

        mode_txt = "TLS 1.3  â€¢  Admin QUIC Intercept Active" if is_admin() else "TLS 1.3  â€¢  Standard System Proxy"
        tk.Label(self.container, text=mode_txt, font=("Segoe UI", 8),
                 bg="#090d16", fg="#475569").pack(side="bottom", pady=self.s(14))

        self._poll_metrics()

    def _metric_card(self, parent, r: int, c: int, title: str, initial: str) -> tk.Label:
        card = tk.Frame(parent, bg="#111827", padx=self.s(14), pady=self.s(12),
                        highlightbackground="#1e293b", highlightthickness=1)
        card.grid(row=r, column=c, padx=self.s(5), pady=self.s(5), sticky="nsew")
        tk.Label(card, text=title, font=("Segoe UI", 7, "bold"), bg="#111827", fg="#64748b").pack(anchor="w")
        val_lbl = tk.Label(card, text=initial, font=("Segoe UI", 12, "bold"), bg="#111827", fg="#f1f5f9")
        val_lbl.pack(anchor="w", pady=(self.s(4), 0))
        return val_lbl

    def toggle_gate(self):
        global GATE_ENABLED
        GATE_ENABLED = not GATE_ENABLED
        set_system_proxy(GATE_ENABLED)
        self.globe.set_connected(GATE_ENABLED)
        self._update_tray_visuals()
        tok = ACTIVE_TOKEN
        if GATE_ENABLED:
            self.connected_since = time.time()
            self.status_lbl.config(text="CONNECTED", fg="#22c55e")
            self.sub_lbl.config(text="Traffic encrypted via Azure VM  â€¢  Click globe to disconnect")
            if tok:
                threading.Thread(target=self._send_instant_heartbeat, args=(tok,), daemon=True).start()
        else:
            self.connected_since = None
            self.status_lbl.config(text="DISCONNECTED", fg="#ef4444")
            self.sub_lbl.config(text="Click the globe to route traffic through Azure TLS 1.3")
            if tok:
                threading.Thread(target=send_gateway_signal, args=(f"DISCONNECT {tok}",), daemon=True).start()

    def _send_instant_heartbeat(self, token: str):
        ms = send_gateway_signal(f"HEARTBEAT {token}")
        if ms > 0 and hasattr(self, "ping_val") and self.ping_val.winfo_exists():
            self.root.after(0, lambda: self.ping_val.config(text=f"{ms} ms"))

    def _poll_metrics(self):
        if not self.container.winfo_exists():
            return
        if hasattr(self, "req_val") and self.req_val.winfo_exists():
            self.req_val.config(text=str(REQUEST_COUNT))
            if self.connected_since:
                elapsed = int(time.time() - self.connected_since)
                hrs, rem = divmod(elapsed, 3600)
                mins, secs = divmod(rem, 60)
                self.time_val.config(text=f"{hrs:02d}:{mins:02d}:{secs:02d}")
            else:
                self.time_val.config(text="00:00:00")

        def ping_task():
            cmd = f"HEARTBEAT {ACTIVE_TOKEN}" if (GATE_ENABLED and ACTIVE_TOKEN) else "PING"
            ms = send_gateway_signal(cmd)
            text = f"{ms} ms" if ms > 0 else "Offline"
            if hasattr(self, "ping_val") and self.ping_val.winfo_exists():
                self.root.after(0, lambda: self.ping_val.config(text=text))

        threading.Thread(target=ping_task, daemon=True).start()
        self.root.after(3000, self._poll_metrics)

    def logout(self):
        global GATE_ENABLED, ACTIVE_TOKEN, ACTIVE_USER
        tok = ACTIVE_TOKEN
        if GATE_ENABLED:
            GATE_ENABLED = False
            set_system_proxy(False)
            if tok:
                threading.Thread(target=send_gateway_signal, args=(f"DISCONNECT {tok}",), daemon=True).start()
        ACTIVE_TOKEN = ""
        ACTIVE_USER = ""
        self._update_tray_visuals()
        if os.path.exists(SESSION_FILE):
            os.remove(SESSION_FILE)
        self.show_auth_screen()

    def on_close(self):
        global GATE_ENABLED
        tok = ACTIVE_TOKEN
        if GATE_ENABLED and tok:
            send_gateway_signal(f"DISCONNECT {tok}")
        GATE_ENABLED = False
        set_system_proxy(False)
        if self.tray_icon is not None:
            try:
                self.tray_icon.stop()
            except Exception:
                pass
            self.tray_icon = None
        self.stop_event.set()
        self.root.destroy()


if __name__ == "__main__":
    atexit.register(set_system_proxy, False)
    set_system_proxy(False)
    app_root = tk.Tk()
    SecureGateApp(app_root)
    app_root.mainloop()