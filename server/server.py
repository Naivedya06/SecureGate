import hashlib
import json
import os
import secrets
import socket
import sqlite3
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

TUNNEL_PORT = 8443
DASHBOARD_PORT = 8081
ADMIN_PATH = "/sg-admin"
ADMIN_USER = "SecureGate-Admin"
ADMIN_PASS = "CHANGE_ME_ADMIN_PASS"

STATIC_TOKEN = "CHANGE_ME_STATIC_TOKEN"
DB_PATH = os.path.expanduser("~/securegate/telemetry.db")
CERT_FILE = os.path.expanduser("~/securegate/server.crt")
KEY_FILE = os.path.expanduser("~/securegate/server.key")

IST = timezone(timedelta(hours=5, minutes=30))
SERVER_START_TIME = time.time()

DB_LOCK = threading.Lock()
STATS_LOCK = threading.Lock()
ACTIVE_TUNNELS = 0
TOTAL_BYTES = 0
RECENT_USERS = {}       # {"username (ip)": last_seen_epoch}
ADMIN_SESSIONS = set()

CDN_PARENT_MAP = {
    "fbcdn.net": "facebook.com",
    "cdninstagram.com": "instagram.com",
    "googlevideo.com": "youtube.com",
    "ytimg.com": "youtube.com",
    "gstatic.com": "google.com",
    "googleapis.com": "google.com",
    "googleusercontent.com": "google.com",
    "twimg.com": "x.com",
    "akamaized.net": "akamai-cdn",
    "cloudfront.net": "aws-cloudfront",
}


def now_ist() -> str:
    return datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")


def extract_root_site(host: str) -> str:
    clean = host.lower().strip().rstrip(".")
    parts = clean.split(".")
    if len(parts) <= 2:
        return clean
    base2 = ".".join(parts[-2:])
    if base2 in CDN_PARENT_MAP:
        return CDN_PARENT_MAP[base2]
    if parts[-2] in {"co", "org", "ac", "gov", "net", "in"} and len(parts) >= 3:
        return ".".join(parts[-3:])
    return base2


def format_bytes(num: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024:
            return f"{num:.1f} {unit}" if unit != "B" else f"{num} B"
        num /= 1024
    return f"{num:.2f} TB"


def get_vm_health() -> tuple[str, str]:
    cpu_str = "N/A"
    mem_str = "N/A"
    try:
        with open("/proc/loadavg", "r", encoding="utf-8") as f:
            load_1m = float(f.read().split()[0])
        cores = os.cpu_count() or 1
        cpu_pct = min(100.0, (load_1m / cores) * 100.0)
        cpu_str = f"{cpu_pct:.1f}% (load {load_1m:.2f})"
    except Exception:
        pass
    try:
        mem = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                k, v = line.split(":", 1)
                mem[k.strip()] = int(v.strip().split()[0])
        total_mb = mem["MemTotal"] / 1024
        avail_mb = mem.get("MemAvailable", mem.get("MemFree", 0)) / 1024
        used_mb = total_mb - avail_mb
        pct = (used_mb / total_mb) * 100 if total_mb else 0
        mem_str = f"{used_mb:.0f}/{total_mb:.0f} MB ({pct:.0f}%)"
    except Exception:
        pass
    return cpu_str, mem_str


def init_db():
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                client_ip TEXT,
                username TEXT,
                root_site TEXT,
                mode TEXT,
                target TEXT,
                bytes_transferred INTEGER DEFAULT 0,
                status TEXT
            )
        """)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(logs)").fetchall()]
        if "root_site" not in cols:
            conn.execute("ALTER TABLE logs ADD COLUMN root_site TEXT DEFAULT ''")
        if "bytes_transferred" not in cols:
            conn.execute("ALTER TABLE logs ADD COLUMN bytes_transferred INTEGER DEFAULT 0")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                token TEXT NOT NULL,
                created_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_domains (
                domain TEXT PRIMARY KEY,
                added_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS meta (
                k TEXT PRIMARY KEY,
                v TEXT
            )
        """)
        seeded = conn.execute("SELECT v FROM meta WHERE k = 'seeded_blocks'").fetchone()
        if not seeded:
            for dom in ("example.org", "badsite.com", "malware-test.org"):
                conn.execute(
                    "INSERT OR IGNORE INTO blocked_domains (domain, added_at) VALUES (?, ?)",
                    (dom, now_ist()),
                )
            conn.execute("INSERT INTO meta (k, v) VALUES ('seeded_blocks', '1')")
        conn.commit()
        conn.close()


def resolve_username(token: str) -> str | None:
    if not token:
        return None
    if token == STATIC_TOKEN:
        return "default"
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute("SELECT username FROM users WHERE token = ?", (token,)).fetchone()
        conn.close()
    return row[0] if row else None


def is_domain_blocked(host: str) -> bool:
    clean = host.lower().strip().rstrip(".")
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        blocked = [r[0] for r in conn.execute("SELECT domain FROM blocked_domains").fetchall()]
        conn.close()
    return any(clean == d or clean.endswith("." + d) for d in blocked)


def hash_password(password: str) -> str:
    return hashlib.sha256(("sg_salt_2026_" + password).encode("utf-8")).hexdigest()


def insert_log(client_ip: str, username: str, root_site: str, mode: str, target: str, status: str) -> int:
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.execute(
            "INSERT INTO logs (ts, client_ip, username, root_site, mode, target, bytes_transferred, status) "
            "VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
            (now_ist(), client_ip, username, root_site, mode, target, status),
        )
        log_id = cur.lastrowid
        conn.commit()
        conn.close()
    return log_id


def update_log_bytes(log_id: int, byte_count: int):
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE logs SET bytes_transferred = ? WHERE id = ?", (byte_count, log_id))
        conn.commit()
        conn.close()


def read_line(sock: ssl.SSLSocket) -> str:
    buf = bytearray()
    while len(buf) < 2048:
        ch = sock.recv(1)
        if not ch or ch == b"\n":
            break
        buf.extend(ch)
    return buf.decode("utf-8", errors="replace").strip()


def pipe(src, dst, counter: list):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
            counter[0] += len(data)
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_client(tls_sock: ssl.SSLSocket, addr):
    global ACTIVE_TUNNELS, TOTAL_BYTES
    client_ip = addr[0]
    remote = None
    counted_active = False
    try:
        line = read_line(tls_sock)
        parts = line.split()
        if not parts:
            return

        cmd = parts[0].upper()

        if cmd == "REGISTER" and len(parts) == 3:
            username, password = parts[1].strip().lower(), parts[2].strip()
            if len(username) < 3 or len(password) < 4:
                tls_sock.sendall(b"ERR_INVALID_INPUT\n")
                return
            token = hashlib.sha256(f"{username}:{password}:sg2026".encode()).hexdigest()[:32]
            with DB_LOCK:
                conn = sqlite3.connect(DB_PATH)
                try:
                    conn.execute(
                        "INSERT INTO users (username, password_hash, token, created_at) VALUES (?, ?, ?, ?)",
                        (username, hash_password(password), token, now_ist()),
                    )
                    conn.commit()
                    tls_sock.sendall(f"OK {token}\n".encode())
                except sqlite3.IntegrityError:
                    tls_sock.sendall(b"ERR_USER_EXISTS\n")
                finally:
                    conn.close()
            return

        if cmd == "LOGIN" and len(parts) == 3:
            username, password = parts[1].strip().lower(), parts[2].strip()
            with DB_LOCK:
                conn = sqlite3.connect(DB_PATH)
                row = conn.execute(
                    "SELECT password_hash, token FROM users WHERE username = ?", (username,)
                ).fetchone()
                conn.close()
            if row and row[0] == hash_password(password):
                tls_sock.sendall(f"OK {row[1]}\n".encode())
            else:
                tls_sock.sendall(b"ERR_INVALID_CREDENTIALS\n")
            return

        if cmd == "PING":
            tls_sock.sendall(b"PONG\n")
            return

        if cmd == "HEARTBEAT" and len(parts) == 2:
            username = resolve_username(parts[1].strip())
            if username:
                with STATS_LOCK:
                    RECENT_USERS[f"{username} ({client_ip})"] = time.time()
                tls_sock.sendall(b"PONG\n")
            else:
                tls_sock.sendall(b"ERR_UNAUTHORIZED\n")
            return

        if cmd == "DISCONNECT" and len(parts) == 2:
            username = resolve_username(parts[1].strip())
            if username:
                with STATS_LOCK:
                    stale_keys = [k for k in RECENT_USERS if k.startswith(f"{username} (")]
                    for k in stale_keys:
                        del RECENT_USERS[k]
            tls_sock.sendall(b"BYE\n")
            return

        if cmd == "AUTH" and len(parts) == 5:
            _, token, mode, host, port_str = parts
            port = int(port_str)
            username = resolve_username(token)
            if not username:
                tls_sock.sendall(b"ERR_UNAUTHORIZED\n")
                return

            with STATS_LOCK:
                RECENT_USERS[f"{username} ({client_ip})"] = time.time()
                ACTIVE_TUNNELS += 1
                counted_active = True

            root_site = extract_root_site(host)

            if is_domain_blocked(host):
                insert_log(client_ip, username, root_site, mode, f"{host}:{port}", "DENY")
                tls_sock.sendall(b"ERR_DENIED\n")
                return

            remote = socket.create_connection((host, port), timeout=10)
            log_id = insert_log(client_ip, username, root_site, mode, f"{host}:{port}", "ALLOW")
            tls_sock.sendall(b"OK\n")

            byte_counter = [0]
            t1 = threading.Thread(target=pipe, args=(tls_sock, remote, byte_counter), daemon=True)
            t2 = threading.Thread(target=pipe, args=(remote, tls_sock, byte_counter), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()

            with STATS_LOCK:
                TOTAL_BYTES += byte_counter[0]
            update_log_bytes(log_id, byte_counter[0])
    except Exception:
        pass
    finally:
        if counted_active:
            with STATS_LOCK:
                ACTIVE_TUNNELS = max(0, ACTIVE_TUNNELS - 1)
        if remote:
            remote.close()
        tls_sock.close()


def build_grouped_payload() -> dict:
    now_ep = time.time()
    with STATS_LOCK:
        active_tunnels = ACTIVE_TUNNELS
        total_bytes = TOTAL_BYTES
        # Heartbeats arrive every 3s; 15s timeout cleans up crashed sessions fast
        expired = [u for u, ts in RECENT_USERS.items() if (now_ep - ts) > 15]
        for u in expired:
            del RECENT_USERS[u]
        connected_list = list(RECENT_USERS.keys())

    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        total_reqs = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        blocked_reqs = conn.execute("SELECT COUNT(*) FROM logs WHERE status = 'DENY'").fetchone()[0]
        registered_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        blocked_domains = conn.execute(
            "SELECT domain, added_at FROM blocked_domains ORDER BY domain ASC"
        ).fetchall()
        recent_rows = conn.execute(
            "SELECT id, ts, client_ip, username, root_site, mode, target, bytes_transferred, status "
            "FROM logs ORDER BY id DESC LIMIT 120"
        ).fetchall()
        conn.close()

    groups = []
    for row in recent_rows:
        rid, ts, cip, user, root_site, mode, target, b_tx, status = row
        user_disp = user or "default"
        site_disp = root_site or extract_root_site(target.split(":")[0])

        if groups and groups[-1]["root_site"] == site_disp and groups[-1]["username"] == user_disp:
            g = groups[-1]
            g["packets"].append({
                "id": rid, "ts": ts, "mode": mode, "target": target,
                "bytes": format_bytes(b_tx or 0), "status": status
            })
            g["total_bytes_raw"] += (b_tx or 0)
            g["total_bytes"] = format_bytes(g["total_bytes_raw"])
            if status == "DENY":
                g["status"] = "DENY"
        else:
            groups.append({
                "group_id": f"grp_{rid}",
                "latest_ts": ts,
                "client_ip": cip,
                "username": user_disp,
                "root_site": site_disp,
                "total_bytes_raw": b_tx or 0,
                "total_bytes": format_bytes(b_tx or 0),
                "status": status,
                "packets": [{
                    "id": rid, "ts": ts, "mode": mode, "target": target,
                    "bytes": format_bytes(b_tx or 0), "status": status
                }]
            })

    uptime_sec = int(now_ep - SERVER_START_TIME)
    hrs, rem = divmod(uptime_sec, 3600)
    mins, secs = divmod(rem, 60)
    cpu_str, mem_str = get_vm_health()

    return {
        "server_time_ist": now_ist(),
        "connected_users_count": len(connected_list),
        "connected_users": connected_list,
        "registered_users": registered_users,
        "active_tunnels": active_tunnels,
        "total_requests": total_reqs,
        "blocked_requests": blocked_reqs,
        "total_bandwidth": format_bytes(total_bytes),
        "uptime": f"{hrs:02d}h {mins:02d}m {secs:02d}s",
        "cpu": cpu_str,
        "memory": mem_str,
        "blocked_domains": [{"domain": d, "added_at": a} for d, a in blocked_domains],
        "groups": groups[:35],
    }


LOGIN_PAGE_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Secure Gate â€” Admin Sign In</title>
<style>
  body{margin:0;background:#070b14;color:#f1f5f9;font-family:'Segoe UI',system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh}
  .card{background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:34px;width:360px;box-shadow:0 20px 40px rgba(0,0,0,.5)}
  h1{margin:0 0 6px;font-size:20px;letter-spacing:.5px}
  p{margin:0 0 22px;color:#64748b;font-size:13px}
  label{display:block;font-size:11px;font-weight:700;color:#94a3b8;margin-bottom:6px;letter-spacing:.6px}
  input{width:100%;box-sizing:border-box;padding:10px 12px;margin-bottom:16px;border-radius:8px;border:1px solid #334155;background:#070b14;color:#f8fafc;font-size:14px}
  input:focus{outline:none;border-color:#38bdf8}
  .pw-wrap{position:relative;margin-bottom:16px}
  .pw-wrap input{margin-bottom:0;padding-right:42px}
  .eye-btn{position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;color:#94a3b8;cursor:pointer;padding:4px;display:flex;align-items:center;width:auto}
  .eye-btn:hover{color:#38bdf8;background:none}
  .submit-btn{width:100%;padding:11px;border:none;border-radius:8px;background:#38bdf8;color:#020617;font-weight:700;font-size:14px;cursor:pointer}
  .submit-btn:hover{background:#0ea5e9}
  .err{color:#f87171;font-size:13px;margin-bottom:14px}
</style></head><body>
<form class="card" method="POST" action="/sg-admin/login">
  <h1>SECURE GATE ADMIN</h1>
  <p>Restricted Cloud Gateway Control Console</p>
  __ERR__
  <label>ADMIN USERNAME</label>
  <input type="text" name="username" required autocomplete="off">
  <label>PASSWORD</label>
  <div class="pw-wrap">
    <input type="password" id="admin-pw" name="password" required>
    <button type="button" class="eye-btn" onclick="toggleAdminPw()" title="Show or hide password">
      <svg id="eye-open" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
      <svg id="eye-closed" style="display:none" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
    </button>
  </div>
  <button class="submit-btn" type="submit">Sign In to Console</button>
</form>
<script>
function toggleAdminPw(){
  const inp = document.getElementById('admin-pw');
  const openIc = document.getElementById('eye-open');
  const closedIc = document.getElementById('eye-closed');
  if(inp.type === 'password'){
    inp.type = 'text';
    openIc.style.display = 'none';
    closedIc.style.display = 'block';
  } else {
    inp.type = 'password';
    openIc.style.display = 'block';
    closedIc.style.display = 'none';
  }
}
</script></body></html>"""


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Secure Gate â€” Admin Console</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;background:#070b14;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;padding:24px 32px}
  .topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px;padding-bottom:16px;border-bottom:1px solid #1e293b}
  .title{font-size:20px;font-weight:700;color:#f8fafc}
  .sub{font-size:12px;color:#38bdf8;margin-top:3px}
  .logout{background:#1e293b;color:#cbd5e1;border:1px solid #334155;padding:7px 14px;border-radius:6px;text-decoration:none;font-size:13px}
  .logout:hover{background:#334155}
  .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:14px;margin-bottom:24px}
  .card{background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:16px}
  .card .k{font-size:11px;font-weight:700;color:#64748b;letter-spacing:.6px;text-transform:uppercase}
  .card .v{font-size:22px;font-weight:700;color:#f8fafc;margin-top:6px}
  .card .subv{font-size:11px;color:#94a3b8;margin-top:4px}
  .layout{display:grid;grid-template-columns:1fr 340px;gap:20px;align-items:start}
  @media(max-width:1050px){.layout{grid-template-columns:1fr}}
  .panel{background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:18px}
  .panel h2{margin:0 0 14px;font-size:15px;color:#f8fafc;display:flex;justify-content:space-between;align-items:center}
  details.grp{border:1px solid #1e293b;border-radius:8px;margin-bottom:8px;background:#0b1120;overflow:hidden}
  details.grp summary{list-style:none;padding:12px 14px;cursor:pointer;display:grid;grid-template-columns:170px 120px 1fr 95px 80px;gap:10px;align-items:center;font-size:13px}
  details.grp summary::-webkit-details-marker{display:none}
  details.grp summary:hover{background:#131c31}
  .badge-cnt{background:#1e293b;color:#38bdf8;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600;margin-left:8px}
  .st-allow{color:#22c55e;font-weight:700;text-align:right}
  .st-deny{color:#ef4444;font-weight:700;text-align:right}
  .pkt-table{width:100%;border-collapse:collapse;background:#070b14;border-top:1px solid #1e293b}
  .pkt-table th,.pkt-table td{padding:7px 14px;font-size:12px;text-align:left;border-bottom:1px solid #111827}
  .pkt-table th{color:#64748b;font-weight:600}
  .add-form{display:flex;gap:8px;margin-bottom:14px}
  .add-form input{flex:1;padding:8px 10px;border-radius:6px;border:1px solid #334155;background:#070b14;color:#f8fafc;font-size:13px}
  .add-form button{padding:8px 14px;border:none;border-radius:6px;background:#ef4444;color:#fff;font-weight:600;font-size:13px;cursor:pointer}
  .dom-item{display:flex;justify-content:space-between;align-items:center;padding:9px 10px;border-bottom:1px solid #1e293b;font-size:13px}
  .btn-allow{background:#143326;color:#4ade80;border:1px solid #22c55e;padding:4px 10px;border-radius:5px;font-size:11px;font-weight:600;cursor:pointer}
  .btn-allow:hover{background:#22c55e;color:#020617}
</style></head><body>
<div class="topbar">
  <div>
    <div class="title">SECURE GATE â€” CLOUD ADMIN CONSOLE</div>
    <div class="sub" id="clock">Loading IST telemetry...</div>
  </div>
  <a class="logout" href="/sg-admin/logout">Sign Out</a>
</div>

<div class="metrics">
  <div class="card"><div class="k">Connected Users</div><div class="v" id="m-users">0</div><div class="subv" id="m-users-sub">0 registered total</div></div>
  <div class="card"><div class="k">Active Tunnels</div><div class="v" id="m-tunnels">0</div><div class="subv">Live TLS 1.3 streams</div></div>
  <div class="card"><div class="k">Total Packets / Reqs</div><div class="v" id="m-reqs">0</div><div class="subv" id="m-blocked">0 blocked threats</div></div>
  <div class="card"><div class="k">Data Tunneled</div><div class="v" id="m-bw">0 B</div><div class="subv">Encrypted throughput</div></div>
  <div class="card"><div class="k">VM Performance</div><div class="v" id="m-cpu" style="font-size:16px">--</div><div class="subv" id="m-mem">RAM: --</div></div>
  <div class="card"><div class="k">Gateway Uptime</div><div class="v" id="m-up" style="font-size:18px">--</div><div class="subv">Azure VM Gateway</div></div>
</div>

<div class="layout">
  <div class="panel">
    <h2><span>Website &amp; Task Traffic Inspector (Click row to expand packets)</span><span style="font-size:11px;color:#64748b">Live IST Feed</span></h2>
    <div id="groups-container">Loading traffic...</div>
  </div>

  <div class="panel">
    <h2>Website Access Policy</h2>
    <form class="add-form" onsubmit="blockDomain(event)">
      <input type="text" id="dom-input" placeholder="e.g. youtube.com or example.org" required>
      <button type="submit">Restrict</button>
    </form>
    <div style="font-size:11px;color:#64748b;margin-bottom:8px">RESTRICTED WEBSITES (CLICK ALLOW TO UNBLOCK)</div>
    <div id="blocked-list"></div>
  </div>
</div>

<script>
const openGroups = new Set();

function esc(s){
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function blockDomain(e){
  e.preventDefault();
  const inp = document.getElementById('dom-input');
  const domain = inp.value.trim();
  if(!domain) return;
  await fetch('/sg-admin/block', {
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'domain=' + encodeURIComponent(domain)
  });
  inp.value = '';
  refreshState();
}

async function unblockDomain(domain){
  await fetch('/sg-admin/unblock', {
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'domain=' + encodeURIComponent(domain)
  });
  refreshState();
}

async function refreshState(){
  try{
    const res = await fetch('/sg-admin/api/state');
    if(res.status === 401){ window.location.href = '/sg-admin'; return; }
    const d = await res.json();

    document.getElementById('clock').textContent = 'Gateway Clock: ' + d.server_time_ist;
    document.getElementById('m-users').textContent = d.connected_users_count;
    document.getElementById('m-users-sub').textContent =
      (d.connected_users.length ? d.connected_users.join(', ') : 'No active sessions') + ' (' + d.registered_users + ' registered)';
    document.getElementById('m-tunnels').textContent = d.active_tunnels;
    document.getElementById('m-reqs').textContent = d.total_requests;
    document.getElementById('m-blocked').textContent = d.blocked_requests + ' blocked requests';
    document.getElementById('m-bw').textContent = d.total_bandwidth;
    document.getElementById('m-cpu').textContent = 'CPU: ' + d.cpu;
    document.getElementById('m-mem').textContent = 'RAM: ' + d.memory;
    document.getElementById('m-up').textContent = d.uptime;

    const bList = document.getElementById('blocked-list');
    bList.innerHTML = d.blocked_domains.map(item => `
      <div class="dom-item">
        <div><strong>${esc(item.domain)}</strong><div style="font-size:10px;color:#64748b">${esc(item.added_at)}</div></div>
        <button class="btn-allow" onclick="unblockDomain('${esc(item.domain)}')">Allow</button>
      </div>
    `).join('') || '<div style="color:#64748b;font-size:12px">No restricted websites.</div>';

    const gCont = document.getElementById('groups-container');
    gCont.innerHTML = d.groups.map(g => {
      const isOpen = openGroups.has(g.group_id) ? 'open' : '';
      const stCls = g.status === 'DENY' ? 'st-deny' : 'st-allow';
      const rows = g.packets.map(p => `
        <tr>
          <td>${esc(p.ts)}</td>
          <td>${esc(p.mode)}</td>
          <td>${esc(p.target)}</td>
          <td>${esc(p.bytes)}</td>
          <td style="color:${p.status==='DENY'?'#ef4444':'#22c55e'};font-weight:700">${esc(p.status)}</td>
        </tr>
      `).join('');
      return `
        <details class="grp" id="${esc(g.group_id)}" ${isOpen} ontoggle="if(this.open){openGroups.add('${esc(g.group_id)}')}else{openGroups.delete('${esc(g.group_id)}')}">
          <summary>
            <span style="color:#94a3b8;font-size:12px">${esc(g.latest_ts)}</span>
            <span style="color:#38bdf8;font-weight:600">@${esc(g.username)}</span>
            <span><strong>&#9662; ${esc(g.root_site)}</strong><span class="badge-cnt">${g.packets.length} pkt${g.packets.length>1?'s':''}</span></span>
            <span style="color:#cbd5e1">${esc(g.total_bytes)}</span>
            <span class="${stCls}">${esc(g.status)}</span>
          </summary>
          <table class="pkt-table">
            <tr><th>Time (IST)</th><th>Protocol</th><th>Sub-Host / Endpoint</th><th>Size</th><th>Policy</th></tr>
            ${rows}
          </table>
        </details>
      `;
    }).join('') || '<div style="color:#64748b;font-size:13px">No traffic recorded yet.</div>';
  }catch(e){}
}

refreshState();
setInterval(refreshState, 1500);
</script></body></html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    def _is_authenticated(self) -> bool:
        cookie_hdr = self.headers.get("Cookie", "")
        for part in cookie_hdr.split(";"):
            part = part.strip()
            if part.startswith("sg_admin_sid="):
                sid = part.split("=", 1)[1]
                if sid in ADMIN_SESSIONS:
                    return True
        return False

    def _send_html(self, status: int, body: str, extra_headers: dict = None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _send_json(self, status: int, payload: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path not in (ADMIN_PATH, f"{ADMIN_PATH}/", f"{ADMIN_PATH}/api/state", f"{ADMIN_PATH}/logout"):
            self._send_html(404, "<h3>404 Not Found</h3>")
            return

        if path == f"{ADMIN_PATH}/logout":
            cookie_hdr = self.headers.get("Cookie", "")
            for part in cookie_hdr.split(";"):
                if part.strip().startswith("sg_admin_sid="):
                    ADMIN_SESSIONS.discard(part.strip().split("=", 1)[1])
            self.send_response(302)
            self.send_header("Set-Cookie", "sg_admin_sid=; Path=/sg-admin; Max-Age=0")
            self.send_header("Location", ADMIN_PATH)
            self.end_headers()
            return

        if not self._is_authenticated():
            if path == f"{ADMIN_PATH}/api/state":
                self._send_json(401, {"error": "unauthorized"})
            else:
                self._send_html(200, LOGIN_PAGE_HTML.replace("__ERR__", ""))
            return

        if path == f"{ADMIN_PATH}/api/state":
            self._send_json(200, build_grouped_payload())
            return

        self._send_html(200, DASHBOARD_HTML)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse_qs(raw_body)

        if path == f"{ADMIN_PATH}/login":
            user = form.get("username", [""])[0].strip()
            pw = form.get("password", [""])[0].strip()
            if user == ADMIN_USER and pw == ADMIN_PASS:
                sid = secrets.token_hex(24)
                ADMIN_SESSIONS.add(sid)
                self.send_response(302)
                self.send_header("Set-Cookie", f"sg_admin_sid={sid}; Path=/sg-admin; HttpOnly")
                self.send_header("Location", ADMIN_PATH)
                self.end_headers()
            else:
                err_html = '<div class="err">Invalid Admin Username or Password.</div>'
                self._send_html(401, LOGIN_PAGE_HTML.replace("__ERR__", err_html))
            return

        if not self._is_authenticated():
            self._send_json(401, {"error": "unauthorized"})
            return

        if path == f"{ADMIN_PATH}/block":
            dom = form.get("domain", [""])[0].strip().lower()
            dom = dom.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            if dom:
                with DB_LOCK:
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute(
                        "INSERT OR IGNORE INTO blocked_domains (domain, added_at) VALUES (?, ?)",
                        (dom, now_ist()),
                    )
                    conn.commit()
                    conn.close()
            self._send_json(200, {"ok": True})
            return

        if path == f"{ADMIN_PATH}/unblock":
            dom = form.get("domain", [""])[0].strip().lower()
            if dom:
                with DB_LOCK:
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute("DELETE FROM blocked_domains WHERE domain = ?", (dom,))
                    conn.commit()
                    conn.close()
            self._send_json(200, {"ok": True})
            return

        self._send_html(404, "<h3>404 Not Found</h3>")

    def log_message(self, format, *args):
        return


def start_tunnel():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", TUNNEL_PORT))
        sock.listen(128)
        while True:
            raw, addr = sock.accept()
            try:
                tls_conn = ctx.wrap_socket(raw, server_side=True)
                threading.Thread(target=handle_client, args=(tls_conn, addr), daemon=True).start()
            except Exception:
                raw.close()


if __name__ == "__main__":
    init_db()
    threading.Thread(target=start_tunnel, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", DASHBOARD_PORT), DashboardHandler).serve_forever()
