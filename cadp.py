#!/usr/bin/env python3
"""CADP — Challenge Anti DDoS +.

A small, dependency-free HTTP gate for static sites:

- optional challenge types: FNV proof-of-work, heavier "mine" hash task,
  arithmetic task, small linear-model training task;
- multi-group challenges: the client must solve every configured group;
- pre-cached challenge pool (no per-request challenge generation);
- pass cookie (HMAC, IP-bound), rate limits, challenge timeouts, bans;
- optional SYN / connection-flood monitor (Windows TCP table, Linux /proc);
- built-in admin UI: stats, config editor, ban / unban, firewall handling;
- one-click installer: install.ps1.

Run:
    python cadp.py --config config.json
Init:
    python cadp.py --init-config --config config.json --port 8080
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import datetime
import hashlib
import hmac
import html
import http.server
import json
import mimetypes
import os
import random
import re
import secrets
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

__version__ = "0.1.0"

# ---------------------------------------------------------------- defaults

DEFAULT_CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 8080,
    "root": "site",
    "pass_ttl": 3600,
    "pending_ttl": 30,
    "pending_max": 10,
    "rate_window": 10,
    "rate_max": 30,
    "fail_max": 5,
    "fail_window": 60,
    "ban_ttl": 3600,
    "pool_size": 20000,
    "challenge_groups": [
        {"id": "pow-fnv", "type": "pow_fnv", "bits": 20, "count": 1, "enabled": True},
    ],
    "admin": {"password_hash": "", "session_ttl": 3600},
    "syn": {
        "enabled": True,
        "syn_threshold": 10,
        "est_threshold": 24,
        "block_firewall": True,
    },
}

_lock = threading.RLock()


def _now() -> float:
    return time.time()


def _merge(base: dict, extra: dict) -> dict:
    out = dict(base)
    for key, value in (extra or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def _load_config(path: Path) -> dict:
    if path.exists():
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        data = {}
    return _merge(DEFAULT_CONFIG, data)


def _save_config(path: Path, cfg: dict):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    rounds = 120_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds)
    return f"pbkdf2_sha256${rounds}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                  bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(got.hex(), digest)
    except Exception:
        return False


# ---------------------------------------------------------------- FNV / pool

def fnv1a(text: str) -> int:
    h = 2166136261
    for ch in text:
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF
    return h


class ChallengePool:
    """Pre-generated (id, salt) pairs; cursor rotation, no per-request generation."""

    def __init__(self, path: Path, size: int):
        self.path = path
        self.entries: list[dict] = []
        self.cursor = 0
        self.lock = threading.Lock()
        self._load(size)

    def _load(self, size: int):
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                self.entries = [e for e in data if isinstance(e, dict) and e.get("id")]
            state = {}
            state_path = self.path.with_name(self.path.stem + "_state.json")
            if state_path.exists():
                state = json.loads(state_path.read_text(encoding="utf-8"))
                self.cursor = int(state.get("cursor", 0))
        except Exception:
            self.entries = []
            self.cursor = 0

        if len(self.entries) < size:
            for _ in range(size - len(self.entries)):
                self.entries.append({
                    "id": secrets.token_hex(8),
                    "salt": secrets.token_hex(8),
                })
            self._save()

        self.cursor %= max(1, len(self.entries))

    def _save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.entries, fh)
            os.replace(tmp, self.path)
            state = self.path.with_name(self.path.stem + "_state.json")
            state.write_text(json.dumps({"cursor": self.cursor}), encoding="utf-8")
        except OSError:
            pass

    def next(self) -> dict:
        with self.lock:
            entry = self.entries[self.cursor]
            self.cursor = (self.cursor + 1) % len(self.entries)
            if self.cursor % 50 == 0:
                self._save()
            return {"id": entry["id"], "salt": entry["salt"]}


# ---------------------------------------------------------------- challenges

def _linear_data(seed: str, n: int, noise: float):
    rng = random.Random(seed)
    w1, w2, b = 1.7, -2.3, 0.4
    xs, ys = [], []
    for _ in range(n):
        x1 = rng.uniform(-1, 1)
        x2 = rng.uniform(-1, 1)
        y = w1 * x1 + w2 * x2 + b + rng.uniform(-noise, noise)
        xs.append([x1, x2])
        ys.append(y)
    return xs, ys


def build_challenge(group: dict, pool: ChallengePool) -> dict:
    typ = group.get("type", "pow_fnv")
    if typ in ("pow_fnv", "mine", "pow_hard"):
        entry = pool.next()
        bits = int(group.get("bits", 20))
        return {
            "type": typ,
            "id": entry["id"],
            "salt": entry["salt"],
            "bits": bits,
            "task": "hash" if typ != "mine" else "mine",
        }
    if typ == "linear_train":
        seed = secrets.token_hex(8)
        n = int(group.get("samples", 40))
        noise = float(group.get("noise", 0.02))
        xs, ys = _linear_data(seed, n, noise)
        return {
            "type": "linear_train",
            "seed": seed,
            "X": [[round(v, 6) for v in row] for row in xs],
            "y": [round(v, 6) for v in ys],
            "epochs": int(group.get("epochs", 120)),
            "lr": float(group.get("lr", 0.05)),
            "threshold": float(group.get("threshold", 0.01)),
        }
    if typ == "arith":
        a = random.randint(11, 99)
        b = random.randint(11, 99)
        c = random.randint(1, 999)
        m = random.randint(7, 31)
        return {
            "type": "arith",
            "a": a, "b": b, "c": c, "m": m,
            "expr": f"({a}*{b}+{c}) % {m}",
            "answer": (a * b + c) % m,
        }
    raise ValueError(f"unknown challenge type: {typ}")


def verify_challenge(ch: dict, answer) -> tuple[bool, str]:
    typ = ch.get("type")
    try:
        if typ in ("pow_fnv", "mine", "pow_hard"):
            nonce = str(answer).strip()
            if not nonce.isdigit():
                return False, "nonce must be an integer"
            bits = int(ch.get("bits", 20))
            target = 1 << (32 - bits)
            if bits <= 0 or bits > 32:
                return False, "bad difficulty"
            return fnv1a(ch["id"] + ch["salt"] + nonce) < target, "bad pow"
        if typ == "linear_train":
            if not isinstance(answer, (list, tuple)) or len(answer) != 3:
                return False, "answer must be [w1,w2,b]"
            w1, w2, b = (float(v) for v in answer)
            xs, ys = ch["X"], ch["y"]
            mse = sum((w1 * x[0] + w2 * x[1] + b - y) ** 2
                      for x, y in zip(xs, ys)) / max(1, len(ys))
            ok = mse <= float(ch.get("threshold", 0.01))
            return ok, f"mse={mse:.6f}"
        if typ == "arith":
            return int(answer) == int(ch["answer"]), "bad arithmetic"
    except Exception:
        return False, "invalid answer"
    return False, "unknown challenge"


# ---------------------------------------------------------------- state

class State:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.config = _load_config(config_path)
        self.base = config_path.parent
        self.root = (self.base / self.config["root"]).resolve()
        self.secret = self._load_secret()
        self.pool = ChallengePool(self.base / "challenge_pool.json",
                                  int(self.config.get("pool_size", 20000)))
        self.bans: dict[str, float] = self._load_bans()
        self.sessions: dict[str, dict] = {}
        self.rate: dict[str, deque] = defaultdict(deque)
        self.fails: dict[str, deque] = defaultdict(deque)
        self.stats = Counter()
        self.ip_counts = Counter()
        self.blocked: list[str] = []
        self.access_log = self.base / "access.log"
        self.security_log = self.base / "security.log"
        self._ensure_admin()

    # ---------- secret / pass ----------

    def _load_secret(self) -> bytes:
        path = self.base / "cadp_secret"
        try:
            data = path.read_bytes()
            if len(data) >= 32:
                return data
        except OSError:
            pass
        data = secrets.token_bytes(32)
        try:
            path.write_bytes(data)
        except OSError:
            pass
        return data

    def make_pass(self, ip: str) -> str:
        exp = int(_now()) + int(self.config.get("pass_ttl", 3600))
        payload = f"{ip}|{exp}"
        sig = hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()[:32]
        return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()

    def verify_pass(self, token: str, ip: str) -> bool:
        try:
            raw = base64.urlsafe_b64decode(token.encode()).decode()
            ip_part, exp, sig = raw.rsplit("|", 2)
            if ip_part != ip or int(exp) < int(_now()):
                return False
            want = hmac.new(self.secret, f"{ip_part}|{exp}".encode(),
                            hashlib.sha256).hexdigest()[:32]
            return hmac.compare_digest(sig, want)
        except Exception:
            return False

    # ---------- admin ----------

    def _ensure_admin(self):
        admin = self.config.setdefault("admin", {})
        if admin.get("password_hash"):
            return
        password = secrets.token_urlsafe(12)
        admin["password_hash"] = _hash_password(password)
        _save_config(self.config_path, self.config)
        try:
            (self.base / "ADMIN_PASSWORD.txt").write_text(password, encoding="utf-8")
        except OSError:
            pass
        print(f"[CADP] admin password: {password} (saved to ADMIN_PASSWORD.txt)")

    def admin_ok(self, token: str) -> bool:
        try:
            raw = base64.urlsafe_b64decode(token.encode()).decode()
            exp, sig = raw.rsplit("|", 1)
            if int(exp) < int(_now()):
                return False
            want = hmac.new(self.secret, f"admin|{exp}".encode(),
                            hashlib.sha256).hexdigest()[:32]
            return hmac.compare_digest(sig, want)
        except Exception:
            return False

    def admin_token(self) -> str:
        exp = str(int(_now()) + int(self.config.get("admin", {}).get("session_ttl", 3600)))
        sig = hmac.new(self.secret, f"admin|{exp}".encode(), hashlib.sha256).hexdigest()[:32]
        return base64.urlsafe_b64encode(f"{exp}|{sig}".encode()).decode()

    # ---------- logs ----------

    def log_security(self, kind: str, ip: str, detail: str = ""):
        line = f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}\t{ip}\t{kind}\t{detail[:300]}\n"
        try:
            with _lock:
                with open(self.security_log, "a", encoding="utf-8") as fh:
                    fh.write(line)
        except OSError:
            pass

    def log_access(self, ip: str, method: str, path: str, status: int, size: int, ua: str):
        self.ip_counts[ip] += 1
        line = "\t".join([
            datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            ip, method, path[:200], str(status), str(size), (ua or "")[:120],
        ]) + "\n"
        try:
            with _lock:
                if self.access_log.exists() and self.access_log.stat().st_size > 50 * 1024 * 1024:
                    os.replace(self.access_log, str(self.access_log) + ".1")
                with open(self.access_log, "a", encoding="utf-8") as fh:
                    fh.write(line)
        except OSError:
            pass

    # ---------- bans ----------

    def _load_bans(self) -> dict:
        path = self.base / "bans.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return {str(k): float(v) for k, v in data.items() if float(v) > _now()}
        except Exception:
            return {}

    def save_bans(self):
        try:
            tmp = self.base / "bans.json.tmp"
            tmp.write_text(json.dumps(self.bans), encoding="utf-8")
            os.replace(tmp, self.base / "bans.json")
        except OSError:
            pass

    def is_banned(self, ip: str) -> bool:
        with _lock:
            until = self.bans.get(ip)
            if not until:
                return False
            if until > _now():
                return True
            self.bans.pop(ip, None)
            return False

    def ban(self, ip: str, reason: str, seconds: int | None = None, block_fw: bool = False):
        seconds = int(seconds or self.config.get("ban_ttl", 3600))
        with _lock:
            self.bans[ip] = _now() + seconds
            self.save_bans()
        self.stats["bans"] += 1
        self.log_security("ban", ip, f"{reason} / {seconds}s")
        if block_fw:
            firewall_block(ip)
            self.log_security("firewall-block", ip, "rule added")

    def unban(self, ip: str):
        with _lock:
            self.bans.pop(ip, None)
            self.save_bans()
        self.log_security("unban", ip)
        firewall_unblock(ip)

    # ---------- sessions / challenges ----------

    def group_list(self) -> list[dict]:
        return [g for g in self.config.get("challenge_groups", [])
                if g.get("enabled", True)]

    def start(self, ip: str, next_path: str = "/") -> dict:
        groups = self.group_list()
        if not groups:
            return {"done": True, "redirect": next_path}
        with _lock:
            active = sum(1 for s in self.sessions.values() if s["ip"] == ip)
        if active >= int(self.config.get("pending_max", 10)):
            self.ban(ip, "too-many-sessions")
            return {"error": "too many sessions"}
        sid = secrets.token_urlsafe(18)
        sess = {
            "ip": ip,
            "groups": groups,
            "gi": 0,
            "count": 0,
            "next": next_path,
            "expires": _now() + float(self.config.get("pending_ttl", 30)),
            "fails": 0,
            "challenge": None,
        }
        self.sessions[sid] = sess
        return {"sid": sid, **self._issue(sess)}

    def _issue(self, sess: dict) -> dict:
        group = sess["groups"][sess["gi"]]
        try:
            ch = build_challenge(group, self.pool)
        except Exception as exc:  # noqa: BLE001
            self.log_security("challenge-error", sess["ip"], repr(exc))
            return {"error": "challenge error"}
        sess["challenge"] = ch
        sess["expires"] = _now() + float(self.config.get("pending_ttl", 30))
        return {
            "done": False,
            "group": group.get("id", sess["gi"]),
            "index": sess["count"] + 1,
            "total": int(group.get("count", 1)),
            "challenge": ch,
        }

    def answer(self, sid: str, answer):
        sess = self.sessions.get(sid)
        if not sess:
            return {"error": "unknown or expired session"}
        if sess["expires"] < _now():
            self.sessions.pop(sid, None)
            self.ban(sess["ip"], "challenge-timeout")
            return {"error": "expired"}
        ok, detail = verify_challenge(sess["challenge"], answer)
        if not ok:
            sess["fails"] += 1
            self.stats["challenge_fail"] += 1
            if sess["fails"] > int(self.config.get("fail_max", 5)):
                self.ban(sess["ip"], "challenge-fail")
                self.sessions.pop(sid, None)
                return {"error": "too many failures"}
            return {"error": "wrong answer", "detail": detail}
        self.stats["challenge_pass"] += 1
        group = sess["groups"][sess["gi"]]
        sess["count"] += 1
        if sess["count"] < int(group.get("count", 1)):
            return self._issue(sess)
        sess["gi"] += 1
        sess["count"] = 0
        if sess["gi"] >= len(sess["groups"]):
            self.sessions.pop(sid, None)
            return {"done": True, "redirect": sess["next"]}
        return self._issue(sess)

    def cleanup(self):
        now = _now()
        with _lock:
            for sid in [s for s, v in self.sessions.items() if v["expires"] < now]:
                sess = self.sessions.pop(sid, None)
                if sess:
                    self.ban(sess["ip"], "challenge-timeout")
            for ip in [i for i, dq in self.rate.items()
                       if not dq or dq[-1] < now - float(self.config.get("rate_window", 10))]:
                self.rate.pop(ip, None)
            for ip in [i for i, until in self.bans.items() if until < now]:
                self.bans.pop(ip, None)


STATE: State | None = None


# ---------------------------------------------------------------- firewall / syn

def firewall_block(ip: str):
    if os.name != "nt" or not ip:
        return
    if ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
                      "172.19.", "172.2", "172.30.", "172.31.")):
        return
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=CADP-block-{ip}", "dir=in", "action=block",
             "protocol=TCP", f"localport={STATE.config['listen_port']}",
             f"remoteip={ip}"],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass


def firewall_unblock(ip: str):
    if os.name != "nt" or not ip:
        return
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name=CADP-block-{ip}"],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.c_ulong),
        ("dwLocalAddr", ctypes.c_ulong),
        ("dwLocalPort", ctypes.c_ulong),
        ("dwRemoteAddr", ctypes.c_ulong),
        ("dwRemotePort", ctypes.c_ulong),
        ("dwOwningPid", ctypes.c_ulong),
    ]


def _tcp_rows_windows() -> list:
    try:
        iphlpapi = ctypes.windll.iphlpapi
        size = ctypes.c_ulong(0)
        iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, 2, 5, 0)
        if size.value <= 0:
            return []
        buf = ctypes.create_string_buffer(size.value)
        ret = iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, 2, 5, 0)
        if ret != 0:
            return []
        n = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ulong)).contents.value
        return list((MIB_TCPROW_OWNER_PID * n).from_buffer(buf, 4))
    except Exception:
        return []


def _tcp_rows_linux() -> list:
    rows = []
    for path in ("/proc/net/tcp",):
        try:
            lines = Path(path).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            local, remote, state = parts[1], parts[2], parts[3]
            try:
                lip, lport = local.split(":")
                rip, rport = remote.split(":")
                if len(rip) != 8:
                    continue  # IPv4 only for this lightweight monitor
                ip = socket.inet_ntoa(struct.pack("<L", int(rip, 16)))
                rows.append((int(state, 16), int(lport, 16), ip))
            except ValueError:
                continue
    return rows


def syn_monitor():
    cfg = STATE.config.get("syn", {})
    if not cfg.get("enabled", True):
        return
    port = int(STATE.config["listen_port"])
    syn_limit = int(cfg.get("syn_threshold", 10))
    est_limit = int(cfg.get("est_threshold", 24))
    while True:
        time.sleep(2)
        try:
            if os.name == "nt":
                syn, est = Counter(), Counter()
                for row in _tcp_rows_windows():
                    if socket.ntohs(row.dwLocalPort & 0xFFFF) != port:
                        continue
                    state = int(row.dwState)
                    if state == 4:
                        syn[socket.inet_ntoa(struct.pack("<L", row.dwRemoteAddr))] += 1
                    elif state == 5:
                        est[socket.inet_ntoa(struct.pack("<L", row.dwRemoteAddr))] += 1
            else:
                syn, est = Counter(), Counter()
                for state, lport, ip in _tcp_rows_linux():
                    if lport != port:
                        continue
                    if state == 0x03:
                        syn[ip] += 1
                    elif state == 0x01:
                        est[ip] += 1
            for ip, n in syn.items():
                if n >= syn_limit and not STATE.is_banned(ip):
                    STATE.ban(ip, f"syn-flood/{n}", block_fw=bool(cfg.get("block_firewall", True)))
            for ip, n in est.items():
                if n >= est_limit and not STATE.is_banned(ip):
                    STATE.ban(ip, f"conn-flood/{n}", block_fw=bool(cfg.get("block_firewall", True)))
        except Exception:
            continue


# ---------------------------------------------------------------- HTML

def challenge_html() -> str:
    return r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CADP · 正在验证</title>
<style>
body{margin:0;background:#0b1020;color:#e8eefc;font:15px/1.7 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;
display:flex;min-height:100vh;align-items:center;justify-content:center}
.box{max-width:560px;padding:28px;border:1px solid #26304a;border-radius:16px;background:#121a2e}
h1{font-size:20px;margin:0 0 6px}.muted{color:#8b9ab5;font-size:13px}
#status{margin:14px 0;padding:10px 12px;border-radius:10px;background:#0d1528;border:1px solid #26304a;font-size:13px}
.bar{height:6px;background:#1b2540;border-radius:99px;overflow:hidden;margin:12px 0}
.bar i{display:block;height:100%;background:linear-gradient(90deg,#4f8cff,#62e0c3);width:0}
code{background:#1a2440;padding:1px 6px;border-radius:5px}
</style></head><body><div class="box">
<h1>CADP · Challenge</h1>
<p class="muted">首次访问需完成少量计算（通常 1–5 秒）。通过后 1 小时内免验证。</p>
<div class="bar"><i id="bar"></i></div>
<div id="status">正在初始化…</div>
<noscript><p style="color:#ffb454">需要启用 JavaScript。</p></noscript>
</div>
<script>
(function(){
  const qs = new URLSearchParams(location.search);
  const next = qs.get('next') || '/';
  const status = document.getElementById('status');
  const bar = document.getElementById('bar');

  function fnv(s){var h=2166136261>>>0;for(var i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619)>>>0;}return h>>>0;}

  async function start(){
    const r = await fetch('/__cadp/api/start', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({next})});
    const d = await r.json();
    if (d.done) { location.href = d.redirect || next; return; }
    if (d.error) throw new Error(d.error);
    await run(d.sid, d);
  }

  async function answer(sid, ans){
    const r = await fetch('/__cadp/api/answer', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sid, answer: ans})});
    return await r.json();
  }

  async function run(sid, d){
    for(;;){
      if(d.error) throw new Error(d.error);
      if(d.done){ location.href = d.redirect || next; return; }
      const ch = d.challenge;
      const group = d.group, idx = d.index, total = d.total;
      status.textContent = `[${group}] ${idx}/${total} · ${ch.type}`;
      bar.style.width = ((idx-1)/Math.max(1,total)*100) + '%';

      let ans;
      if (ch.type === 'pow_fnv' || ch.type === 'mine' || ch.type === 'pow_hard'){
        const target = Math.floor(4294967296 / Math.pow(2, ch.bits));
        const base = ch.id + ch.salt;
        let n = 0;
        while (fnv(base + n) >= target) n++;
        ans = n;
      } else if (ch.type === 'linear_train'){
        let w1 = 0, w2 = 0, b = 0;
        const X = ch.X, Y = ch.y, lr = ch.lr, epochs = ch.epochs;
        for (let e = 0; e < epochs; e++){
          for (let j = 0; j < X.length; j++){
            const pred = w1*X[j][0] + w2*X[j][1] + b;
            const err = pred - Y[j];
            w1 -= lr * err * X[j][0];
            w2 -= lr * err * X[j][1];
            b  -= lr * err;
          }
        }
        ans = [w1, w2, b];
      } else if (ch.type === 'arith'){
        ans = eval(ch.expr);
      } else {
        throw new Error('unsupported challenge: ' + ch.type);
      }
      const res = await answer(sid, ans);
      if (res.error) throw new Error(res.error);
      d = res;
    }
  }

  start().catch(err => { status.textContent = '验证失败：' + err.message + '（可刷新重试）'; });
})();
</script></body></html>"""


def admin_login_html() -> str:
    return """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>CADP Admin</title><style>
body{margin:0;background:#0b1020;color:#e8eefc;font:15px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;
display:flex;min-height:100vh;align-items:center;justify-content:center}
.box{width:360px;padding:26px;border:1px solid #26304a;border-radius:14px;background:#121a2e}
h1{margin:0 0 14px;font-size:19px}input{width:100%;padding:10px;border-radius:8px;border:1px solid #2b3655;background:#0d1528;color:#e8eefc;margin:6px 0 12px}
button{width:100%;padding:10px;border:0;border-radius:8px;background:#4f8cff;color:#06101f;font-weight:700;cursor:pointer}
</style></head><body><div class="box">
<h1>CADP Admin</h1>
<form method="post" action="/__cadp/admin/login">
<input type="password" name="password" placeholder="Admin password" autofocus>
<button type="submit">登录</button>
</form></div></body></html>"""


def admin_dashboard_html() -> str:
    return r"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CADP Admin</title><style>
body{margin:0;background:#0b1020;color:#e8eefc;font:14px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 4px}.muted{color:#8b9ab5}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}
.card{padding:14px;border:1px solid #26304a;border-radius:12px;background:#121a2e}
.card b{display:block;font-size:22px}.ok{color:#62e0c3}.warn{color:#ffb454}.bad{color:#ff6b8a}
section{margin:20px 0;padding:16px;border:1px solid #26304a;border-radius:12px;background:#121a2e}
textarea{width:100%;min-height:240px;background:#0d1528;color:#dbe9ff;border:1px solid #2b3655;border-radius:8px;padding:10px;font-family:Consolas,monospace;font-size:12px}
button{padding:8px 12px;border:0;border-radius:8px;background:#4f8cff;color:#06101f;font-weight:700;cursor:pointer;margin:4px 6px 4px 0}
button.ghost{background:#1b2540;color:#dbe9ff;border:1px solid #2b3655}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid #1e2740}th{color:#8b9ab5}
input{padding:8px;border-radius:8px;border:1px solid #2b3655;background:#0d1528;color:#e8eefc}
</style></head><body><div class="wrap">
<h1>CADP Admin</h1><div class="muted">Challenge Anti DDoS + · <span id="ver"></span></div>
<div class="grid">
<div class="card"><span class="muted">Requests</span><b id="s-req">0</b></div>
<div class="card"><span class="muted">Challenge passes</span><b class="ok" id="s-pass">0</b></div>
<div class="card"><span class="muted">Active bans</span><b class="bad" id="s-bans">0</b></div>
<div class="card"><span class="muted">Groups</span><b id="s-groups">0</b></div>
</div>
<section><h3>Ban / Unban</h3>
<input id="ip" placeholder="1.2.3.4"><button onclick="ban()">Ban</button>
<button class="ghost" onclick="unban()">Unban</button>
<table><thead><tr><th>IP</th><th>Until</th><th></th></tr></thead><tbody id="bans"></tbody></table>
</section>
<section><h3>Config</h3>
<textarea id="cfg"></textarea><br>
<button onclick="saveCfg()">保存配置</button>
<span class="muted" id="cfgmsg"></span>
</section>
<section><h3>Top IPs</h3><table><thead><tr><th>IP</th><th>Requests</th></tr></thead><tbody id="tops"></tbody></table></section>
<script>
async function j(url, opts){ const r = await fetch(url, opts); return await r.json(); }
async function load(){
  const s = await j('/__cadp/admin/api/stats');
  document.getElementById('ver').textContent = s.version || '';
  document.getElementById('s-req').textContent = s.stats.requests || 0;
  document.getElementById('s-pass').textContent = s.stats.challenge_pass || 0;
  document.getElementById('s-bans').textContent = s.bans.length;
  document.getElementById('s-groups').textContent = s.groups;
  document.getElementById('bans').innerHTML = s.bans.map(b =>
    `<tr><td>${b.ip}</td><td>${new Date(b.until*1000).toLocaleString()}</td><td><button class="ghost" onclick="unbanIp('${b.ip}')">解封</button></td></tr>`).join('');
  document.getElementById('tops').innerHTML = s.top_ips.map(t => `<tr><td>${t.ip}</td><td>${t.count}</td></tr>`).join('');
  const c = await j('/__cadp/admin/api/config');
  document.getElementById('cfg').value = JSON.stringify(c, null, 2);
}
async function ban(){ const ip=document.getElementById('ip').value.trim(); if(!ip)return;
  await j('/__cadp/admin/api/ban',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,seconds:3600})}); load(); }
async function unban(){ const ip=document.getElementById('ip').value.trim(); if(!ip)return; await unbanIp(ip); }
async function unbanIp(ip){ await j('/__cadp/admin/api/unban',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})}); load(); }
async function saveCfg(){ try{ const c=JSON.parse(document.getElementById('cfg').value);
  await j('/__cadp/admin/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(c)});
  document.getElementById('cfgmsg').textContent='已保存'; load();
}catch(e){ document.getElementById('cfgmsg').textContent='JSON 错误: '+e.message; } }
load();
</script></div></body></html>"""


# ---------------------------------------------------------------- handler

class Handler(http.server.BaseHTTPRequestHandler):
    timeout = 15

    def __init__(self, *args, **kwargs):
        self._logged = False
        super().__init__(*args, **kwargs)

    def log_message(self, fmt, *args):
        pass

    # ---------- helpers ----------

    def _ip(self) -> str:
        return self.client_address[0]

    def _cookie(self, name: str) -> str:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith(name + "="):
                return part[len(name) + 1:]
        return ""

    def _send(self, code: int, body: bytes, ctype: str, *, head: bool = False,
              headers: list[tuple[str, str]] | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in headers or []:
            self.send_header(key, value)
        self.end_headers()
        if not head:
            self.wfile.write(body)
        self._log_once(code, len(body))

    def _json(self, data, code: int = 200, headers: list[tuple[str, str]] | None = None):
        body = json.dumps(data, ensure_ascii=False).encode()
        self._send(code, body, "application/json; charset=utf-8", headers=headers)

    def _read_json(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(min(n, 1024 * 1024)) if n else b"{}"
            return json.loads(raw.decode() or "{}")
        except Exception:
            return {}

    def _redirect(self, location: str, cookie: str | None = None):
        self.send_response(302)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()
        self._log_once(302, 0)

    def _log_once(self, status: int, size: int):
        if getattr(self, "_logged", False):
            return
        self._logged = True
        try:
            STATE.log_access(self._ip(), self.command or "-", self.path or "-",
                             status, size, self.headers.get("User-Agent") or "")
        except Exception:
            pass

    def _has_pass(self) -> bool:
        token = self._cookie("cadp_pass")
        return bool(token) and STATE.verify_pass(token, self._ip())

    def _admin(self) -> bool:
        return STATE.admin_ok(self._cookie("cadp_admin"))

    def _static(self, path: str, head: bool = False):
        rel = "index.html" if path in ("", "/") else path.lstrip("/")
        target = (STATE.root / rel).resolve()
        try:
            target.relative_to(STATE.root)
        except ValueError:
            self.send_error(403)
            return
        if not target.is_file():
            self.send_error(404)
            return
        ctype, _ = mimetypes.guess_type(str(target))
        body = target.read_bytes()
        self._send(200, body, ctype or "application/octet-stream", head=head)

    # ---------- routes ----------

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        ip = self._ip()
        STATE.stats["requests"] += 1

        if STATE.is_banned(ip):
            self.close_connection = True
            return
        if path in ("/__cadp", "/__cadp/"):
            if self._has_pass():
                self._redirect("/")
            else:
                self._send(200, challenge_html().encode(), "text/html; charset=utf-8")
            return
        if path == "/__cadp/admin":
            if self._admin():
                self._send(200, admin_dashboard_html().encode(), "text/html; charset=utf-8")
            else:
                self._send(200, admin_login_html().encode(), "text/html; charset=utf-8")
            return
        if path.startswith("/__cadp/admin/api/"):
            if not self._admin():
                self._json({"error": "unauthorized"}, 401)
                return
            self._admin_api(path, parsed)
            return
        if path == "/__cadp/admin/logout":
            self._redirect("/__cadp/admin", "cadp_admin=; Path=/; Max-Age=0; HttpOnly")
            return
        if path.startswith("/__cadp/api/"):
            self._json({"error": "use POST"}, 405)
            return

        if not self._has_pass():
            self._redirect("/__cadp?next=" + quote(path or "/"))
            return
        if path.startswith("/__cadp/"):
            self.send_error(404)
            return
        self._static(path)

    def do_HEAD(self):
        path = urlparse(self.path).path
        if not self._has_pass() or STATE.is_banned(self._ip()):
            self.send_error(403)
            return
        self._static(path, head=True)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        ip = self._ip()
        STATE.stats["requests"] += 1
        if STATE.is_banned(ip):
            self.close_connection = True
            return

        if path == "/__cadp/api/start":
            if self._has_pass():
                self._json({"done": True, "redirect": "/"})
                return
            data = self._read_json()
            nxt = data.get("next") or "/"
            if not isinstance(nxt, str) or not nxt.startswith("/") or nxt.startswith("//"):
                nxt = "/"
            # simple per-IP rate check
            now = _now()
            with _lock:
                dq = STATE.rate[ip]
                while dq and dq[0] < now - float(STATE.config.get("rate_window", 10)):
                    dq.popleft()
                dq.append(now)
                too_many = len(dq) > int(STATE.config.get("rate_max", 30))
            if too_many:
                STATE.ban(ip, "rate-limit")
                self._json({"error": "rate limited"}, 429)
                return
            result = STATE.start(ip, nxt)
            if result.get("done"):
                self._json(result)
            else:
                self._json(result)
            return

        if path == "/__cadp/api/answer":
            data = self._read_json()
            sid = str(data.get("sid") or "")
            result = STATE.answer(sid, data.get("answer"))
            if result.get("done"):
                cookie = (f"cadp_pass={STATE.make_pass(ip)}; Path=/; "
                          f"Max-Age={int(STATE.config.get('pass_ttl', 3600))}; "
                          "HttpOnly; SameSite=Lax")
                self._json(result, 200, [("Set-Cookie", cookie)])
                return
            self._json(result)
            return

        if path == "/__cadp/admin/login":
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(min(n, 4096)).decode(errors="replace")
            password = (parse_qs(raw).get("password") or [""])[0]
            admin = STATE.config.get("admin", {})
            if _verify_password(password, admin.get("password_hash", "")):
                cookie = (f"cadp_admin={STATE.admin_token()}; Path=/; "
                          f"Max-Age={int(admin.get('session_ttl', 3600))}; HttpOnly; SameSite=Strict")
                self._redirect("/__cadp/admin", cookie)
            else:
                self._redirect("/__cadp/admin")
            return

        if path.startswith("/__cadp/admin/api/"):
            if not self._admin():
                self._json({"error": "unauthorized"}, 401)
                return
            self._admin_api(path, parsed)
            return

        self._json({"error": "not found"}, 404)

    # ---------- admin api ----------

    def _admin_api(self, path: str, parsed):
        if path == "/__cadp/admin/api/stats":
            with _lock:
                bans = [{"ip": ip, "until": until} for ip, until in STATE.bans.items()
                        if until > _now()]
            self._json({
                "version": __version__,
                "stats": {
                    "requests": STATE.stats.get("requests", 0),
                    "challenge_pass": STATE.stats.get("challenge_pass", 0),
                    "challenge_fail": STATE.stats.get("challenge_fail", 0),
                    "bans": len(bans),
                },
                "bans": bans,
                "groups": len(STATE.group_list()),
                "top_ips": [{"ip": ip, "count": c}
                            for ip, c in STATE.ip_counts.most_common(10)],
            })
            return
        if path == "/__cadp/admin/api/config":
            if self.command == "GET":
                self._json(STATE.config)
            else:
                data = self._read_json()
                if not isinstance(data, dict):
                    self._json({"error": "bad config"}, 400)
                    return
                # never drop the admin password hash by saving an incomplete config
                if not data.get("admin", {}).get("password_hash"):
                    data.setdefault("admin", {})["password_hash"] = \
                        STATE.config.get("admin", {}).get("password_hash", "")
                STATE.config = _merge(DEFAULT_CONFIG, data)
                _save_config(STATE.config_path, STATE.config)
                self._json({"ok": True})
            return
        if path == "/__cadp/admin/api/bans":
            self._json([{"ip": ip, "until": until} for ip, until in STATE.bans.items()])
            return
        if path == "/__cadp/admin/api/ban":
            data = self._read_json()
            ip = str(data.get("ip") or "").strip()
            if not ip:
                self._json({"error": "ip required"}, 400)
                return
            STATE.ban(ip, "admin", int(data.get("seconds") or 3600))
            self._json({"ok": True})
            return
        if path == "/__cadp/admin/api/unban":
            data = self._read_json()
            ip = str(data.get("ip") or "").strip()
            if ip:
                STATE.unban(ip)
            self._json({"ok": True})
            return
        self._json({"error": "not found"}, 404)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._sem = threading.BoundedSemaphore(64)

    def process_request(self, request, client_address):
        if not self._sem.acquire(blocking=False):
            try:
                request.close()
            except Exception:
                pass
            return
        super().process_request(request, client_address)

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            self._sem.release()


def _cleanup_thread():
    while True:
        time.sleep(2)
        try:
            STATE.cleanup()
        except Exception:
            pass


def init_config(path: Path, port: int, root: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        cfg = _load_config(path)
    else:
        example = path.parent / "config.example.json"
        data = {}
        if example.exists():
            try:
                data = json.loads(example.read_text(encoding="utf-8"))
            except Exception:
                data = {}
        cfg = _merge(DEFAULT_CONFIG, data)
    cfg["listen_port"] = port
    cfg["root"] = root
    admin = cfg.setdefault("admin", {})
    if not admin.get("password_hash"):
        password = secrets.token_urlsafe(12)
        admin["password_hash"] = _hash_password(password)
        (path.parent / "ADMIN_PASSWORD.txt").write_text(password, encoding="utf-8")
        print(f"Admin password: {password}")
    _save_config(path, cfg)
    print(f"Config written: {path}")


def main(argv=None):
    global STATE
    ap = argparse.ArgumentParser(description="CADP — Challenge Anti DDoS +")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--init-config", action="store_true")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--root", default="site")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    config_path = Path(args.config).resolve()
    if args.init_config:
        init_config(config_path, args.port, args.root)
        return 0

    if not config_path.exists():
        init_config(config_path, args.port, args.root)
    STATE = State(config_path)

    threading.Thread(target=_cleanup_thread, daemon=True).start()
    threading.Thread(target=syn_monitor, daemon=True).start()

    host = STATE.config.get("listen_host", "0.0.0.0")
    port = int(STATE.config.get("listen_port", 8080))
    with Server((host, port), Handler) as httpd:
        print(f"CADP {__version__} listening on http://{host}:{port} (root={STATE.root})")
        print(f"Admin: http://{host}:{port}/__cadp/admin")
        httpd.serve_forever()


if __name__ == "__main__":
    raise SystemExit(main())
