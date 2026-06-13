#!/usr/bin/env python3
"""Add Irancell-optimized inbounds to a 3x-ui panel via its HTTP API (localhost).

Run this ON the panel server. It:
  * reads the panel's port / base-path straight from the x-ui SQLite DB,
  * reuses the FULL existing client objects (id, email, subId, limits, ...)
    pulled from a current inbound, so the new inbounds show up in the same
    users' subscriptions and respect their limits,
  * adds the new inbounds through the panel API, so the panel writes the DB
    correctly (client_traffics, tags, GUI visibility) instead of hand-editing.

Inbounds added (ports auto-picked to avoid DB inbounds AND host-bound ports):
  * VLESS + Reality + Vision (TCP)   -- direct to IP, bypasses CDN + SNI throttle
  * VLESS + Reality + gRPC
  * VLESS + mKCP (srtp header)       -- rides Irancell's UDP/video-call QoS
  * VLESS + mKCP (wireguard header)

Credentials are read from the environment so they are never written to disk:
    XUI_PANEL_USERNAME, XUI_PANEL_PASSWORD   (required)
    XUI_PANEL_SECRET                         (only if your panel login needs it)
Optional:
    IR_SERVER_ADDR   address used in printed share links (default: detected IP)
    IR_REALITY_SNI   borrowed SNI for Reality (default: www.datadoghq.com)
    XUI_DB_PATH      default: /etc/x-ui/x-ui.db

Pure Python 3 stdlib only.
"""

import base64
import json
import os
import re
import secrets
import sqlite3
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from urllib.parse import quote, urlencode


def _clean_sni(value: str) -> str:
    value = value.strip()
    m = re.match(r"^\[([^\]]+)\]\((?:https?://)?[^)]*\)$", value)
    if m:
        value = m.group(1)
    return re.sub(r"^https?://", "", value).strip().strip("/")


REALITY_SNI = _clean_sni(os.getenv("IR_REALITY_SNI", "www.datadoghq.com"))
DB_PATH = os.getenv("XUI_DB_PATH", "/etc/x-ui/x-ui.db")

# --------------------------------------------------------------------------- #
# X25519 (RFC 7748), pure Python -- matches `xray x25519`                      #
# --------------------------------------------------------------------------- #
_P = 2 ** 255 - 19


def _x25519(scalar: bytes, u_coord: bytes) -> bytes:
    def clamp(k):
        b = bytearray(k)
        b[0] &= 248
        b[31] &= 127
        b[31] |= 64
        return int.from_bytes(b, "little")

    u = bytearray(u_coord)
    u[31] &= 127
    x1 = int.from_bytes(u, "little")
    k = clamp(scalar)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = pow((da + cb) % _P, 2, _P)
        z3 = (x1 * pow((da - cb) % _P, 2, _P)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * ((aa + (121665 * e) % _P) % _P)) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, _P - 2, _P)) % _P).to_bytes(32, "little")


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def reality_keypair():
    priv = bytearray(secrets.token_bytes(32))
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    pub = _x25519(bytes(priv), b"\x09" + b"\x00" * 31)
    return _b64url(bytes(priv)), _b64url(pub)


# --------------------------------------------------------------------------- #
# Host / DB helpers                                                            #
# --------------------------------------------------------------------------- #

def os_listening_ports():
    ports = set()
    try:
        out = subprocess.run(["ss", "-tuln"], capture_output=True, text=True, timeout=8).stdout
    except Exception:
        return ports
    for line in out.splitlines()[1:]:
        f = line.split()
        if len(f) >= 2:
            m = re.search(r":(\d+)$", f[-2])
            if m:
                ports.add(int(m.group(1)))
    return ports


def detect_public_ip():
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=8) as r:
                ip = r.read().decode().strip()
                if ip:
                    return ip
        except Exception:
            continue
    return "YOUR_SERVER_IP"


def read_db():
    """Return (web_port, base_path, db_ports, clients) from the x-ui DB."""
    con = sqlite3.connect(DB_PATH)
    try:
        def setting(key):
            r = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return r[0] if r else None

        web_port = setting("webPort") or "2053"
        base_path = setting("webBasePath") or "/"
        if not base_path.startswith("/"):
            base_path = "/" + base_path
        if not base_path.endswith("/"):
            base_path += "/"

        rows = con.execute("SELECT port, protocol, settings, enable FROM inbounds").fetchall()
    finally:
        con.close()

    db_ports = {int(p) for p, *_ in rows if isinstance(p, int) or str(p).isdigit()}

    best = []
    for port, proto, settings_str, enable in rows:
        if proto != "vless" or not settings_str:
            continue
        try:
            clients = json.loads(settings_str).get("clients", [])
        except json.JSONDecodeError:
            continue
        if enable and len(clients) > len(best):
            best = clients
    return web_port, base_path, db_ports, best


# --------------------------------------------------------------------------- #
# Inbound builders (panel API payload format)                                  #
# --------------------------------------------------------------------------- #
SNIFF = {"enabled": True, "destOverride": ["http", "tls", "quic"]}


def _clients_for(base_clients, *, flow):
    """Copy full client objects (keeps subId/limits/etc.), set the right flow."""
    out = []
    for c in base_clients:
        nc = dict(c)
        nc["flow"] = flow
        out.append(nc)
    return out


def _payload(remark, port, settings, stream):
    return {
        "up": 0, "down": 0, "total": 0, "remark": remark, "enable": True,
        "expiryTime": 0, "listen": "", "port": port, "protocol": "vless",
        "settings": json.dumps({"clients": settings, "decryption": "none", "fallbacks": []},
                               ensure_ascii=False),
        "streamSettings": json.dumps(stream, ensure_ascii=False),
        "sniffing": json.dumps(SNIFF, ensure_ascii=False),
    }


def _reality_stream(network_block, priv, pub):
    sid = secrets.token_hex(8)
    s = {
        "security": "reality",
        "realitySettings": {
            "show": False, "xver": 0, "dest": f"{REALITY_SNI}:443",
            "serverNames": [REALITY_SNI], "privateKey": priv, "shortIds": [sid],
            "settings": {"publicKey": pub, "fingerprint": "chrome", "serverName": "", "spiderX": "/"},
        },
    }
    s.update(network_block)
    return s, sid


def _mkcp_stream(header, seed):
    return {
        "network": "kcp", "security": "none",
        "kcpSettings": {
            "mtu": 1350, "tti": 50, "uplinkCapacity": 12, "downlinkCapacity": 100,
            "congestion": True, "readBufferSize": 2, "writeBufferSize": 2,
            "header": {"type": header}, "seed": seed,
        },
    }


def build(base_clients, pick):
    payloads, meta = [], []

    priv, pub = reality_keypair()
    stream, sid = _reality_stream({"network": "tcp"}, priv, pub)
    port = pick(9443)
    payloads.append(_payload("IR-Reality-Vision", port,
                             _clients_for(base_clients, flow="xtls-rprx-vision"), stream))
    meta.append((port, "reality-vision", {"pbk": pub, "sid": sid, "flow": "xtls-rprx-vision"}))

    priv, pub = reality_keypair()
    stream, sid = _reality_stream(
        {"network": "grpc", "grpcSettings": {"serviceName": "irancell-grpc", "multiMode": True}},
        priv, pub)
    port = pick(8444)
    payloads.append(_payload("IR-Reality-gRPC", port, _clients_for(base_clients, flow=""), stream))
    meta.append((port, "reality-grpc", {"pbk": pub, "sid": sid, "serviceName": "irancell-grpc"}))

    seed = secrets.token_hex(6)
    port = pick(2097)
    payloads.append(_payload("IR-mKCP-srtp", port, _clients_for(base_clients, flow=""),
                             _mkcp_stream("srtp", seed)))
    meta.append((port, "mkcp", {"headerType": "srtp", "seed": seed}))

    seed = secrets.token_hex(6)
    port = pick(2098)
    payloads.append(_payload("IR-mKCP-wireguard", port, _clients_for(base_clients, flow=""),
                             _mkcp_stream("wireguard", seed)))
    meta.append((port, "mkcp", {"headerType": "wireguard", "seed": seed}))

    return payloads, meta


def share_link(addr, cid, port, kind, p):
    tag = quote(f"IR-{kind}")
    if kind == "reality-vision":
        q = (f"type=tcp&security=reality&flow={p['flow']}&sni={REALITY_SNI}"
             f"&pbk={p['pbk']}&sid={p['sid']}&fp=chrome&spx=%2F")
    elif kind == "reality-grpc":
        q = (f"type=grpc&serviceName={quote(p['serviceName'])}&mode=multi&security=reality"
             f"&sni={REALITY_SNI}&pbk={p['pbk']}&sid={p['sid']}&fp=chrome")
    else:
        q = f"type=kcp&headerType={p['headerType']}&seed={quote(p['seed'])}&security=none"
    return f"vless://{cid}@{addr}:{port}?{q}#{tag}"


# --------------------------------------------------------------------------- #

def main():
    user = os.getenv("XUI_PANEL_USERNAME", "")
    pw = os.getenv("XUI_PANEL_PASSWORD", "")
    secret = os.getenv("XUI_PANEL_SECRET", "")
    if not user or not pw:
        sys.exit("Set XUI_PANEL_USERNAME and XUI_PANEL_PASSWORD.")

    web_port, base_path, db_ports, base_clients = read_db()
    if not base_clients:
        sys.exit("Could not read existing clients from the DB.")

    used = set(db_ports) | os_listening_ports()

    def pick(pref):
        p = pref
        while p in used or p > 65535:
            p += 1
        used.add(p)
        return p

    payloads, meta = build(base_clients, pick)

    base = f"https://127.0.0.1:{web_port}{base_path}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(CookieJar()),
        urllib.request.HTTPSHandler(context=ctx),
    )

    def post(path, form=None, body=None):
        data, ctype = ((urlencode(form).encode(), "application/x-www-form-urlencoded")
                       if form is not None
                       else (json.dumps(body).encode(), "application/json"))
        req = urllib.request.Request(base + path, data=data,
                                     headers={"Content-Type": ctype, "Accept": "application/json"})
        try:
            with opener.open(req, timeout=20) as r:
                raw = r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
        except urllib.error.URLError as e:
            return {"success": False, "msg": f"connection error: {e.reason}"}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"success": False, "msg": raw[:200]}

    login_form = {"username": user, "password": pw}
    if secret:
        login_form["loginSecret"] = secret
    login = post("login", form=login_form)
    if not login.get("success"):
        sys.exit(f"Panel login failed: {login.get('msg', login)}")
    print(f"Logged in. Reusing {len(base_clients)} existing clients.")

    addr = os.getenv("IR_SERVER_ADDR") or detect_public_ip()
    sample = base_clients[0]["id"]
    links, added = [], 0
    for payload, (port, kind, p) in zip(payloads, meta):
        resp = post("panel/api/inbounds/add", body=payload)
        ok = bool(resp.get("success"))
        added += ok
        print(f"  {'OK ' if ok else 'ERR'} {payload['remark']} :{port} -> {str(resp.get('msg',''))[:100]}")
        if ok:
            links.append(f"# {payload['remark']} (port {port})\n{share_link(addr, sample, port, kind, p)}")

    print(f"\nDone: {added}/{len(payloads)} inbounds added.")
    if links:
        with open("irancell_share_links.txt", "w", encoding="utf-8") as f:
            f.write(f"# Server: {addr} -- any existing user's UUID works; swap per user.\n\n"
                    + "\n\n".join(links) + "\n")
        print("Sample links -> irancell_share_links.txt")
    print("Open firewall: 9443/tcp, 8444/tcp, 2097/udp, 2098/udp (adjust to the ports above).")


if __name__ == "__main__":
    main()
