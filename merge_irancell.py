#!/usr/bin/env python3
"""Merge Irancell-optimized inbounds into an existing Xray config.

The configs on this server already work on every operator except Irancell.
Irancell throttles them because they all ride TLS over the rimaex.com domains
(behind a CDN). This adds inbounds that take different paths Irancell does not
throttle as hard:

  * VLESS + Reality + Vision (raw TCP)  -- connects straight to the server IP
    with a borrowed foreign SNI, bypassing both the CDN and SNI throttling.
  * VLESS + Reality + gRPC              -- same, multiplexed.
  * VLESS + mKCP (srtp header)          -- UDP carrying a video-call header,
    which Irancell's QoS prioritises -> big speed gains.
  * VLESS + mKCP (wireguard header)     -- second UDP profile.

It reuses the EXISTING client list (so all current users work on the new
inbounds too) and picks ports that are not already taken. Output is the full,
merged Xray config -- paste it back into the panel's Xray Configuration and save.

Usage (on the server):
    python3 merge_irancell.py [INPUT] [OUTPUT]
        INPUT  default: /usr/local/x-ui/bin/config.json
        OUTPUT default: ./merged_config.json

Env overrides:
    IR_SERVER_ADDR   address clients dial for the new inbounds
                     (default: server's own public IP, auto-detected)
    IR_REALITY_SNI   borrowed SNI for Reality (default: www.datadoghq.com)

Pure Python 3 stdlib only.
"""

import base64
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.request
import uuid
from urllib.parse import quote


def _clean_sni(value: str) -> str:
    """Tolerate pasted markdown links etc.  '[host](https://host)' -> 'host'."""
    value = value.strip()
    m = re.match(r"^\[([^\]]+)\]\((?:https?://)?[^)]*\)$", value)
    if m:
        value = m.group(1)
    value = re.sub(r"^https?://", "", value).strip().strip("/")
    return value


REALITY_SNI = _clean_sni(os.getenv("IR_REALITY_SNI", "www.datadoghq.com"))


# --------------------------------------------------------------------------- #
# X25519 (RFC 7748), pure Python -- matches `xray x25519`                      #
# --------------------------------------------------------------------------- #

_P = 2 ** 255 - 19


def _x25519(scalar: bytes, u_coord: bytes) -> bytes:
    def clamp(k: bytes) -> int:
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


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def reality_keypair() -> tuple[str, str]:
    priv = bytearray(secrets.token_bytes(32))
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    pub = _x25519(bytes(priv), b"\x09" + b"\x00" * 31)
    return _b64url(bytes(priv)), _b64url(pub)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def detect_public_ip() -> str:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=8) as r:
                ip = r.read().decode().strip()
                if ip:
                    return ip
        except Exception:
            continue
    return "YOUR_SERVER_IP"


def extract_clients(inbounds: list) -> list:
    """Reuse the existing client list so current users work on new inbounds."""
    for inb in inbounds:
        if inb.get("protocol") == "vless":
            clients = inb.get("settings", {}).get("clients")
            if clients:
                return [{"id": c["id"], "email": c["email"]} for c in clients]
    return []


def os_listening_ports() -> set:
    """Ports already bound on the host (nginx, sshd, ...), via `ss`."""
    ports = set()
    try:
        out = subprocess.run(["ss", "-tuln"], capture_output=True, text=True, timeout=8).stdout
    except Exception:
        return ports
    for line in out.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2:
            m = re.search(r":(\d+)$", fields[-2])
            if m:
                ports.add(int(m.group(1)))
    return ports


def port_picker(used: set):
    def pick(preferred: int) -> int:
        p = preferred
        while p in used or p > 65535:
            p += 1
        used.add(p)
        return p
    return pick


SNIFF = {"enabled": True, "destOverride": ["http", "tls", "quic"]}


def build_inbounds(clients: list, pick) -> tuple[list, list]:
    inbounds, meta = [], []

    # 1) VLESS + Reality + Vision (raw TCP)
    priv, pub = reality_keypair()
    sid = secrets.token_hex(8)
    port = pick(9443)
    vision_clients = [dict(c, flow="xtls-rprx-vision") for c in clients]
    inbounds.append({
        "listen": "0.0.0.0", "port": port, "protocol": "vless",
        "settings": {"clients": vision_clients, "decryption": "none"},
        "streamSettings": {
            "network": "tcp", "security": "reality",
            "realitySettings": {
                "show": False, "dest": f"{REALITY_SNI}:443", "xver": 0,
                "serverNames": [REALITY_SNI], "privateKey": priv, "shortIds": [sid],
            },
        },
        "sniffing": SNIFF, "tag": f"ir-reality-vision-{port}",
    })
    meta.append(("Reality-Vision-TCP", port, "reality-vision",
                 {"pbk": pub, "sid": sid, "flow": "xtls-rprx-vision"}))

    # 2) VLESS + Reality + gRPC
    priv, pub = reality_keypair()
    sid = secrets.token_hex(8)
    port = pick(8444)
    svc = "irancell-grpc"
    inbounds.append({
        "listen": "0.0.0.0", "port": port, "protocol": "vless",
        "settings": {"clients": list(clients), "decryption": "none"},
        "streamSettings": {
            "network": "grpc", "security": "reality",
            "grpcSettings": {"serviceName": svc, "multiMode": True},
            "realitySettings": {
                "show": False, "dest": f"{REALITY_SNI}:443", "xver": 0,
                "serverNames": [REALITY_SNI], "privateKey": priv, "shortIds": [sid],
            },
        },
        "sniffing": SNIFF, "tag": f"ir-reality-grpc-{port}",
    })
    meta.append(("Reality-gRPC", port, "reality-grpc",
                 {"pbk": pub, "sid": sid, "serviceName": svc}))

    # 3) VLESS + mKCP (srtp header) -- rides Irancell's UDP/video-call QoS
    seed = secrets.token_hex(6)
    port = pick(2096)
    inbounds.append({
        "listen": "0.0.0.0", "port": port, "protocol": "vless",
        "settings": {"clients": list(clients), "decryption": "none"},
        "streamSettings": {
            "network": "kcp", "security": "none",
            "kcpSettings": {
                "mtu": 1350, "tti": 50, "uplinkCapacity": 12, "downlinkCapacity": 100,
                "congestion": True, "readBufferSize": 2, "writeBufferSize": 2,
                "header": {"type": "srtp"}, "seed": seed,
            },
        },
        "sniffing": SNIFF, "tag": f"ir-mkcp-srtp-{port}",
    })
    meta.append(("mKCP-srtp (UDP)", port, "mkcp", {"headerType": "srtp", "seed": seed}))

    # 4) VLESS + mKCP (wireguard header)
    seed = secrets.token_hex(6)
    port = pick(2097)
    inbounds.append({
        "listen": "0.0.0.0", "port": port, "protocol": "vless",
        "settings": {"clients": list(clients), "decryption": "none"},
        "streamSettings": {
            "network": "kcp", "security": "none",
            "kcpSettings": {
                "mtu": 1350, "tti": 50, "uplinkCapacity": 12, "downlinkCapacity": 100,
                "congestion": True, "readBufferSize": 2, "writeBufferSize": 2,
                "header": {"type": "wireguard"}, "seed": seed,
            },
        },
        "sniffing": SNIFF, "tag": f"ir-mkcp-wg-{port}",
    })
    meta.append(("mKCP-wireguard (UDP)", port, "mkcp",
                 {"headerType": "wireguard", "seed": seed}))

    return inbounds, meta


def share_link(addr: str, cid: str, email: str, port: int, kind: str, p: dict) -> str:
    tag = quote(f"IR-{kind}-{email}")
    if kind == "reality-vision":
        q = (f"type=tcp&security=reality&flow={p['flow']}&sni={REALITY_SNI}"
             f"&pbk={p['pbk']}&sid={p['sid']}&fp=chrome&spx=%2F")
    elif kind == "reality-grpc":
        q = (f"type=grpc&serviceName={quote(p['serviceName'])}&mode=multi"
             f"&security=reality&sni={REALITY_SNI}&pbk={p['pbk']}&sid={p['sid']}&fp=chrome")
    else:  # mkcp
        q = f"type=kcp&headerType={p['headerType']}&seed={quote(p['seed'])}&security=none"
    return f"vless://{cid}@{addr}:{port}?{q}#{tag}"


def main() -> None:
    src = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/x-ui/bin/config.json"
    dst = sys.argv[2] if len(sys.argv) > 2 else "merged_config.json"

    with open(src, encoding="utf-8") as f:
        config = json.load(f)

    inbounds = config.setdefault("inbounds", [])
    clients = extract_clients(inbounds)
    if not clients:
        sys.exit("No existing VLESS clients found to reuse; aborting.")

    addr = os.getenv("IR_SERVER_ADDR") or detect_public_ip()
    used = {i.get("port") for i in inbounds if isinstance(i.get("port"), int)}
    used |= os_listening_ports()  # avoid nginx/sshd/etc. already bound on the host
    pick = port_picker(used)

    new_inbounds, meta = build_inbounds(clients, pick)
    inbounds.extend(new_inbounds)

    with open(dst, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print(f"Reused {len(clients)} existing clients.")
    print(f"Added {len(new_inbounds)} Irancell inbounds. Merged config -> {dst}\n")

    sample = clients[0]
    links = []
    print("New inbounds (ports):")
    for (name, port, kind, p), inb in zip(meta, new_inbounds):
        print(f"  - {name:24s} port {port}  tag={inb['tag']}")
        links.append(f"# {name} (port {port}) -- sample user: {sample['email']}\n"
                     + share_link(addr, sample["id"], sample["email"], port, kind, p))

    out_links = "irancell_share_links.txt"
    with open(out_links, "w", encoding="utf-8") as f:
        f.write(f"# Server address used: {addr}\n"
                "# Any EXISTING user UUID works on these inbounds -- swap the UUID per user.\n\n"
                + "\n\n".join(links) + "\n")
    print(f"\nSample share links (for {sample['email']}) -> {out_links}")
    print("Open ports on the firewall: TCP for Reality ports, UDP for the mKCP ports.")


if __name__ == "__main__":
    main()
