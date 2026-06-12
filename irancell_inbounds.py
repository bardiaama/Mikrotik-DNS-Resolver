#!/usr/bin/env python3
"""Generate Irancell-optimized Xray inbounds for the 3x-ui (Sanaei) panel.

The configs we already run on the "Sanai" server work well on most Iranian
operators but are throttled by Irancell (MTN-Irancell). Irancell's DPI/QoS
behaves differently:

  * Plain TLS-over-TCP on 443 is throttled hard after some volume.
  * UDP traffic carrying a "whitelisted" obfuscation header (srtp/video-call,
    wireguard, dtls, wechat-video, utp) is prioritised by Irancell's QoS, so
    mKCP inbounds with those headers often get far better speed.
  * Multiplexed / chunked transports (gRPC, XHTTP/splithttp) survive the DPI
    noticeably better than plain WebSocket.
  * Reality removes the need for a real certificate/domain and resists
    SNI-based blocking, as long as the borrowed SNI is itself not throttled.

This module builds a set of inbounds covering those angles, writes each one as
an import-ready JSON file under ./inbounds/, prints a share link for quick
client testing, and (optionally) pushes them straight into a 3x-ui panel via
its HTTP API.

Nothing here is operator-specific magic: tune PORTS, REALITY_SNI and
SERVER_ADDRESS for your box, import/push, then A/B test on an Irancell SIM.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# --------------------------------------------------------------------------- #
# Configuration -- override via environment variables instead of editing here. #
# --------------------------------------------------------------------------- #

# Public address (IP or domain) clients dial. This is the Xray/3x-ui box,
# NOT the MikroTik in connect.py. Reality does not need a domain on the box.
SERVER_ADDRESS = os.getenv("XUI_SERVER_ADDRESS", "YOUR_SERVER_IP")

# SNI borrowed by Reality. Pick a high-traffic host that Irancell does NOT
# throttle and that supports TLS1.3 + HTTP/2. Test a few; common picks below.
REALITY_SNI = os.getenv("XUI_REALITY_SNI", "www.datadoghq.com")

# 3x-ui panel API (only needed for --push). e.g. http://1.2.3.4:2053
PANEL_URL = os.getenv("XUI_PANEL_URL", "")
PANEL_USERNAME = os.getenv("XUI_PANEL_USERNAME", "")
PANEL_PASSWORD = os.getenv("XUI_PANEL_PASSWORD", "")
# 3x-ui "Secret Token" (Panel Settings -> Security). When the panel has secret
# auth enabled, the /login form needs this as `loginSecret`. Never commit it.
PANEL_SECRET = os.getenv("XUI_PANEL_SECRET", "")
# Some panels live under a secret base path, e.g. /abc123/. Leave empty if none.
PANEL_BASE_PATH = os.getenv("XUI_PANEL_BASE_PATH", "")

OUTPUT_DIR = Path(__file__).parent / "inbounds"


# --------------------------------------------------------------------------- #
# Crypto / id helpers                                                          #
# --------------------------------------------------------------------------- #

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def gen_reality_keypair() -> tuple[str, str]:
    """Return (private_key, public_key) in the base64url form `xray x25519` uses."""
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return _b64url(priv_raw), _b64url(pub_raw)


def gen_short_id(n_bytes: int = 8) -> str:
    return secrets.token_hex(n_bytes)


def gen_uuid() -> str:
    return str(uuid.uuid4())


def gen_ss2022_password(key_len: int = 16) -> str:
    """base64 (standard, padded) key for shadowsocks-2022."""
    return base64.b64encode(secrets.token_bytes(key_len)).decode()


# --------------------------------------------------------------------------- #
# Inbound builders                                                             #
# --------------------------------------------------------------------------- #

@dataclass
class Inbound:
    remark: str
    port: int
    protocol: str
    settings: dict
    stream_settings: dict
    sniffing: dict = field(
        default_factory=lambda: {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
            "metadataOnly": False,
            "routeOnly": False,
        }
    )
    # extra data kept only for building share links (not sent to the panel)
    link_meta: dict = field(default_factory=dict)

    def to_panel_payload(self) -> dict:
        """Shape expected by POST /panel/api/inbounds/add (nested objects as JSON strings)."""
        return {
            "up": 0,
            "down": 0,
            "total": 0,
            "remark": self.remark,
            "enable": True,
            "expiryTime": 0,
            "listen": "",
            "port": self.port,
            "protocol": self.protocol,
            "settings": json.dumps(self.settings, ensure_ascii=False),
            "streamSettings": json.dumps(self.stream_settings, ensure_ascii=False),
            "sniffing": json.dumps(self.sniffing, ensure_ascii=False),
        }


def _reality_stream(network_block: dict, priv: str, pub: str, sni: str) -> dict:
    short_ids = [gen_short_id(8), gen_short_id(4)]
    stream = {
        "security": "reality",
        "realitySettings": {
            "show": False,
            "xver": 0,
            "dest": f"{sni}:443",
            "serverNames": [sni],
            "privateKey": priv,
            "shortIds": short_ids,
            "settings": {
                "publicKey": pub,
                "fingerprint": "chrome",
                "serverName": "",
                "spiderX": "/",
            },
        },
    }
    stream.update(network_block)
    # stash for link building
    stream["_shortId"] = short_ids[0]
    stream["_publicKey"] = pub
    return stream


def build_vless_reality_vision(port: int) -> Inbound:
    """#1 baseline: VLESS + Reality + xtls-rprx-vision over raw TCP."""
    cid = gen_uuid()
    priv, pub = gen_reality_keypair()
    stream = _reality_stream({"network": "tcp"}, priv, pub, REALITY_SNI)
    short_id, public_key = stream.pop("_shortId"), stream.pop("_publicKey")
    return Inbound(
        remark="IR-Reality-Vision-TCP",
        port=port,
        protocol="vless",
        settings={
            "clients": [
                {"id": cid, "flow": "xtls-rprx-vision", "email": "ircell-vision", "enable": True}
            ],
            "decryption": "none",
            "fallbacks": [],
        },
        stream_settings=stream,
        link_meta={
            "type": "vless", "id": cid, "flow": "xtls-rprx-vision",
            "net": "tcp", "security": "reality", "sni": REALITY_SNI,
            "pbk": public_key, "sid": short_id, "fp": "chrome",
        },
    )


def build_vless_reality_grpc(port: int) -> Inbound:
    """#2 VLESS + Reality + gRPC: multiplexed, rides out Irancell DPI better."""
    cid = gen_uuid()
    priv, pub = gen_reality_keypair()
    service = "irancell-grpc"
    stream = _reality_stream(
        {"network": "grpc", "grpcSettings": {"serviceName": service, "multiMode": True}},
        priv, pub, REALITY_SNI,
    )
    short_id, public_key = stream.pop("_shortId"), stream.pop("_publicKey")
    return Inbound(
        remark="IR-Reality-gRPC",
        port=port,
        protocol="vless",
        settings={
            "clients": [{"id": cid, "flow": "", "email": "ircell-grpc", "enable": True}],
            "decryption": "none",
            "fallbacks": [],
        },
        stream_settings=stream,
        link_meta={
            "type": "vless", "id": cid, "flow": "",
            "net": "grpc", "serviceName": service, "mode": "multi",
            "security": "reality", "sni": REALITY_SNI,
            "pbk": public_key, "sid": short_id, "fp": "chrome",
        },
    )


def build_vless_reality_xhttp(port: int) -> Inbound:
    """#3 VLESS + Reality + XHTTP (splithttp): newest transport, strong on mobile."""
    cid = gen_uuid()
    priv, pub = gen_reality_keypair()
    path = "/irancell"
    stream = _reality_stream(
        {"network": "xhttp", "xhttpSettings": {"path": path, "host": "", "mode": "auto"}},
        priv, pub, REALITY_SNI,
    )
    short_id, public_key = stream.pop("_shortId"), stream.pop("_publicKey")
    return Inbound(
        remark="IR-Reality-XHTTP",
        port=port,
        protocol="vless",
        settings={
            "clients": [{"id": cid, "flow": "", "email": "ircell-xhttp", "enable": True}],
            "decryption": "none",
            "fallbacks": [],
        },
        stream_settings=stream,
        link_meta={
            "type": "vless", "id": cid, "flow": "",
            "net": "xhttp", "path": path, "mode": "auto",
            "security": "reality", "sni": REALITY_SNI,
            "pbk": public_key, "sid": short_id, "fp": "chrome",
        },
    )


def _mkcp_stream(header_type: str, seed: str) -> dict:
    return {
        "network": "kcp",
        "security": "none",
        "kcpSettings": {
            "mtu": 1350,
            "tti": 50,
            "uplinkCapacity": 12,
            "downlinkCapacity": 100,
            "congestion": True,
            "readBufferSize": 2,
            "writeBufferSize": 2,
            "header": {"type": header_type},
            "seed": seed,
        },
    }


def build_vmess_mkcp_srtp(port: int) -> Inbound:
    """#4 VMess + mKCP, srtp (video-call) header -- rides Irancell's UDP QoS."""
    cid = gen_uuid()
    seed = secrets.token_hex(6)
    return Inbound(
        remark="IR-mKCP-VMess-srtp",
        port=port,
        protocol="vmess",
        settings={"clients": [{"id": cid, "security": "auto", "email": "ircell-mkcp-srtp"}]},
        stream_settings=_mkcp_stream("srtp", seed),
        link_meta={"type": "vmess", "id": cid, "net": "kcp", "header": "srtp", "seed": seed},
    )


def build_vless_mkcp_wireguard(port: int) -> Inbound:
    """#5 VLESS + mKCP, wireguard header -- second whitelisted UDP profile."""
    cid = gen_uuid()
    seed = secrets.token_hex(6)
    return Inbound(
        remark="IR-mKCP-VLESS-wireguard",
        port=port,
        protocol="vless",
        settings={
            "clients": [{"id": cid, "flow": "", "email": "ircell-mkcp-wg", "enable": True}],
            "decryption": "none",
            "fallbacks": [],
        },
        stream_settings=_mkcp_stream("wireguard", seed),
        link_meta={"type": "vless", "id": cid, "net": "kcp", "header": "wireguard", "seed": seed},
    )


def build_shadowsocks_2022(port: int) -> Inbound:
    """#6 Shadowsocks-2022 (TCP+UDP): lightweight, low-overhead fallback."""
    method = "2022-blake3-aes-128-gcm"
    server_pw = gen_ss2022_password(16)
    client_pw = gen_ss2022_password(16)
    return Inbound(
        remark="IR-Shadowsocks-2022",
        port=port,
        protocol="shadowsocks",
        settings={
            "method": method,
            "password": server_pw,
            "network": "tcp,udp",
            "clients": [{"method": "", "password": client_pw, "email": "ircell-ss2022"}],
        },
        stream_settings={"network": "tcp", "security": "none"},
        link_meta={"type": "ss", "method": method, "server_pw": server_pw, "client_pw": client_pw},
    )


# Port plan: keep 443 for the flagship Vision inbound; spread the rest.
BUILDERS = [
    (443, build_vless_reality_vision),
    (8443, build_vless_reality_grpc),
    (2087, build_vless_reality_xhttp),
    (2095, build_vmess_mkcp_srtp),
    (2096, build_vless_mkcp_wireguard),
    (8388, build_shadowsocks_2022),
]


def build_all() -> list[Inbound]:
    return [builder(port) for port, builder in BUILDERS]


# --------------------------------------------------------------------------- #
# Share links (for quick client-side testing)                                 #
# --------------------------------------------------------------------------- #

def make_share_link(inb: Inbound) -> str:
    m = inb.link_meta
    addr, port, tag = SERVER_ADDRESS, inb.port, quote(inb.remark)

    if m["type"] == "vless":
        params = {"type": m["net"], "security": m.get("security", "none")}
        if m.get("flow"):
            params["flow"] = m["flow"]
        if m.get("security") == "reality":
            params.update({"sni": m["sni"], "pbk": m["pbk"], "sid": m["sid"],
                           "fp": m["fp"], "spx": "/"})
        if m["net"] == "grpc":
            params.update({"serviceName": m["serviceName"], "mode": m["mode"]})
        if m["net"] == "xhttp":
            params.update({"path": m["path"], "mode": m["mode"]})
        if m["net"] == "kcp":
            params.update({"headerType": m["header"], "seed": m["seed"]})
        query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
        return f"vless://{m['id']}@{addr}:{port}?{query}#{tag}"

    if m["type"] == "vmess":
        cfg = {
            "v": "2", "ps": inb.remark, "add": addr, "port": str(port),
            "id": m["id"], "aid": "0", "scy": "auto", "net": m["net"],
            "type": m["header"], "host": "", "path": m["seed"], "tls": "",
        }
        return "vmess://" + base64.b64encode(
            json.dumps(cfg, ensure_ascii=False).encode()
        ).decode()

    if m["type"] == "ss":
        userinfo = base64.urlsafe_b64encode(
            f"{m['method']}:{m['client_pw']}".encode()
        ).rstrip(b"=").decode()
        return f"ss://{userinfo}@{addr}:{port}#{tag}"

    return ""


# --------------------------------------------------------------------------- #
# Output                                                                       #
# --------------------------------------------------------------------------- #

def write_files(inbounds: list[Inbound]) -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)
    links = []
    for inb in inbounds:
        payload = inb.to_panel_payload()
        path = OUTPUT_DIR / f"{inb.remark}.json"
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        link = make_share_link(inb)
        links.append(f"# {inb.remark} (port {inb.port})\n{link}")
        print(f"  wrote {path.relative_to(Path(__file__).parent)}")
    (OUTPUT_DIR / "share-links.txt").write_text("\n\n".join(links) + "\n", encoding="utf-8")
    print(f"  wrote {(OUTPUT_DIR / 'share-links.txt').relative_to(Path(__file__).parent)}")


# --------------------------------------------------------------------------- #
# Optional: push directly into a 3x-ui panel                                   #
# --------------------------------------------------------------------------- #

def push_to_panel(inbounds: list[Inbound]) -> None:
    import requests
    from urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    if not PANEL_URL or not (PANEL_SECRET or (PANEL_USERNAME and PANEL_PASSWORD)):
        raise SystemExit(
            "Set XUI_PANEL_URL plus either XUI_PANEL_SECRET, or "
            "XUI_PANEL_USERNAME + XUI_PANEL_PASSWORD, to push."
        )

    base = PANEL_URL.rstrip("/") + (("/" + PANEL_BASE_PATH.strip("/")) if PANEL_BASE_PATH else "")
    sess = requests.Session()

    # 3x-ui accepts username/password and, when secret auth is on, a loginSecret.
    # Send whatever we have; the panel ignores empty fields.
    login_data = {"username": PANEL_USERNAME, "password": PANEL_PASSWORD}
    if PANEL_SECRET:
        login_data["loginSecret"] = PANEL_SECRET
    login = sess.post(f"{base}/login", data=login_data, timeout=15, verify=False)
    login.raise_for_status()
    if not login.json().get("success"):
        raise SystemExit(f"Panel login failed: {login.text}")
    print("Logged into panel.")

    for inb in inbounds:
        resp = sess.post(
            f"{base}/panel/api/inbounds/add",
            json=inb.to_panel_payload(),
            timeout=15,
            verify=False,
        )
        ok = resp.ok and resp.json().get("success")
        print(f"  {'OK ' if ok else 'ERR'} {inb.remark}: {resp.json().get('msg', resp.text)[:120]}")


# --------------------------------------------------------------------------- #

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--push", action="store_true",
                        help="push the generated inbounds to the 3x-ui panel API")
    args = parser.parse_args()

    if SERVER_ADDRESS == "YOUR_SERVER_IP":
        print("WARNING: XUI_SERVER_ADDRESS is unset; share links use a placeholder.\n")

    inbounds = build_all()
    print(f"Generated {len(inbounds)} Irancell-optimized inbounds:")
    write_files(inbounds)

    if args.push:
        print("\nPushing to panel...")
        push_to_panel(inbounds)
    else:
        print("\nImport the JSON files in ./inbounds/ into 3x-ui, or run with --push.")


if __name__ == "__main__":
    main()
