"""MTProto proxy handshake and liveness check.

A proxy counts only when this machine completes the proxy handshake and
Telegram answers. Fake-TLS (secrets starting with ee) is required on
networks that block plain MTProxy.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import re
import struct
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

RESPQ = 0x05162463
DC_INDEX = 2
TAG_INTERMEDIATE = b"\xee\xee\xee\xee"
TAG_SECURE = b"\xdd\xdd\xdd\xdd"

_LINK_RE = re.compile(
    r"(?:tg://proxy|https?://t\.me/proxy)\?([^\s\"'<>]+)",
    re.IGNORECASE,
)
_TRIPLE_RE = re.compile(
    r"(?:^|[^\d])("
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"):(\d{2,5}):([0-9a-fA-F]{32,}|[A-Za-z0-9_\-]{22,})"
)


@dataclass(frozen=True)
class MtProxy:
    host: str
    port: int
    secret: str

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def link(self) -> str:
        return f"tg://proxy?server={self.host}&port={self.port}&secret={self.secret}"


class _Ctr:
    def __init__(self, key: bytes, iv: bytes):
        self._enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()

    def process(self, data: bytes) -> bytes:
        return self._enc.update(data)


def _b64(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def parse_secret(secret: str) -> tuple[bytes, str | None, str]:
    text = secret.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) % 2 == 0:
        raw = bytes.fromhex(text)
    else:
        raw = _b64(text)
    if raw[:1] == b"\xee":
        body = raw[1:]
        domain = body[16:].decode("utf-8", "ignore") or "www.google.com"
        return body[:16], domain, "ee"
    if raw[:1] == b"\xdd":
        return raw[1:17], None, "dd"
    if len(raw) < 16:
        raise ValueError("secret too short")
    return raw[:16], None, "plain"


def parse_mtproxies(text: str) -> list[MtProxy]:
    found: list[MtProxy] = []
    seen: set[tuple[str, int, str]] = set()

    def add(host: str, port: int, secret: str) -> None:
        host = host.strip().rstrip(".")
        secret = secret.strip()
        if not (1 <= port <= 65535) or len(secret) < 16:
            return
        key = (host, port, secret.lower())
        if key in seen:
            return
        try:
            parse_secret(secret)
        except Exception:
            return
        seen.add(key)
        found.append(MtProxy(host, port, secret))

    for match in _LINK_RE.finditer(text):
        query = parse_qs(match.group(1))
        host = (query.get("server") or [""])[0].strip().rstrip(".")
        port_s = (query.get("port") or ["0"])[0]
        secret = (query.get("secret") or [""])[0]
        if host and port_s.isdigit():
            add(host, int(port_s), secret)

    for match in _TRIPLE_RE.finditer(text):
        add(match.group(1), int(match.group(2)), match.group(3))

    # JSON objects without a tg:// link: "host"/"server", "port", "secret"
    for block in re.finditer(r"\{[^{}]{0,400}\}", text):
        chunk = block.group(0)
        host_m = re.search(r'"(?:host|server|ip)"\s*:\s*"([^"]+)"', chunk)
        port_m = re.search(r'"port"\s*:\s*"?(\d+)"?', chunk)
        sec_m = re.search(r'"secret"\s*:\s*"([^"]+)"', chunk)
        if host_m and port_m and sec_m:
            add(host_m.group(1), int(port_m.group(1)), sec_m.group(1))
    return found


def _obfuscated_init(secret: bytes, tag: bytes) -> tuple[bytes, _Ctr, _Ctr]:
    banned = (
        b"PVrG",
        b"GET ",
        b"POST",
        b"HEAD",
        b"\xee\xee\xee\xee",
        b"\xdd\xdd\xdd\xdd",
        b"\xef\xef\xef\xef",
        b"\x16\x03\x01\x02",
    )
    while True:
        blob = bytearray(os.urandom(64))
        if blob[0] != 0xEF and blob[:4] not in banned and blob[4:8] != b"\x00\x00\x00\x00":
            break
    blob[56:60] = tag
    blob[60:62] = DC_INDEX.to_bytes(2, "little", signed=True)
    enc_key = hashlib.sha256(bytes(blob[8:40]) + secret).digest()
    enc_iv = bytes(blob[40:56])
    rev = bytes(blob[8:56])[::-1]
    dec_key = hashlib.sha256(rev[:32] + secret).digest()
    dec_iv = rev[32:48]
    enc = _Ctr(enc_key, enc_iv)
    dec = _Ctr(dec_key, dec_iv)
    encrypted = enc.process(bytes(blob))
    blob[56:64] = encrypted[56:64]
    return bytes(blob), enc, dec


def _client_hello(secret: bytes, sni: str) -> bytes:
    """Fake-TLS ClientHello. Digest matches mtprotoproxy's HMAC check."""
    sni_b = sni.encode("ascii", "ignore") or b"www.google.com"
    ciphers = bytes.fromhex(
        "130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035000a"
    )
    sni_ext = (
        b"\x00\x00"
        + struct.pack(">H", len(sni_b) + 5)
        + struct.pack(">H", len(sni_b) + 3)
        + b"\x00"
        + struct.pack(">H", len(sni_b))
        + sni_b
    )
    extensions = sni_ext + bytes.fromhex(
        "002b0003020304"
        "000a00040002001d"
        "000d00080006040308040401"
        "0010000b000908687474702f312e31"
    )
    # handshake payload must be >= 512 bytes; padding extension fills the gap
    fixed = (
        4  # handshake header
        + 2
        + 32
        + 1
        + 32
        + 2
        + len(ciphers)
        + 2
        + 2
        + len(extensions)
    )
    pad_total = 512 - fixed
    pad_body = max(0, pad_total - 4)
    extensions += b"\x00\x15" + struct.pack(">H", pad_body) + (b"\x00" * pad_body)

    hello = bytearray()
    hello += b"\x03\x03"
    hello += b"\x00" * 32
    hello += b"\x20" + os.urandom(32)
    hello += struct.pack(">H", len(ciphers)) + ciphers
    hello += b"\x01\x00"
    hello += struct.pack(">H", len(extensions)) + extensions
    body = b"\x01" + len(hello).to_bytes(3, "big") + bytes(hello)
    if len(body) < 512:
        body += b"\x00" * (512 - len(body))
    record = bytearray(b"\x16\x03\x01" + struct.pack(">H", len(body)) + body)

    msg = bytes(record[:11]) + (b"\x00" * 32) + bytes(record[43:])
    digest = hmac.new(secret, msg, hashlib.sha256).digest()
    stamp = int(time.time()).to_bytes(4, "little")
    mask = (b"\x00" * 28) + stamp
    record[11:43] = bytes(a ^ b for a, b in zip(digest, mask))
    return bytes(record)


def _req_pq() -> bytes:
    nonce = os.urandom(16)
    query = struct.pack("<I", 0xBE7E8EF1) + nonce
    msg_id = int(time.time()) << 32
    body = struct.pack("<q", 0) + struct.pack("<q", msg_id) + struct.pack("<I", len(query)) + query
    return struct.pack("<I", len(body)) + body


def _looks_like_telegram(packet: bytes) -> bool:
    if len(packet) < 24:
        return False
    auth_key = struct.unpack_from("<q", packet, 0)[0]
    msg_len = struct.unpack_from("<I", packet, 16)[0]
    if auth_key != 0 or not (4 <= msg_len <= len(packet) - 20):
        return False
    ctor = struct.unpack_from("<I", packet, 20)[0]
    # resPQ is the direct answer to req_pq. The others are still Telegram.
    return ctor in (
        RESPQ,
        0xA7EFF811,  # bad_msg_notification
        0xEDAB447B,  # bad_server_salt
        0x73F1F8DC,  # msg_container
        0x2144CA19,  # rpc_error
        0x62D6B459,  # msgs_ack
    )


class _TlsReader:
    def __init__(self, reader: asyncio.StreamReader):
        self._reader = reader
        self._buf = bytearray()

    async def _record(self) -> bytes:
        while True:
            rec_type = (await self._reader.readexactly(1))[0]
            version = await self._reader.readexactly(2)
            if version != b"\x03\x03":
                raise ConnectionError("bad tls version")
            length = int.from_bytes(await self._reader.readexactly(2), "big")
            data = await self._reader.readexactly(length)
            if rec_type == 0x17:
                return data
            if rec_type not in (0x14, 0x15, 0x16):
                raise ConnectionError("unexpected tls record")

    async def discard_record(self) -> None:
        self._buf.clear()
        await self._record()

    async def readexactly(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._buf += await self._record()
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out


def _tls_app(data: bytes) -> bytes:
    return b"\x17\x03\x03" + struct.pack(">H", len(data)) + data


async def _read_reply(readexactly, dec: _Ctr) -> bool:
    for _ in range(6):
        length = struct.unpack("<i", dec.process(await readexactly(4)))[0]
        if length < 0:
            continue
        if length == 0 or length > 65536:
            return False
        packet = dec.process(await readexactly(length))
        # randomized-intermediate padding is 0..3 bytes; payload stays 4-aligned
        pad = len(packet) % 4
        if pad:
            packet = packet[:-pad]
        if _looks_like_telegram(packet):
            return True
    return False


async def check_mtproxy(proxy: MtProxy, timeout: float) -> bool:
    secret, domain, kind = parse_secret(proxy.secret)
    tag = TAG_SECURE if kind in ("ee", "dd") else TAG_INTERMEDIATE
    init, enc, dec = _obfuscated_init(secret, tag)
    payload = init + enc.process(_req_pq())

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port),
            timeout=timeout,
        )
    except Exception:
        return False

    try:
        if kind == "ee":
            writer.write(_client_hello(secret, domain or "www.google.com"))
            await asyncio.wait_for(writer.drain(), timeout)
            tls = _TlsReader(reader)
            # Handshake records are skipped; the fake certificate is one
            # app-data record. Drop it before reading Telegram's reply.
            await asyncio.wait_for(tls.discard_record(), timeout)
            writer.write(_tls_app(payload))
            await asyncio.wait_for(writer.drain(), timeout)
            return await asyncio.wait_for(_read_reply(tls.readexactly, dec), timeout)

        writer.write(payload)
        await asyncio.wait_for(writer.drain(), timeout)
        return await asyncio.wait_for(_read_reply(reader.readexactly, dec), timeout)
    except Exception:
        return False
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def handshake_digest_ok(secret: bytes, hello: bytes) -> bool:
    """Same check the proxy server uses. Used by the local self-test."""
    msg = hello[:11] + (b"\x00" * 32) + hello[43:]
    digest = hello[11:43]
    computed = hmac.new(secret, msg, hashlib.sha256).digest()
    mixed = bytes(a ^ b for a, b in zip(digest, computed))
    return mixed.startswith(b"\x00" * 28)
