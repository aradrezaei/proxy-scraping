"""Collect public V2Ray share-links and keep the ones this network can use.

Configs are tested with the official Xray client: a link is saved only when
traffic through it reaches an IP echo and the exit address is not this machine.
"""

from __future__ import annotations

import asyncio
import base64
import html
import json
import os
import platform
import re
import shutil
import stat
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import aiohttp
from aiohttp_socks import ProxyConnector

from .net import NetworkProfile, extract_ip, probe, ssl_context

ROOT = Path(__file__).resolve().parent.parent
AUTO = ROOT / "auto" / "v2ray.txt"
OUT = ROOT / "out"
BIN = ROOT / "bin" / "xray"
_LINK_RE = re.compile(r"(?:vmess|vless|trojan|ss)://[A-Za-z0-9+/=_\-%.~:@?#&]+")


@dataclass(frozen=True)
class ShareLink:
    uri: str
    kind: str
    outbound: dict


def _b64(data: str) -> bytes:
    text = unquote(data.strip())
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, validate=False)
    except Exception:
        return base64.urlsafe_b64decode(text)


def _first(query: dict[str, list[str]], key: str, default: str = "") -> str:
    values = query.get(key)
    if not values or values[0] is None:
        return default
    return unquote(values[0])


def _stream(query: dict[str, list[str]], address: str) -> dict:
    network = _first(query, "type") or _first(query, "net") or "tcp"
    if network == "http":
        network = "h2"
    security = _first(query, "security") or "none"
    header = _first(query, "headerType") or _first(query, "headertype")
    sni = _first(query, "sni") or _first(query, "peer") or address
    fingerprint = _first(query, "fp") or "chrome"
    host = _first(query, "host")
    path = _first(query, "path") or "/"
    service = _first(query, "serviceName") or _first(query, "serviceName".lower())
    if not service:
        service = _first(query, "servicename")

    stream: dict = {"network": network}
    if security == "tls":
        tls: dict = {
            "serverName": sni or host or address,
            "fingerprint": fingerprint,
            "allowInsecure": True,
        }
        alpn = _first(query, "alpn")
        if alpn:
            tls["alpn"] = alpn.split(",")
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fingerprint,
            "publicKey": _first(query, "pbk"),
            "shortId": _first(query, "sid"),
            "spiderX": _first(query, "spx") or "",
        }
    else:
        stream["security"] = "none"

    if network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host or sni or address}}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": service}
    elif network in ("h2", "http"):
        stream["network"] = "h2"
        stream["httpSettings"] = {"host": [host or sni or address], "path": path}
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, "host": host or sni or address}
    elif network == "xhttp":
        stream["xhttpSettings"] = {
            "path": path,
            "host": host or sni or address,
            "mode": _first(query, "mode") or "auto",
        }
    elif network == "tcp" and header == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {"path": [path], "headers": {"Host": [host or address]}},
            }
        }
    return stream


def _parse_vmess(uri: str) -> ShareLink | None:
    try:
        payload = json.loads(_b64(uri[len("vmess://"):]).decode("utf-8", "ignore"))
    except Exception:
        return None
    address = str(payload.get("add") or "").strip()
    port = int(payload.get("port") or 0)
    user_id = str(payload.get("id") or "").strip()
    if not address or not user_id or not (1 <= port <= 65535):
        return None
    network = str(payload.get("net") or "tcp")
    tls = str(payload.get("tls") or "")
    query = {
        "type": [network],
        "security": ["tls" if tls == "tls" else "none"],
        "sni": [str(payload.get("sni") or payload.get("host") or address)],
        "host": [str(payload.get("host") or "")],
        "path": [str(payload.get("path") or "/")],
        "headerType": [str(payload.get("type") or "none")],
        "fp": [str(payload.get("fp") or "chrome")],
        "alpn": [str(payload.get("alpn") or "")],
        "serviceName": [str(payload.get("path") or "") if network == "grpc" else ""],
    }
    outbound = {
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": address,
                "port": port,
                "users": [{
                    "id": user_id,
                    "alterId": int(payload.get("aid") or 0),
                    "security": str(payload.get("scy") or "auto"),
                }],
            }]
        },
        "streamSettings": _stream(query, address),
    }
    return ShareLink(uri, "vmess", outbound)


def _split_ss(uri: str) -> tuple[str, str, str, int] | None:
    body = uri[len("ss://"):].split("#", 1)[0].strip()
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        userinfo = unquote(userinfo)
        if ":" not in userinfo:
            try:
                userinfo = _b64(userinfo).decode("utf-8", "ignore")
            except Exception:
                return None
        if ":" not in userinfo:
            return None
        method, password = userinfo.split(":", 1)
    else:
        try:
            decoded = _b64(body).decode("utf-8", "ignore")
        except Exception:
            return None
        if "@" not in decoded or ":" not in decoded.split("@", 1)[0]:
            return None
        userinfo, hostport = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
    hostport = hostport.split("?", 1)[0].strip("/")
    if hostport.startswith("["):
        host, _, port_s = hostport[1:].partition("]")
        port_s = port_s.lstrip(":")
    else:
        host, _, port_s = hostport.rpartition(":")
    if not host or not port_s.isdigit():
        return None
    return method, password, host, int(port_s)


def parse_share(uri: str) -> ShareLink | None:
    uri = uri.strip()
    kind = uri.split("://", 1)[0].lower()
    if kind == "vmess":
        return _parse_vmess(uri)
    if kind == "ss":
        parts = _split_ss(uri)
        if not parts:
            return None
        method, password, host, port = parts
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "method": method,
                    "password": password,
                }]
            },
        }
        return ShareLink(uri, "ss", outbound)
    if kind not in ("vless", "trojan"):
        return None
    try:
        parsed = urlparse(uri)
        host = parsed.hostname
        port = parsed.port
        user = unquote(parsed.username) if parsed.username else ""
    except ValueError:
        return None
    if not host or not port or not user:
        return None
    query = parse_qs(parsed.query, keep_blank_values=True)
    stream = _stream(query, parsed.hostname)
    if kind == "vless":
        user = {
            "id": unquote(parsed.username),
            "encryption": _first(query, "encryption") or "none",
        }
        flow = _first(query, "flow")
        if flow and stream.get("network") in ("tcp", "raw"):
            user["flow"] = flow
        settings = {"vnext": [{"address": parsed.hostname, "port": parsed.port, "users": [user]}]}
    else:
        settings = {
            "servers": [{
                "address": parsed.hostname,
                "port": parsed.port,
                "password": unquote(parsed.username),
            }]
        }
    outbound = {"protocol": kind, "settings": settings, "streamSettings": stream}
    return ShareLink(uri, kind, outbound)


def extract_links(text: str) -> list[str]:
    text = html.unescape(text)
    found = list(dict.fromkeys(_LINK_RE.findall(text)))
    if found:
        return found
    compact = "".join(text.split())
    if len(compact) < 16 or not re.fullmatch(r"[A-Za-z0-9+/=_\-]+", compact[:200]):
        return []
    try:
        decoded = _b64(compact).decode("utf-8", "ignore")
    except Exception:
        return []
    return list(dict.fromkeys(_LINK_RE.findall(decoded)))


def _asset_name() -> str:
    machine = platform.machine().lower()
    system = platform.system().lower()
    if system == "darwin" and machine in ("arm64", "aarch64"):
        return "Xray-macos-arm64-v8a.zip"
    if system == "darwin":
        return "Xray-macos-64.zip"
    if system == "linux" and machine in ("arm64", "aarch64"):
        return "Xray-linux-arm64-v8a.zip"
    if system == "linux":
        return "Xray-linux-64.zip"
    return "Xray-windows-64.zip"


async def ensure_xray(session: aiohttp.ClientSession) -> Path:
    if BIN.exists() and os.access(BIN, os.X_OK):
        return BIN
    found = shutil.which("xray")
    if found:
        return Path(found)
    BIN.parent.mkdir(parents=True, exist_ok=True)
    zip_path = BIN.parent / "xray.zip"
    asset = _asset_name()
    # v26 dropped allowInsecure, which public configs still rely on.
    tags = ("v25.12.8", "v25.10.15", "v25.8.3", "v25.3.6")
    timeout = aiohttp.ClientTimeout(total=180, sock_read=60)
    saved = False
    for tag in tags:
        url = f"https://github.com/XTLS/Xray-core/releases/download/{tag}/{asset}"
        async with session.get(url, allow_redirects=True, timeout=timeout) as resp:
            if resp.status != 200:
                continue
            with zip_path.open("wb") as handle:
                async for chunk in resp.content.iter_chunked(1024 * 256):
                    handle.write(chunk)
            saved = True
            break
    if not saved:
        raise SystemExit("Could not download Xray.")
    with zipfile.ZipFile(zip_path) as archive:
        name = next(item for item in archive.namelist() if Path(item).name == "xray")
        BIN.write_bytes(archive.read(name))
    zip_path.unlink(missing_ok=True)
    BIN.chmod(BIN.stat().st_mode | stat.S_IEXEC)
    return BIN


def _client_config(link: ShareLink, port: int) -> dict:
    outbound = dict(link.outbound)
    outbound["tag"] = "proxy"
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {"udp": False},
        }],
        "outbounds": [outbound],
    }


async def _port_open(port: int) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port),
            timeout=0.2,
        )
    except Exception:
        return False
    writer.close()
    return True


async def check_link(xray: Path, link: ShareLink, echo_url: str, local_ip: str, timeout: float) -> bool:
    port = socket_bind_port()
    config_path = Path(tempfile.mkstemp(suffix=".json")[1])
    config_path.write_text(json.dumps(_client_config(link, port)), encoding="utf-8")
    proc = await asyncio.create_subprocess_exec(
        str(xray), "run", "-c", str(config_path),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        opened = False
        for _ in range(25):
            if proc.returncode is not None:
                return False
            if await _port_open(port):
                opened = True
                break
            await asyncio.sleep(0.1)
        if not opened:
            return False
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
        client_timeout = aiohttp.ClientTimeout(total=timeout, connect=timeout)
        async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=False) as session:
            async with session.get(
                "https://www.cloudflare.com/cdn-cgi/trace",
                ssl=False,
            ) as resp:
                if resp.status != 200:
                    return False
                ip = extract_ip(await resp.text(errors="ignore"))
        return bool(ip and ip != local_ip)
    except Exception:
        return False
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        config_path.unlink(missing_ok=True)


def socket_bind_port() -> int:
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _endpoint(link: ShareLink) -> tuple[str, int]:
    settings = link.outbound["settings"]
    if "vnext" in settings:
        node = settings["vnext"][0]
    else:
        node = settings["servers"][0]
    return str(node["address"]).lower(), int(node["port"])


def _identity(link: ShareLink) -> tuple:
    host, port = _endpoint(link)
    stream = link.outbound.get("streamSettings") or {}
    tls = stream.get("tlsSettings") or stream.get("realitySettings") or {}
    sni = tls.get("serverName") or ""
    path = ""
    for key in ("wsSettings", "xhttpSettings", "httpSettings", "httpupgradeSettings"):
        block = stream.get(key) or {}
        if block.get("path"):
            path = str(block["path"])
    settings = link.outbound["settings"]
    if "vnext" in settings:
        secret = settings["vnext"][0]["users"][0].get("id", "")
    else:
        secret = settings["servers"][0].get("password", "")
    return (host, port, link.kind, secret, sni, path)


def _rank(link: ShareLink) -> int:
    security = link.outbound.get("streamSettings", {}).get("security", "none")
    base = {"vless": 0, "trojan": 1, "vmess": 2, "ss": 3}.get(link.kind, 9)
    if security == "reality":
        base -= 2
    return base


class Finder:
    def __init__(self, target: int, profile: NetworkProfile, xray: Path):
        self.target = target
        self.profile = profile
        self.xray = xray
        self.found = 0
        self.checked = 0
        self.dialed = 0
        self.reachable = 0
        self.unique = 0
        self.phase = "fetch"
        self.stop = asyncio.Event()
        self.lock = asyncio.Lock()
        self.saved: list[str] = []
        self.errors: list[str] = []
        self.xray_workers = 4
        self.dial_timeout = min(2.0, max(1.5, profile.rtt_ms / 1000 * 3))
        self.test_timeout = min(8.0, max(8.0, profile.rtt_ms / 1000 * 8))

    async def _fetch_all(self) -> list[ShareLink]:
        urls = []
        for line in AUTO.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(self.profile.rewrite(line))
        if not urls:
            raise SystemExit(f"No sources in {AUTO}")
        seen: set[str] = set()
        found: dict[tuple[str, int], ShareLink] = {}
        timeout = aiohttp.ClientTimeout(total=self.profile.scrape_timeout)
        connector = aiohttp.TCPConnector(
            limit=len(urls),
            ttl_dns_cache=300,
            ssl=ssl_context(self.profile.verify_ssl),
        )

        async def one(session: aiohttp.ClientSession, url: str) -> None:
            try:
                async with session.get(url, timeout=timeout) as resp:
                    if resp.status != 200:
                        raise aiohttp.ClientResponseError(
                            resp.request_info, resp.history, status=resp.status, message=resp.reason or ""
                        )
                    text = await resp.text(errors="ignore")
            except Exception as exc:
                if len(self.errors) < 40:
                    self.errors.append(f"{url} -> {type(exc).__name__}: {exc}\n")
                return
            for raw in extract_links(text):
                if raw in seen:
                    continue
                seen.add(raw)
                try:
                    link = parse_share(raw)
                except Exception:
                    continue
                if not link:
                    continue
                key = _identity(link)
                current = found.get(key)
                if current is None or _rank(link) < _rank(current):
                    found[key] = link

        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, trust_env=False,
            headers={"User-Agent": "proxy-scraper/2.0"},
        ) as session:
            await asyncio.gather(*(one(session, url) for url in urls))
        self.unique = len(found)
        return list(found.values())

    async def _dial(self, links: list[ShareLink], sink: asyncio.Queue) -> None:
        self.phase = "dial"
        sem = asyncio.Semaphore(250)

        async def one(link: ShareLink) -> None:
            if self.stop.is_set():
                return
            host, port = _endpoint(link)
            async with sem:
                if self.stop.is_set():
                    self.dialed += 1
                    return
                started = time.perf_counter()
                try:
                    _reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        self.dial_timeout,
                    )
                except Exception:
                    self.dialed += 1
                    return
                writer.close()
                rtt = (time.perf_counter() - started) * 1000
            self.dialed += 1
            self.reachable += 1
            if not self.stop.is_set():
                await sink.put((rtt, link))

        await asyncio.gather(*(one(link) for link in links))

    async def _prove(self, sink: asyncio.Queue, total: int) -> None:
        async def worker() -> None:
            while not self.stop.is_set():
                try:
                    _rtt, link = await asyncio.wait_for(sink.get(), timeout=0.3)
                except asyncio.TimeoutError:
                    if self.dialed >= total:
                        return
                    continue
                started = time.perf_counter()
                ok = await check_link(
                    self.xray, link, self.profile.echo_url,
                    self.profile.local_ip, self.test_timeout,
                )
                self.checked += 1
                sink.task_done()
                if not ok or self.stop.is_set():
                    if self.dialed >= total and sink.empty():
                        return
                    continue
                elapsed = (time.perf_counter() - started) * 1000
                async with self.lock:
                    if self.found >= self.target:
                        self.stop.set()
                        return
                    self.found += 1
                    self.saved.append(link.uri)
                    print(f"\n{link.kind:8}  {elapsed:.0f}ms  {link.uri}")
                    if self.found >= self.target:
                        self.stop.set()
                        return

        self.phase = "test"
        await asyncio.gather(*(worker() for _ in range(self.xray_workers)))

    async def status_loop(self) -> None:
        while not self.stop.is_set():
            print(
                f"\r{self.phase:5}  servers={self.unique}  dialed={self.dialed}  "
                f"open={self.reachable}  tested={self.checked}  "
                f"found={self.found}/{self.target}   ",
                end="",
                flush=True,
            )
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=0.4)
            except asyncio.TimeoutError:
                pass
        print()

    async def run(self) -> None:
        profile = self.profile
        print(
            f"network  ip={profile.local_ip}  rtt={profile.rtt_ms:.0f}ms  "
            f"mirror={profile.mirror}  dial={self.dial_timeout:.1f}s  test={self.test_timeout:.1f}s"
        )
        OUT.mkdir(exist_ok=True)
        status = asyncio.create_task(self.status_loop())
        links = await self._fetch_all()
        links.sort(key=_rank)
        print(f"\n{len(links)} unique servers. Dialing and testing together...")
        sink: asyncio.Queue = asyncio.Queue()
        dial = asyncio.create_task(self._dial(links, sink))
        prove = asyncio.create_task(self._prove(sink, len(links)))
        await dial
        if not self.stop.is_set():
            await prove
        else:
            prove.cancel()
            await asyncio.gather(prove, return_exceptions=True)
        self.stop.set()
        status.cancel()
        await asyncio.gather(status, return_exceptions=True)

        path = OUT / "v2ray.txt"
        path.write_text("\n".join(self.saved) + ("\n" if self.saved else ""), encoding="utf-8")
        sub = base64.b64encode("\n".join(self.saved).encode()).decode()
        (OUT / "v2ray-sub.txt").write_text(sub + "\n", encoding="utf-8")
        if self.errors:
            (ROOT / "error.txt").write_text("".join(self.errors), encoding="utf-8")
        if self.found >= self.target:
            print(f"finished  ->  {path}")
        else:
            print(f"done — only {self.found}/{self.target} working configs  ->  {path}")


def main() -> None:
    raw = input("how many configs? : ").strip()
    try:
        target = int(raw)
    except ValueError:
        raise SystemExit("Enter a number.")
    if target < 1:
        raise SystemExit("Enter a number greater than zero.")

    async def _go() -> None:
        profile = await probe()
        connector = aiohttp.TCPConnector(ssl=ssl_context(profile.verify_ssl))
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            xray = await ensure_xray(session)
        await Finder(target, profile, xray).run()

    asyncio.run(_go())
