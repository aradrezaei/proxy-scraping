"""Measure the network this process is actually running on."""

from __future__ import annotations

import asyncio
import re
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import aiohttp
import certifi

IP_RE = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b"
)

ECHO_CANDIDATES = (
    "http://ip-api.com/line/?fields=query",
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
    "http://icanhazip.com",
    "https://1.1.1.1/cdn-cgi/trace",
)

# Tiny file used only to see which GitHub mirror answers here.
_CANARY = ("github", "gitignore", "main", "Python.gitignore")

MIRROR_BUILDERS = {
    "github": "https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}",
    "jsdelivr": "https://cdn.jsdelivr.net/gh/{user}/{repo}@{branch}/{path}",
    "statically": "https://cdn.statically.io/gh/{user}/{repo}/{branch}/{path}",
}

_RAW_RE = re.compile(
    r"^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$"
)
_JSDELIVR_RE = re.compile(
    r"^https?://cdn\.jsdelivr\.net/gh/([^/]+)/([^@/]+)@([^/]+)/(.+)$"
)
_STATICALLY_RE = re.compile(
    r"^https?://cdn\.statically\.io/gh/([^/]+)/([^/]+)/([^/]+)/(.+)$"
)


def ssl_context(verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context(cafile=certifi.where())
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def extract_ip(text: str) -> str | None:
    match = IP_RE.search(text)
    if not match:
        return None
    ip = match.group(1)
    if ip.startswith("0.") or ip == "127.0.0.1":
        return None
    return ip


@dataclass
class NetworkProfile:
    echo_url: str
    local_ip: str
    rtt_ms: float
    verify_ssl: bool
    mirror: str
    scrape_workers: int
    check_workers: int
    scrape_timeout: float
    check_timeout: float
    telegram_direct: bool

    def rewrite(self, url: str) -> str:
        parts = _split_github(url)
        if not parts:
            return url
        user, repo, branch, path = parts
        return MIRROR_BUILDERS[self.mirror].format(
            user=user, repo=repo, branch=branch, path=path
        )


def _split_github(url: str) -> tuple[str, str, str, str] | None:
    for pattern in (_RAW_RE, _JSDELIVR_RE, _STATICALLY_RE):
        match = pattern.match(url)
        if match:
            return match.group(1), match.group(2), match.group(3), match.group(4)
    return None


def _plan(rtt_ms: float) -> tuple[int, int, float, float]:
    if rtt_ms < 120:
        scrape, check = 40, 180
    elif rtt_ms < 300:
        scrape, check = 24, 100
    elif rtt_ms < 700:
        scrape, check = 12, 50
    else:
        scrape, check = 8, 24
    scrape_timeout = min(12.0, max(6.0, rtt_ms / 1000 * 12))
    check_timeout = min(8.0, max(4.0, rtt_ms / 1000 * 10))
    return scrape, check, scrape_timeout, check_timeout


async def _probe_echo(session: aiohttp.ClientSession, url: str) -> tuple[float, str] | None:
    started = time.perf_counter()
    try:
        async with session.get(url, allow_redirects=True) as resp:
            if resp.status != 200:
                return None
            text = await resp.text(errors="ignore")
    except Exception:
        return None
    ip = extract_ip(text)
    if not ip:
        return None
    return (time.perf_counter() - started) * 1000, ip


async def _probe_mirror(session: aiohttp.ClientSession, name: str) -> float | None:
    user, repo, branch, path = _CANARY
    url = MIRROR_BUILDERS[name].format(user=user, repo=repo, branch=branch, path=path)
    started = time.perf_counter()
    try:
        async with session.get(url) as resp:
            if resp.status != 200:
                return None
            body = await resp.content.read(64)
    except Exception:
        return None
    if b"python" not in body.lower() and b"#" not in body:
        return None
    return (time.perf_counter() - started) * 1000


async def _telegram_open(timeout: float) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection("149.154.167.51", 443),
            timeout=timeout,
        )
    except Exception:
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return True


async def _open_session(verify: bool, timeout: float) -> aiohttp.ClientSession:
    connector = aiohttp.TCPConnector(
        ssl=ssl_context(verify),
        ttl_dns_cache=300,
        limit=20,
    )
    return aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=timeout, connect=min(3.0, timeout)),
        trust_env=False,
        headers={"User-Agent": "proxy-scraper/2.0"},
    )


async def probe() -> NetworkProfile:
    verify = True
    echo: tuple[float, str, str] | None = None
    mirrors: list[tuple[float, str]] = []

    for attempt_verify in (True, False):
        verify = attempt_verify
        async with await _open_session(verify, 4.0) as session:
            echo_tasks = [asyncio.create_task(_probe_echo(session, url)) for url in ECHO_CANDIDATES]
            mirror_tasks = {
                name: asyncio.create_task(_probe_mirror(session, name))
                for name in MIRROR_BUILDERS
            }
            echo_results = await asyncio.gather(*echo_tasks)
            for url, result in zip(ECHO_CANDIDATES, echo_results):
                if result is None:
                    continue
                rtt, ip = result
                if echo is None or rtt < echo[0]:
                    echo = (rtt, ip, url)
            for name, task in mirror_tasks.items():
                rtt = await task
                if rtt is not None:
                    mirrors.append((rtt, name))
        if echo is not None:
            break

    if echo is None:
        raise SystemExit(
            "This network could not reach any IP-echo endpoint. "
            "Check the connection and run again."
        )

    rtt_ms, local_ip, echo_url = echo
    mirror = min(mirrors)[1] if mirrors else "jsdelivr"
    scrape_workers, check_workers, scrape_timeout, check_timeout = _plan(rtt_ms)
    telegram_direct = await _telegram_open(min(3.0, check_timeout))
    return NetworkProfile(
        echo_url=echo_url,
        local_ip=local_ip,
        rtt_ms=rtt_ms,
        verify_ssl=verify,
        mirror=mirror,
        scrape_workers=scrape_workers,
        check_workers=check_workers,
        scrape_timeout=scrape_timeout,
        check_timeout=check_timeout,
        telegram_direct=telegram_direct,
    )


def host_of(url: str) -> str:
    return urlparse(url).netloc
