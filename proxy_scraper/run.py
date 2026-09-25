"""Scrape public lists and keep only proxies that work on this network."""

from __future__ import annotations

import asyncio
import random
import re
import time
from pathlib import Path

import aiohttp
from aiohttp_socks import ProxyConnector

from .mtproto import MtProxy, check_mtproxy, parse_mtproxies
from .net import NetworkProfile, extract_ip, host_of, ssl_context

ROOT = Path(__file__).resolve().parent.parent
AUTO = ROOT / "auto"
OUT = ROOT / "out"

PROXY_RE = re.compile(
    r"(?:^|\D)((?:"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|[1-9])\."
    r"(?:\d|1\d\d|2[0-4]\d|25[0-5]|[1-9]\d)\."
    r"(?:\d|1\d\d|2[0-4]\d|25[0-5]|[1-9]\d)\."
    r"(?:\d|1\d\d|2[0-4]\d|25[0-5]|[1-9]\d)"
    r"):(?:"
    r"\d|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]"
    r"))(?:\D|$)"
)

TYPES = ("http", "socks4", "socks5", "mtproto")
_HOST_FAIL_LIMIT = 2


def load_sources(profile: NetworkProfile) -> list[tuple[str, str]]:
    jobs: list[tuple[str, str]] = []
    for proxy_type in TYPES:
        path = AUTO / f"{proxy_type}.txt"
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            jobs.append((proxy_type, profile.rewrite(line)))
    if not jobs:
        raise SystemExit(f"No sources in {AUTO}")
    random.shuffle(jobs)
    return jobs


class Scraper:
    def __init__(self, target: int, profile: NetworkProfile):
        self.target = target
        self.profile = profile
        self.found = 0
        self.checked = 0
        self.scraped = 0
        self.failed_sources = 0
        self.stop = asyncio.Event()
        self.lock = asyncio.Lock()
        self.seen: set[tuple] = set()
        self.queues = {kind: asyncio.Queue(maxsize=2000) for kind in TYPES}
        self.host_fail: dict[str, int] = {}
        self.dead_hosts: set[str] = set()
        self.errors: list[str] = []
        self._files: dict[str, object] = {}

    def _note_source_error(self, url: str, exc: BaseException) -> None:
        host = host_of(url)
        self.host_fail[host] = self.host_fail.get(host, 0) + 1
        if self.host_fail[host] >= _HOST_FAIL_LIMIT:
            self.dead_hosts.add(host)
        if len(self.errors) < 40:
            name = type(exc).__name__
            detail = str(exc).strip() or name
            self.errors.append(f"{url} -> {detail}\n")
        self.failed_sources += 1

    async def scrape_one(self, session: aiohttp.ClientSession, sem: asyncio.Semaphore, url: str, proxy_type: str) -> None:
        if self.stop.is_set() or host_of(url) in self.dead_hosts:
            return
        timeout = aiohttp.ClientTimeout(total=self.profile.scrape_timeout, connect=min(3.0, self.profile.scrape_timeout))
        async with sem:
            if self.stop.is_set() or host_of(url) in self.dead_hosts:
                return
            try:
                async with session.get(url, timeout=timeout) as resp:
                    if resp.status != 200:
                        raise aiohttp.ClientResponseError(
                            resp.request_info, resp.history, status=resp.status, message=resp.reason or ""
                        )
                    text = await resp.text(errors="ignore")
            except Exception as exc:
                self._note_source_error(url, exc)
                return

        fresh: list[tuple] = []
        if proxy_type == "mtproto":
            for proxy in parse_mtproxies(text):
                key = ("mtproto", proxy.host, proxy.port, proxy.secret.lower())
                if key in self.seen:
                    continue
                self.seen.add(key)
                fresh.append(("mtproto", proxy))
        else:
            for match in PROXY_RE.finditer(text):
                proxy = match.group(1)
                key = (proxy_type, proxy)
                if key in self.seen:
                    continue
                self.seen.add(key)
                fresh.append(key)

        random.shuffle(fresh)
        for item in fresh:
            if self.stop.is_set():
                return
            self.scraped += 1
            bucket = self.queues[item[0]]
            while not self.stop.is_set():
                try:
                    bucket.put_nowait(item)
                    break
                except asyncio.QueueFull:
                    await asyncio.sleep(0.05)

    async def _check_http(self, session: aiohttp.ClientSession, proxy: str) -> bool:
        timeout = aiohttp.ClientTimeout(total=self.profile.check_timeout, connect=self.profile.check_timeout)
        try:
            async with session.get(
                self.profile.echo_url,
                proxy=f"http://{proxy}",
                timeout=timeout,
            ) as resp:
                if resp.status != 200:
                    return False
                body = await resp.text(errors="ignore")
        except Exception:
            return False
        ip = extract_ip(body)
        return bool(ip and ip != self.profile.local_ip)

    async def _check_socks(self, proxy_type: str, proxy: str) -> bool:
        scheme = "socks4" if proxy_type == "socks4" else "socks5"
        timeout = aiohttp.ClientTimeout(total=self.profile.check_timeout, connect=self.profile.check_timeout)
        connector = ProxyConnector.from_url(f"{scheme}://{proxy}", rdns=True)
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout, trust_env=False) as session:
                async with session.get(self.profile.echo_url) as resp:
                    if resp.status != 200:
                        return False
                    body = await resp.text(errors="ignore")
        except Exception:
            return False
        ip = extract_ip(body)
        return bool(ip and ip != self.profile.local_ip)

    async def check_one(self, item: tuple) -> bool:
        if item[0] == "mtproto":
            return await check_mtproxy(item[1], self.profile.check_timeout)
        if item[0] == "http":
            return False  # replaced by the shared-session path
        return await self._check_socks(item[0], item[1])

    def _remember(self, item: tuple, elapsed_ms: float) -> None:
        OUT.mkdir(exist_ok=True)
        if item[0] == "mtproto":
            proxy: MtProxy = item[1]
            line = f"{proxy.link}  # {elapsed_ms:.0f}ms"
            kind = "mtproto"
            shown = proxy.link
        else:
            line = f"{item[1]}  # {elapsed_ms:.0f}ms"
            kind = item[0]
            shown = item[1]
        handle = self._files.get(kind)
        if handle is None:
            handle = (OUT / f"{kind}.txt").open("a", encoding="utf-8")
            self._files[kind] = handle
        handle.write(line + "\n")
        handle.flush()
        print(f"proxy type : {kind}    proxy : {shown}    {elapsed_ms:.0f}ms")

    def _queued(self) -> int:
        return sum(queue.qsize() for queue in self.queues.values())

    def _idle(self) -> bool:
        return all(queue.empty() for queue in self.queues.values())

    async def worker(self, http_session: aiohttp.ClientSession, offset: int) -> None:
        order = TYPES[offset % len(TYPES):] + TYPES[: offset % len(TYPES)]
        while not self.stop.is_set():
            item = None
            for kind in order:
                try:
                    item = self.queues[kind].get_nowait()
                except asyncio.QueueEmpty:
                    continue
                order = order[1:] + order[:1]
                break
            if item is None:
                await asyncio.sleep(0.05)
                continue
            started = time.perf_counter()
            try:
                if item[0] == "http":
                    ok = await self._check_http(http_session, item[1])
                else:
                    ok = await self.check_one(item)
            finally:
                self.checked += 1
                self.queues[item[0]].task_done()
            if not ok or self.stop.is_set():
                continue
            elapsed_ms = (time.perf_counter() - started) * 1000
            async with self.lock:
                if self.found >= self.target:
                    self.stop.set()
                    continue
                self.found += 1
                self._remember(item, elapsed_ms)
                if self.found >= self.target:
                    self.stop.set()

    async def status_loop(self) -> None:
        while not self.stop.is_set():
            print(
                f"\rscraped={self.scraped}  queued={self._queued()}  "
                f"checked={self.checked}  found={self.found}/{self.target}   ",
                end="",
                flush=True,
            )
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
        print()

    async def run(self) -> None:
        jobs = load_sources(self.profile)
        profile = self.profile
        print(
            f"network  ip={profile.local_ip}  rtt={profile.rtt_ms:.0f}ms  "
            f"mirror={profile.mirror}  ssl={'verify' if profile.verify_ssl else 'insecure'}  "
            f"workers={profile.check_workers}  "
            f"telegram={'open' if profile.telegram_direct else 'filtered'}"
        )
        print(f"echo {profile.echo_url}")
        print("Scraping + checking in parallel...")

        for kind in TYPES:
            path = OUT / f"{kind}.txt"
            if path.exists():
                path.unlink()

        sem = asyncio.Semaphore(profile.scrape_workers)
        connector = aiohttp.TCPConnector(
            limit=profile.scrape_workers,
            ttl_dns_cache=300,
            ssl=ssl_context(profile.verify_ssl),
            enable_cleanup_closed=True,
        )
        http_connector = aiohttp.TCPConnector(
            limit=profile.check_workers,
            force_close=True,
            ssl=ssl_context(profile.verify_ssl),
            enable_cleanup_closed=True,
        )
        timeout = aiohttp.ClientTimeout(total=profile.scrape_timeout)

        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, trust_env=False,
            headers={"User-Agent": "proxy-scraper/2.0"},
        ) as session, aiohttp.ClientSession(
            connector=http_connector, trust_env=False,
            headers={"User-Agent": "proxy-scraper/2.0"},
        ) as http_session:
            workers = [
                asyncio.create_task(self.worker(http_session, index))
                for index in range(profile.check_workers)
            ]
            status = asyncio.create_task(self.status_loop())
            mt_jobs = [job for job in jobs if job[0] == "mtproto"]
            other_jobs = [job for job in jobs if job[0] != "mtproto"]
            mt_scrapers = [
                asyncio.create_task(self.scrape_one(session, sem, url, proxy_type))
                for proxy_type, url in mt_jobs
            ]
            # Telegram is filtered on this network, so pull those lists first
            # and let checks start before the much larger HTTP/SOCKS files land.
            if mt_scrapers:
                await asyncio.wait(mt_scrapers, timeout=min(6.0, profile.scrape_timeout))
            scrapers = mt_scrapers + [
                asyncio.create_task(self.scrape_one(session, sem, url, proxy_type))
                for proxy_type, url in other_jobs
            ]
            scrapers_done = asyncio.gather(*scrapers)
            stop_wait = asyncio.create_task(self.stop.wait())
            while not self.stop.is_set():
                done, _pending = await asyncio.wait(
                    {stop_wait, scrapers_done},
                    return_when=asyncio.FIRST_COMPLETED,
                    timeout=0.5,
                )
                if stop_wait in done:
                    break
                if scrapers_done in done and self._idle():
                    await asyncio.sleep(profile.check_timeout)
                    if self._idle():
                        break

            self.stop.set()
            for task in workers:
                task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            status.cancel()
            await asyncio.gather(status, scrapers_done, return_exceptions=True)

        for handle in self._files.values():
            handle.close()
        if self.errors:
            (ROOT / "error.txt").write_text("".join(self.errors), encoding="utf-8")

        if self.found >= self.target:
            print(f"finished  ->  {OUT}")
        else:
            print(f"done — only {self.found}/{self.target} working proxies  ->  {OUT}")


def main() -> None:
    from .net import probe

    raw = input("how much proxy? : ").strip()
    try:
        target = int(raw)
    except ValueError:
        raise SystemExit("Enter a number.")
    if target < 1:
        raise SystemExit("Enter a number greater than zero.")
    profile = asyncio.run(probe())
    asyncio.run(Scraper(target, profile).run())
