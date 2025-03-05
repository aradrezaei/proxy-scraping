import aiohttp, asyncio
from re import search
from aiohttp_socks import ProxyConnector
from argparse import ArgumentParser
from re import compile
from os import system, name
from threading import Thread
from time import sleep


user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
REGEX = compile(
    r"(?:^|\D)?(("+ r"(?:[1-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])"
    + r"\." + r"(?:\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])"
    + r"\." + r"(?:\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])"
    + r"\." + r"(?:\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])"
    + r"):" + (r"(?:\d|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}"
    + r"|65[0-4]\d{2}|655[0-2]\d|6553[0-5])")
    + r")(?:\D|$)"
)


class morf:
    def __init__(self,number):
        self.count=0
        self.num=number
        self.tasks = 255
    def run(self):
        while True:
            async def inner(proxies: tuple):
                await asyncio.wait(
                    [asyncio.create_task(self.request(proxy, proxy_type))
                    for proxy_type, proxy in proxies])
            auto = Auto()
            chunks = [auto.proxies[i:i+self.tasks] for i in range(0, len(auto.proxies), self.tasks)]
            for chunk in chunks: asyncio.run(inner(chunk))


    async def request(self, proxy: str, proxy_type: str):
        if proxy_type == 'socks4': connector = ProxyConnector.from_url(f'socks4://{proxy}')
        elif proxy_type == 'socks5': connector = ProxyConnector.from_url(f'socks5://{proxy}')
        elif proxy_type == 'https': connector = ProxyConnector.from_url(f'https://{proxy}')
        else: connector = ProxyConnector.from_url(f'http://{proxy}')
        if self.count>=self.num:
           print("finished")
           exit()
        else:
           jar = aiohttp.CookieJar(unsafe=True)
           async with aiohttp.ClientSession(cookie_jar=jar, connector=connector) as session:
               try:
                   async with session.get('https://www.instagram.com',timeout=aiohttp.ClientTimeout(total=5)) as embed_response:
                       if (embed_response.status == 200):
                           print(f'proxy type : {proxy_type}    proxy : {proxy}')
                           self.count+=1
               except:
                   pass
            
class Auto:
    def __init__(self):
        self.proxies = []
        try:
            with open(f'auto/http.txt', 'r') as file:
                self.http_sources = file.read().splitlines()
            with open(f'auto/socks4.txt', 'r') as file:
                self.socks4_sources = file.read().splitlines()
            with open(f'auto/socks5.txt', 'r') as file:
                self.socks5_sources = file.read().splitlines()
        except FileNotFoundError: 
            print(' [ Error ] auto file not found!')
            exit()
        print('Scraping proxies... ')
        asyncio.run(self.init())


    async def scrap(self, source_url, proxy_type):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    source_url, 
                    headers={'user-agent': user_agent}, 
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    html = await response.text()
                    if tuple(REGEX.finditer(html)):
                        for proxy in tuple(REGEX.finditer(html)):
                            self.proxies.append( (proxy_type, proxy.group(1)) )
        except Exception as e:
            with open('error.txt', 'a', encoding='utf-8', errors='ignore') as f:
                f.write(f'{source_url} -> {e}\n')


    async def init(self):
        tasks = []
        self.proxies.clear()
        for sources in (
            (self.http_sources, 'http'), 
            (self.socks4_sources, 'socks4'), 
            (self.socks5_sources, 'socks5') 
        ):
            srcs, proxy_type = sources
            for source_url in srcs: 
                task = asyncio.create_task(
                    self.scrap(source_url, proxy_type)
                )
                tasks.append(task)
        await asyncio.wait(tasks)


if __name__ == '__main__':
   number = int(input("how much proxy? : "))
   morfix = morf(number)
   morfix.run()
