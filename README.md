# proxy scraper

Finds public HTTP, SOCKS4, SOCKS5, and Telegram MTProto proxies, then keeps
only the ones that actually work on the network running the script.

On startup it measures that network: which IP-echo answers, which GitHub
mirror answers, TLS verification, and a worker count sized to the latency.
A proxy is saved only when the exit IP is different from this machine, or,
for MTProto, when Telegram answers the handshake.

## Run

```
pip install -r requirements.txt
python3 dd.py
```

Results are appended to `out/http.txt`, `out/socks4.txt`, `out/socks5.txt`,
and `out/mtproto.txt` (`tg://proxy?...` links).
