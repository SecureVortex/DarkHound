import aiohttp

async def tor_get(url):
    # Example using local Tor SOCKS5 proxy at 127.0.0.1:9050
    # Requires Tor running locally!
    proxy = "socks5://127.0.0.1:9050"
    async with aiohttp.ClientSession() as session:
        async with session.get(url, proxy=proxy, timeout=30) as resp:
            return await resp.text()