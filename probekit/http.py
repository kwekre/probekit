"""异步 HTTP 客户端：并发受限、超时、可选代理、记录耗时。"""
import asyncio
import time
import aiohttp

from .config import Config
from .models import Response


class Requester:
    def __init__(self, config: Config):
        self.config = config
        self._sem = asyncio.Semaphore(config.concurrency)
        self._session: Optional[aiohttp.ClientSession] = None

    async def _session_get(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                headers={"User-Agent": self.config.user_agent},
                trust_env=self.config.proxy is not None,
            )
        return self._session

    async def request(
        self,
        method: str,
        url: str,
        params: dict = None,
        data: dict = None,
    ) -> Response:
        async with self._sem:
            sess = await self._session_get()
            t0 = time.monotonic()
            try:
                async with sess.request(
                    method,
                    url,
                    params=params,
                    data=data,
                    proxy=self.config.proxy,
                    allow_redirects=self.config.follow_redirects,
                    ssl=None if self.config.verify_ssl else False,
                ) as resp:
                    body = await resp.text()
                    elapsed = time.monotonic() - t0
                    return Response(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        url=str(resp.url),
                        elapsed=elapsed,
                    )
            except Exception as e:  # 超时/连接拒绝/SSL 等
                return Response(status=0, headers={}, body="", url=url, error=str(e),
                                 elapsed=time.monotonic() - t0)

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
