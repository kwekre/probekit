"""扫描引擎：解析目标参数、调度检测器、汇总结果。"""
import asyncio
from urllib.parse import urlsplit, parse_qsl
from typing import List

from .http import Requester
from .config import Config
from .models import Target, Finding
from .detectors import ALL_DETECTORS


class Scanner:
    def __init__(self, config: Config = None):
        self.cfg = config or Config()
        self.req = Requester(self.cfg)
        self.detectors = ALL_DETECTORS

    @staticmethod
    def extract_targets(url: str) -> List[Target]:
        parts = urlsplit(url)
        # base：去掉查询串，避免和 params 合并冲突
        base = parts.scheme + "://" + parts.netloc + parts.path
        all_params = {k: (v[0] if v else "") for k, v in parse_qsl(parts.query, keep_blank_values=True)}
        return [Target(url=base, param=k, original=v, params=all_params)
                for k, v in all_params.items()]

    async def scan_url(self, url: str) -> List[Finding]:
        targets = self.extract_targets(url)
        tasks = [Det(self.req, self.cfg).scan(t) for t in targets for Det in self.detectors]
        results = await asyncio.gather(*tasks)
        return [f for sub in results for f in sub]

    async def scan_urls(self, urls: List[str]) -> List[Finding]:
        all_findings: List[Finding] = []
        for url in urls:
            all_findings.extend(await self.scan_url(url))
        return all_findings

    async def close(self):
        await self.req.close()
