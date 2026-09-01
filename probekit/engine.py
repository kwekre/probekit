"""扫描引擎：解析目标参数、调度检测器、汇总结果。可选同源爬虫扩展检测面。"""
import asyncio
from urllib.parse import urlsplit, parse_qsl
from typing import List

from .http import Requester
from .config import Config
from .models import Target, Finding
from .detectors import ALL_DETECTORS
from .crawler import targets_from_html


class Scanner:
    def __init__(self, config: Config = None):
        self.cfg = config or Config()
        self.req = Requester(self.cfg)
        self.detectors = ALL_DETECTORS

    @staticmethod
    def extract_targets(url: str) -> List[Target]:
        """从 URL 查询串拆出每个参数作为 GET 检测入口。"""
        parts = urlsplit(url)
        base = parts.scheme + "://" + parts.netloc + parts.path
        all_params = {k: (v[0] if v else "") for k, v in
                      parse_qsl(parts.query, keep_blank_values=True)}
        return [Target(url=base, param=k, original=v, params=all_params)
                for k, v in all_params.items()]

    async def scan_url(self, url: str, crawl: bool = False) -> List[Finding]:
        targets = self.extract_targets(url)
        if crawl:
            base_resp = await self.req.request("GET", url)
            if base_resp.status != 0:
                targets.extend(targets_from_html(base_resp.body, url))
        # 站点级检测（JWT 等）：忽略具体参数
        targets.append(Target(url=url, param="", is_site=True))

        tasks = [Det(self.req, self.cfg).scan(t) for t in targets
                 for Det in self.detectors]
        results = await asyncio.gather(*tasks)
        return [f for sub in results for f in sub]

    async def scan_urls(self, urls: List[str], crawl: bool = False) -> List[Finding]:
        all_findings: List[Finding] = []
        for url in urls:
            all_findings.extend(await self.scan_url(url, crawl=crawl))
        return all_findings

    async def close(self):
        await self.req.close()
