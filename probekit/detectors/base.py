"""检测器基类。每个检测器对单个 (url, param) 入口做检测，返回 Finding 列表。"""
from abc import ABC, abstractmethod
from typing import List

from ..http import Requester
from ..config import Config
from ..models import Target, Finding


class Detector(ABC):
    name: str = "base"
    severity: str = "Medium"

    def __init__(self, requester: Requester, config: Config):
        self.req = requester
        self.cfg = config

    @abstractmethod
    async def scan(self, target: Target) -> List[Finding]:
        ...

    # ---- 工具方法 ----
    async def _get(self, target: "Target", value: str) -> "object":
        """按参数所在位置(query/body)构造请求并发送。"""
        if target.location == "body":
            data = dict(target.body_params)
            data[target.param] = value
            return await self.req.request(target.method, target.url, data=data)
        p = dict(target.params)
        p[target.param] = value
        return await self.req.request(target.method, target.url, params=p)

    async def _raw(self, url: str, headers: dict = None) -> "object":
        """直接发一个请求（站点级检测用，如 JWT 取基线）。"""
        return await self.req.request("GET", url, headers=headers or {})

    @staticmethod
    def _similar(a: str, b: str) -> float:
        """基于长度比的相似度，0(完全不同)~1(等长)。"""
        if not a and not b:
            return 1.0
        return min(len(a), len(b)) / max(len(a), len(b))
