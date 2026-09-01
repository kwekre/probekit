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
        # 用原始查询字典 + 被测参数覆盖，避免 URL 自带 query 与 params 合并冲突
        p = dict(target.params)
        p[target.param] = value
        return await self.req.request("GET", target.url, params=p)

    @staticmethod
    def _similar(a: str, b: str) -> float:
        """基于长度比的相似度，0(完全不同)~1(等长)。"""
        if not a and not b:
            return 1.0
        return min(len(a), len(b)) / max(len(a), len(b))
