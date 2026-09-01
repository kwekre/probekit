"""检测器基类。每个检测器对单个 (url, param) 入口做检测，返回 Finding 列表。"""
from abc import ABC, abstractmethod
from typing import List

from ..http import Requester
from ..config import Config
from ..models import Target, Finding
from ..denoise import normalized_similar


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
        """去噪后的响应相似度（0~1）。

        先剥离 CSRF/会话/时间戳/哈希/JWT 等高熵随机变量再比长度，
        避免页面每次响应都带的 token 抖动造成布尔盲注误判或 SSRF 基线失效。
        """
        return normalized_similar(a, b)
