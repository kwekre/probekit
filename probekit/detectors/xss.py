"""反射型 XSS 检测器：注入唯一标记，检查是否被原样回显。"""
from typing import List

from .base import Detector
from ..models import Target, Finding

# 用唯一标记，避免误报普通关键词。注入后检查标记是否原样回显（未编码）。
MARKERS = [
    "prb<x>",
    "prb<img src=x onerror=1>",
    "prb<svg/onload=1>",
]


class XSSDetector(Detector):
    name = "xss"
    severity = "Medium"

    async def scan(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        orig = target.original or "x"
        for sent in MARKERS:
            resp = await self._get(target, orig + sent)
            # 未编码回显（注意大小写归一）
            if sent.lower() in resp.body.lower():
                findings.append(Finding(
                    detector=self.name,
                    severity=self.severity,
                    url=target.url,
                    param=target.param,
                    payload=orig + sent,
                    evidence=f"响应中原样出现未编码标记 {sent}",
                    description=f"参数 '{target.param}' 将输入反射到 HTML 且未过滤/编码，"
                                f"可构造反射型 XSS。",
                    recommendation="输出到 HTML 处做 HTML 实体编码；"
                                   "设置 CSP；关键操作加 CSRF Token。",
                ))
                return findings
        return findings
