"""开放重定向检测器：注入外部地址，检查 3xx Location 或 meta refresh 是否跳转。"""
from typing import List
import re

from .base import Detector
from ..models import Target, Finding

EVIL = "evil.example.com"
PAYLOADS = [
    f"//{EVIL}/",                 # 协议相对
    f"https://{EVIL}/",           # 绝对
    f"\\\\{EVIL}\\",              # 反斜杠变体
    f"/\\{EVIL}",                 # 部分框架解析差异
]


class OpenRedirectDetector(Detector):
    name = "openredirect"
    severity = "Low"

    async def scan(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        # 该检测器需要看到重定向，故要求引擎以 follow_redirects=False 调用
        for p in PAYLOADS:
            resp = await self._get(target, p)
            # 1) 3xx 头 Location
            loc = resp.headers.get("Location", "")
            if EVIL in loc:
                findings.append(self._mk(target, p, f"Location: {loc}"))
                return findings
            # 2) meta refresh / JS 跳转
            if re.search(rf"(meta[^>]+url=|window\.location|location\.href)[^>]*{EVIL}",
                         resp.body, re.I):
                findings.append(self._mk(target, p, "响应体含跳转到 evil.example.com"))
                return findings
        return findings

    def _mk(self, target: Target, payload: str, evidence: str) -> Finding:
        return Finding(
            detector=self.name,
            severity=self.severity,
            url=target.url,
            param=target.param,
            payload=payload,
            evidence=evidence,
            description=f"参数 '{target.param}' 未校验跳转目标，可被导向外部站点，"
                        f"用于钓鱼/令牌泄露。",
            recommendation="跳转目标做白名单；使用内部路由标识而非外部 URL；"
                           "关键跳转二次确认。",
        )
