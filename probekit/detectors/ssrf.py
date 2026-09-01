"""SSRF 检测器：探测服务端是否代发了内部/云元数据请求。

注意：仅向公认的链路本地/内网地址发探测，不触碰任意外网，避免变成放大。
真实场景里出现下列回显即说明服务端代发了请求 -> 存在 SSRF。
"""
from typing import List

from .base import Detector
from ..models import Target, Finding

SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",   # AWS/GCP 云元数据
    "http://127.0.0.1:80/",
    "http://localhost:8080/",
]
# 代发成功后常见的内部内容指纹
INTERNAL_MARKERS = [
    "ami-id", "instance-id", "MOCK_METADATA", "root:x:", "<?xml",
    "shop-api-internal", "internal-service",
]


class SSRFDetector(Detector):
    name = "ssrf"
    severity = "High"

    async def scan(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        # 基线：一个明显外网的、不应被代发的地址（用 IP 字面量，避免 DNS 解析挂死）
        base = await self._get(target, "http://127.0.0.1:1/")
        for internal in SSRF_TARGETS:
            resp = await self._get(target, internal)
            if resp.status == 0:
                continue
            # 命中内部内容指纹
            hit = [m for m in INTERNAL_MARKERS if m.lower() in resp.body.lower()]
            # 或：内网地址有实质回显而基线无
            if hit or (len(resp.body) > 20 and self._similar(resp.body, base.body) < 0.3):
                findings.append(Finding(
                    detector=self.name,
                    severity=self.severity,
                    url=target.url,
                    param=target.param,
                    payload=internal,
                    evidence=(f"回显指纹 {hit}" if hit else
                              f"内网地址返回 {len(resp.body)}B 而基线仅 {len(base.body)}B"),
                    description=f"参数 '{target.param}' 被服务端当作 URL 代发请求，"
                                f"可打到内网/云元数据。",
                    recommendation="禁止代发内网/链路本地地址；URL 白名单；"
                                   "出网走独立低权限网段；禁用重定向跟随。",
                ))
                return findings
        return findings
