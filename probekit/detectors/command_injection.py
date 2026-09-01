"""命令注入检测器：基于回显标记与执行耗时两类信号。仅对授权目标使用。"""
import asyncio
from typing import List

from ..models import Target, Finding
from .base import Detector


MARKER = "PRBCMD7Z9"
SLEEP_S = 5


class CommandInjectionDetector(Detector):
    name = "command_injection"
    severity = "High"

    async def scan(self, target: Target) -> List[Finding]:
        if target.is_site:
            return []
        findings = []
        echo_payloads = [
            f";echo {MARKER}", f"|echo {MARKER}",
            f"$(echo {MARKER})", f"`echo {MARKER}`",
        ]
        time_payloads = [
            f";sleep {SLEEP_S}", f"|sleep {SLEEP_S}",
            f"$(sleep {SLEEP_S})", f"`sleep {SLEEP_S}`",
        ]
        # 1) 回显标记
        for p in echo_payloads:
            try:
                resp = await self._get(target, target.original + p)
            except Exception:
                continue
            if resp.error:
                continue
            if MARKER in resp.body:
                return [self._mk(target, p, f"响应中出现命令执行回显标记 {MARKER}")]
        # 2) 时间盲注
        for p in time_payloads:
            try:
                resp = await self._get(target, target.original + p)
            except Exception:
                continue
            if not resp.error and resp.elapsed >= SLEEP_S * 0.8:
                return [self._mk(target, p,
                                 f"注入 sleep 后响应耗时 {resp.elapsed:.1f}s")]
        return findings

    @staticmethod
    def _mk(target: Target, payload: str, evidence: str) -> Finding:
        return Finding(
            detector=CommandInjectionDetector.name,
            severity=CommandInjectionDetector.severity,
            url=target.url, param=target.param, payload=payload,
            evidence=evidence,
            description="参数疑似被拼接到系统命令中执行，可通过分隔符注入额外命令。",
            recommendation="禁止拼接命令；使用白名单参数 + 最小权限子进程；必要时用 "
                           "shlex.quote / 参数数组调用，并对输入做严格校验。",
        )
