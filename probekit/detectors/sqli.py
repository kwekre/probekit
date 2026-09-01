"""SQL 注入检测器：报错型 / 布尔盲注 / 时间盲注。"""
import re
from typing import List

from .base import Detector
from ..models import Target, Finding

# 常见数据库报错指纹
ERROR_SIGNS = [
    r"you have an error in your sql syntax",
    r"sqlstate\[",
    r"mysql_fetch",
    r"unclosed quotation mark",
    r"odbc driver",
    r"ora-\d{5}",
    r"sqlite_error",
    r"pg_query\(\)",
    r"supplied argument is not a valid mysql",
    r"warning: mysqli",
]

# 数字型 / 字符型 布尔对比后缀
BOOL_TRUE = [" AND 1=1", "') AND ('1'='1", "\" AND \"1\"=\"1"]
BOOL_FALSE = [" AND 1=2", "') AND ('1'='2", "\" AND \"1\"=\"2"]

# 时间盲注（MySQL / PostgreSQL / MSSQL）
TIME_PAYLOADS = [" AND SLEEP(%d)", " AND PG_SLEEP(%d)", "; WAITFOR DELAY '0:0:%d'"]


class SQLiDetector(Detector):
    name = "sqli"
    severity = "High"

    async def scan(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        orig = target.original or "1"

        # 1) 报错型
        for quote in ["'", "\"", "`)", "')"]:
            resp = await self._get(target, orig + quote)
            for sig in ERROR_SIGNS:
                if re.search(sig, resp.body, re.I):
                    findings.append(self._mk(target, orig + quote,
                                             f"响应命中数据库报错指纹: {sig}",
                                             "报错型注入"))
                    break
            if findings:
                return findings  # 报错型最确凿，直接返回

        # 2) 布尔盲注
        base = await self._get(target, orig)
        for t, f in zip(BOOL_TRUE, BOOL_FALSE):
            r_t = await self._get(target, orig + t)
            r_f = await self._get(target, orig + f)
            if r_t.status == 0 or r_f.status == 0 or base.status == 0:
                continue
            # true 与 baseline 相似，false 与 baseline 明显不同
            sim_t = self._similar(r_t.body, base.body)
            sim_f = self._similar(r_f.body, base.body)
            diff = sim_t - sim_f
            if diff >= self.cfg.bool_ratio and sim_t > 0.9:
                findings.append(self._mk(target, orig + t,
                                         f"布尔对比: true 与基线相似度 {sim_t:.2f}, "
                                         f"false 与基线相似度 {sim_f:.2f}",
                                         "布尔盲注"))
                return findings

        # 3) 时间盲注
        for p in TIME_PAYLOADS:
            payload = orig + p % self.cfg.time_sleep
            r = await self._get(target, payload)
            if r.status != 0 and r.elapsed >= self.cfg.time_sleep * 0.8:
                findings.append(self._mk(target, payload,
                                         f"响应耗时 {r.elapsed:.2f}s (预期 {self.cfg.time_sleep}s)",
                                         "时间盲注"))
                return findings
        return findings

    def _mk(self, target: Target, payload: str, evidence: str, kind: str) -> Finding:
        return Finding(
            detector=self.name,
            severity=self.severity,
            url=target.url,
            param=target.param,
            payload=payload,
            evidence=evidence,
            description=f"参数 '{target.param}' 存在 {kind} SQL 注入，"
                        f"攻击者可读取/篡改数据库。",
            recommendation="使用参数化查询(预编译)；数据库账号最小权限；"
                           "生产环境关闭详细报错；输入做白名单校验。",
        )
