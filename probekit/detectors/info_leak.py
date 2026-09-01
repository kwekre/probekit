"""敏感信息泄露检测（站点级）：扫描响应体，发现密钥/内网 IP/栈跟踪/JWT 等泄露。
指纹均为高置信模式，刻意避免宽泛正则以降低误报。站点级：每个 URL 仅请求一次。
"""
import re
from typing import List, Tuple

from ..models import Finding, Target


# (标签, 严重度, 正则, 描述, 修复建议)
_PATTERNS: List[Tuple[str, str, "re.Pattern", str, str]] = [
    ("private_key", "High",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
     "响应体包含私钥（PEM）内容，攻击者可借此伪造身份或解密流量。",
     "立即吊销并轮换泄露的密钥；禁止在服务端源码/配置/错误信息中回显密钥；用密钥管理服务(KMS/Vault)托管。"),
    ("aws_access_key", "High",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "响应体出现 AWS Access Key ID（AKIA...），可能被用于横向或资源访问。",
     "立即在 IAM 禁用并轮换该 AK；开启 CloudTrail 审计；避免把密钥写入前端/接口响应。"),
    ("gcp_api_key", "High",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     "响应体出现 Google API Key（AIza...）。",
     "在 GCP 控制台轮换并限制该 Key 的 API 范围；不要在前端硬编码服务密钥。"),
    ("internal_ip", "Medium",
     re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                r"|192\.168\.\d{1,3}\.\d{1,3}"
                r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
                r"|127\.0\.0\.1)\b"),
     "响应体泄露内网 RFC1918/回环地址，暴露网络拓扑，便于攻击者定向内网探测。",
     "不要在前端/报错/接口响应中回显内网 IP；用反向代理隐藏真实后端；统一错误信息。"),
    ("stack_trace", "Low",
     re.compile(r"(Traceback \(most recent call last\)|java\.lang\.\w*Exception"
                r"|at (?:com|org|net)\.[\w.]+\(|ORA-\d{5}|SQLSTATE\[)"),
     "响应体包含栈跟踪/异常细节，泄露技术栈与代码路径，辅助攻击者构造利用。",
     "生产环境关闭详细报错；返回通用错误页；栈跟踪仅记录到服务端日志。"),
    ("jwt_in_body", "Low",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]+"),
     "响应体返回 JWT（可能含权限声明），若泄露/可预测会带来越权风险。",
     "JWT 仅在必要场景返回；使用强密钥(HS256)或非对称(RS256)；设置短过期与 audience 校验。"),
]


class InfoLeakDetector:
    name = "info_leak"
    severity = "Medium"

    def __init__(self, requester, config):
        self.req = requester
        self.cfg = config

    async def scan(self, target: Target) -> List[Finding]:
        if not target.is_site:
            return []
        resp = await self.req.request("GET", target.url,
                                      headers=self.cfg.headers or {})
        if resp.status == 0 or not resp.body:
            return []
        findings: List[Finding] = []
        for label, sev, pat, desc, rec in _PATTERNS:
            m = pat.search(resp.body)
            if m:
                findings.append(Finding(
                    detector=self.name, severity=sev, url=target.url,
                    param="", payload="",
                    evidence=f"[{label}] ...{m.group(0)[:80]}...",
                    description=desc, recommendation=rec))
        return findings
