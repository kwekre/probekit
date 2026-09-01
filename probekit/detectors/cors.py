"""CORS 错误配置检测（站点级）：发送伪造 Origin，观察 Access-Control-Allow-Origin
是否反射任意来源且允许携带凭据。仅当可实际被跨站读取时才报 High，避免误报。
"""
from typing import List

from ..models import Finding, Target


class CorsDetector:
    name = "cors"
    severity = "High"

    def __init__(self, requester, config):
        self.req = requester
        self.cfg = config

    async def scan(self, target: Target) -> List[Finding]:
        if not target.is_site:
            return []
        evil = "https://evil.example.com"
        resp = await self.req.request("GET", target.url,
                                      headers={"Origin": evil,
                                               **(self.cfg.headers or {})})
        if resp.status == 0:
            return []
        acao = (resp.headers.get("access-control-allow-origin") or "").strip()
        acac = (resp.headers.get("access-control-allow-credentials") or "").strip().lower()

        findings: List[Finding] = []
        allow_creds = acac == "true"

        # 情形1：反射任意来源 + 允许凭据 → 任何网站可带用户凭据读取响应（高危）
        if allow_creds and evil in acao:
            findings.append(Finding(
                detector=self.name, severity="High", url=target.url, param="",
                payload=f"Origin: {evil}",
                evidence=f"ACAO={acao}; ACAC={acac}",
                description="服务端将任意 Origin 反射进 Access-Control-Allow-Origin 且"
                            "允许携带凭据，任意第三方站点可读取该接口（含 Cookie/鉴权）"
                            "的响应内容，造成跨站数据泄露。",
                recommendation="不要按请求 Origin 原样反射；白名单固定可信来源；"
                               "带凭据时禁止用通配符 *；收紧暴露的敏感接口。"))
        # 情形2：反射 null（沙盒 iframe 可伪造） + 允许凭据 → 中危
        elif allow_creds and acao == "null":
            findings.append(Finding(
                detector=self.name, severity="Medium", url=target.url, param="",
                payload=f"Origin: {evil}",
                evidence=f"ACAO={acao}; ACAC={acac}",
                description="服务端对 Origin: null 返回允许凭据，攻击者可借沙盒"
                            "iframe(iframe sandbox)伪造 null 源读取响应。",
                recommendation="避免使用 null 作为允许来源；改为白名单；带凭据时"
                               "显式校验来源。"))

        # 说明：ACAO=* 且 ACAC=true 时浏览器会拒绝携带凭据，不报（避免误报）。
        return findings
