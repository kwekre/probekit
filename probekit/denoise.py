"""响应差异去噪：比较两个响应时，先剥离高熵随机变量（CSRF token、会话 ID、
UUID、时间戳、哈希、JWT 等），只比较“应用真实行为”差异，从而降低误报/漏报。

为什么需要：很多页面每次响应都带不同的 CSRF token / 会话 ID / 时间戳。若直接按
原文长度比相似度，基线响应与注入响应会因为这些噪声而“看起来不同”，导致布尔盲注
误判、或 SSRF 基线比对失效。去噪后再比，只剩真正的业务差异。
"""
import re
from typing import Dict, Union

# 响应头里每次都变、对“是否漏洞”无意义的键（大小写不敏感）
VOLATILE_HEADERS = {
    "set-cookie", "date", "etag", "expires", "last-modified",
    "x-request-id", "x-runtime", "server-timing", "age", "content-length",
    "vary", "x-cache", "x-amz-request-id", "x-powered-by", "x-envoy-upstream-service-time",
}

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_HEX64_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_HEX40_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
_HEX32_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?")
_TS13_RE = re.compile(r"\b\d{13}\b")          # 毫秒时间戳
_TOKEN_RE = re.compile(
    r"(?i)((?:csrf|__token|nonce|authtoken|token|sessionid)[a-z0-9_]*)"
    r"""["']?\s*[=:]\s*["']?([^"'\s&<>`]+)""")
# 通用长随机串（会话 ID / base64 blob 等，>=24 位字母数字）
_RAND_RE = re.compile(r"\b[a-zA-Z0-9]{24,}\b")


def _mask_token(m: "re.Match") -> str:
    return f"{m.group(1)}=<SECRET>"


def normalize_body(body: str) -> str:
    """把响应体里的高熵随机变量替换为占位符，保留真实业务文本。"""
    if not body:
        return ""
    s = body
    s = _JWT_RE.sub("<JWT>", s)
    s = _UUID_RE.sub("<UUID>", s)
    s = _HEX64_RE.sub("<H64>", s)
    s = _HEX40_RE.sub("<H40>", s)
    s = _HEX32_RE.sub("<H32>", s)
    s = _TS_RE.sub("<TS>", s)
    s = _TS13_RE.sub("<TS13>", s)
    s = _TOKEN_RE.sub(_mask_token, s)
    s = _RAND_RE.sub("<RAND>", s)
    return s


def normalize_headers(headers: Union[dict, "object"]) -> Dict[str, str]:
    """丢弃每次都变的响应头，返回用于比对的干净头字典。"""
    out: Dict[str, str] = {}
    items = headers.items() if hasattr(headers, "items") else (headers or {})
    for k, v in items:
        if str(k).lower() in VOLATILE_HEADERS:
            continue
        out[str(k)] = str(v)
    return out


def normalized_similar(a: str, b: str) -> float:
    """去噪后的长度比相似度（0~1）。先 normalize 再比，避免 token 抖动干扰。"""
    na, nb = normalize_body(a), normalize_body(b)
    if not na and not nb:
        return 1.0
    return min(len(na), len(nb)) / max(len(na), len(nb))
