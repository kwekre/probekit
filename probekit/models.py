"""数据模型：请求响应、目标、发现结果。"""
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Response:
    status: int
    headers: dict
    body: str
    url: str
    error: str = ""
    elapsed: float = 0.0

    @property
    def text_len(self) -> int:
        return len(self.body)


SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]


def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 0


@dataclass
class Target:
    """一个待检测的参数入口。
    url 为去掉查询串的 base；params 为原始查询字典（用于保留其他参数）。
    location 指示被测参数位于 query 还是 body（POST 表单）。
    """
    url: str
    param: str
    method: str = "GET"
    original: str = ""                  # 被测参数原始值
    params: dict = field(default_factory=dict)   # 原始查询参数(GET/POST 页 query)
    body_params: dict = field(default_factory=dict)  # 原始表单参数(POST)
    location: str = "query"             # query | body
    is_site: bool = False               # 站点级检测(JWT 等)忽略 param


@dataclass
class Finding:
    detector: str
    severity: str          # Critical / High / Medium / Low / Info
    url: str
    param: str
    payload: str
    evidence: str
    description: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)
