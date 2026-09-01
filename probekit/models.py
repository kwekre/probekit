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


@dataclass
class Target:
    """一个待检测的参数入口。
    url 为去掉查询串的 base；params 为原始查询字典（用于保留其他参数）。
    """
    url: str
    param: str
    method: str = "GET"
    original: str = ""            # 被测参数原始值
    params: dict = field(default_factory=dict)  # 原始全部查询参数


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
