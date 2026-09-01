"""扫描器配置。"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Config:
    timeout: float = 10.0
    concurrency: int = 10
    user_agent: str = "probekit/0.1 (+authorized-security-scanner)"
    proxy: Optional[str] = None
    follow_redirects: bool = False
    verify_ssl: bool = True
    # 自定义请求头（如认证）：{"Authorization": "Bearer xxx", "Cookie": "sid=yyy"}
    headers: dict = field(default_factory=dict)
    # 时间盲注休眠秒数（服务端），判定阈值 = sleep * 0.8
    time_sleep: int = 5
    # 布尔盲注：true/false 响应长度差超过该比例视为差异
    bool_ratio: float = 0.05
