"""结果输出：人类可读文本 + JSON。"""
import json
from typing import List

from .models import Finding


def to_text(findings: List[Finding]) -> str:
    if not findings:
        return "[+] 未发现漏洞（仅基于已启用检测器的启发式判断）。"
    lines = [f"[!] 发现 {len(findings)} 个疑似漏洞：\n"]
    for i, f in enumerate(findings, 1):
        lines.append(f"{i}. [{f.severity}] {f.detector} @ {f.url}")
        lines.append(f"   参数 : {f.param}")
        lines.append(f"   Payload: {f.payload}")
        lines.append(f"   证据 : {f.evidence}")
        lines.append(f"   描述 : {f.description}")
        lines.append(f"   修复 : {f.recommendation}")
        lines.append("")
    return "\n".join(lines)


def to_json(findings: List[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2)
