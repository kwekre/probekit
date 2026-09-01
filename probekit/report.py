"""结果输出：人类可读文本 + JSON + SARIF(可接入 CI)。"""
import json
from typing import List

from .models import Finding, severity_rank


def _summary(findings: List[Finding]) -> str:
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    order = ["Critical", "High", "Medium", "Low", "Info"]
    parts = [f"{s}:{counts[s]}" for s in order if s in counts]
    return "，".join(parts) if parts else "无"


def to_text(findings: List[Finding]) -> str:
    if not findings:
        return "[+] 未发现漏洞（仅基于已启用检测器的启发式判断）。"
    head = f"[!] 发现 {len(findings)} 个疑似漏洞（{_summary(findings)}）：\n"
    lines = [head]
    for i, f in enumerate(sorted(findings, key=lambda x: -severity_rank(x.severity)), 1):
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


def to_sarif(findings: List[Finding], tool: str = "probekit") -> str:
    """输出 SARIF 2.1.0，可被 GitHub Code Scanning / 其它 CI 消费。"""
    rules = {}
    for f in findings:
        rules.setdefault(f.detector, {
            "id": f.detector,
            "name": f.detector,
            "shortDescription": {"text": f.detector},
            "fullDescription": {"text": f.description},
            "help": {"text": f"{f.description}\n修复: {f.recommendation}"},
        })
    results = []
    level_map = {"Critical": "error", "High": "error", "Medium": "warning",
                 "Low": "note", "Info": "note"}
    for f in findings:
        results.append({
            "ruleId": f.detector,
            "level": level_map.get(f.severity, "warning"),
            "message": {"text": f"{f.evidence} | 修复: {f.recommendation}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.url},
                    "region": {"snippet": {"text": f"param={f.param} payload={f.payload}"}},
                }
            }],
            "properties": {"severity": f.severity, "param": f.param,
                           "payload": f.payload},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool, "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)
