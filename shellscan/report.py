"""生成 JSON 报告。报告中只包含静态分析结论，不含任何命令执行结果。"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Iterable, Union

from .detector import DANGEROUS, Finding


def build_report(findings: Iterable[Finding]) -> Dict:
    items = [asdict(f) for f in findings]
    dangerous = sum(1 for item in items if item["verdict"] == DANGEROUS)
    return {
        "summary": {
            "total": len(items),
            "dangerous": dangerous,
            "safe": len(items) - dangerous,
        },
        "findings": items,
    }


def write_report(report: Dict, path: Union[str, Path]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

