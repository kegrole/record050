"""命令行入口：python -m shellscan.cli --sinks demo/sinks.json --out out/report.json"""
from __future__ import annotations

import argparse
from typing import Optional, Sequence

from .detector import analyze
from .report import build_report, write_report
from .sinks import load_sinks


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shellscan",
        description="静态分析模板命令中的取值是否构成 shell 注入（不执行任何命令）",
    )
    parser.add_argument("--sinks", required=True, help="sink 定义 JSON（模板 + 取值）")
    parser.add_argument("--out", required=True, help="报告输出路径")
    args = parser.parse_args(argv)

    sinks = load_sinks(args.sinks)
    findings = [analyze(sink) for sink in sinks]
    report = build_report(findings)
    write_report(report, args.out)

    summary = report["summary"]
    print(f"检查 {summary['total']} 条：危险 {summary['dangerous']} 条，安全 {summary['safe']} 条")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

