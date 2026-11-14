"""sink 定义与模板代入：把待检值替换进命令模板里的占位符。"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple, Union

PLACEHOLDER = "%s"


@dataclass
class Sink:
    sink_id: str
    template: str
    value: str


def load_sinks(path: Union[str, Path]) -> List[Sink]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items = data["sinks"] if isinstance(data, dict) else data
    sinks = []
    for item in items:
        sinks.append(
            Sink(
                sink_id=str(item["sink_id"]),
                template=str(item["template"]),
                value=str(item["value"]),
            )
        )
    return sinks


def substitute(template: str, value: str) -> Tuple[str, int]:
    """把值代入模板，返回（代入后的完整命令， 值起始下标）。"""
    count = template.count(PLACEHOLDER)
    if count != 1:
        raise ValueError(
            f"模板必须恰好包含一个 {PLACEHOLDER!r} 占位符，实际 {count} 个: {template!r}"
        )
    start = template.index(PLACEHOLDER)
    return template[:start] + value + template[start + len(PLACEHOLDER):], start

