"""识别命令替换与变量展开（基于 lexer 的静态扫描，不执行任何命令）。"""
from __future__ import annotations

from typing import List

from .lexer import Span, scan


def find_command_substitutions(text: str) -> List[Span]:
    """返回全部命令替换区间：kind 为 dollar_paren（$(...)）或 backquote（反引号）。"""
    return list(scan(text).substitutions)


def find_variable_expansions(text: str) -> List[Span]:
    """返回全部变量展开区间：kind 为 variable（$VAR）或 parameter（${VAR}）。"""
    return list(scan(text).variables)


def has_command_substitution(text: str) -> bool:
    return bool(find_command_substitutions(text))

