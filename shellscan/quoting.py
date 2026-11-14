"""引号层级判定：把词法上下文映射为报告用的 layer 取值。"""
from __future__ import annotations

from .lexer import Context, Quote

LAYER_SINGLE = "单引号"
LAYER_DOUBLE = "双引号"
LAYER_BARE = "裸词"
LAYER_SUBST = "命令替换内"

LAYER_VALUES = (LAYER_SINGLE, LAYER_DOUBLE, LAYER_BARE, LAYER_SUBST)


def layer_of(ctx: Context) -> str:
    """按最内层上下文判定层级。

    优先级：单引号 > 命令替换 > 双引号 > 裸词。
    单引号内一切都是字面量；否则只要还在 $(...) 或反引号里就算命令替换内。
    """
    if ctx.quote is Quote.SINGLE:
        return LAYER_SINGLE
    if ctx.in_substitution:
        return LAYER_SUBST
    if ctx.quote is Quote.DOUBLE:
        return LAYER_DOUBLE
    return LAYER_BARE

