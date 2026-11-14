"""静态判定逻辑：把取值代入模板后按引号层级分析。不执行任何命令。"""
from __future__ import annotations

from dataclasses import dataclass

from .expansion import find_variable_expansions
from .lexer import BACKQUOTE, scan
from .quoting import LAYER_BARE, LAYER_DOUBLE, LAYER_SINGLE, LAYER_SUBST, layer_of
from .sinks import Sink, substitute

DANGEROUS = "危险"
SAFE = "安全"

_DQUOTE_ESCAPABLE = frozenset("$" + BACKQUOTE + '"\x5c\n')
_SEPARATORS = {";": "分号", "|": "管道符", "&": "后台符", "\n": "换行"}


@dataclass
class Finding:
    sink_id: str
    template: str
    value: str
    verdict: str
    layer: str
    reason: str


def _find_unescaped_dquote(value: str) -> int:
    """在双引号语义下找第一个能闭合模板引号的未转义双引号。"""
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\x5c" and i + 1 < len(value) and value[i + 1] in _DQUOTE_ESCAPABLE:
            i += 2
            continue
        if ch == '"':
            return i
        i += 1
    return -1


def _find_bare_char(value: str, targets) -> int:
    """在裸词语义下找第一个未转义的目标字符。"""
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\x5c" and i + 1 < len(value):
            i += 2
            continue
        if ch in targets:
            return i
        i += 1
    return -1


def _analyze_double(value: str):
    close_at = _find_unescaped_dquote(value)
    if close_at >= 0:
        rest = value[close_at + 1:]
        sep_at = _find_bare_char(rest, _SEPARATORS)
        if sep_at >= 0:
            name = _SEPARATORS[rest[sep_at]]
            return DANGEROUS, (
                f"值中的双引号先闭合了模板的引号，随后{name}终止了命令，"
                "其后的内容会作为新的命令被解析"
            )
        return DANGEROUS, "值中的双引号闭合了模板的引号，剩余内容落在裸词位置，会被重新分词与展开"
    if BACKQUOTE in value:
        return DANGEROUS, "值位于双引号内，但反引号在双引号内仍会触发命令替换，命令会被执行"
    if "$(" in value:
        return DANGEROUS, "值位于双引号内，但 $(...) 命令替换在双引号内依然会执行命令"
    if "$" in value:
        expansions = find_variable_expansions(value)
        if expansions:
            frag = value[expansions[0].start:expansions[0].end]
            return DANGEROUS, f"变量展开在双引号内依然生效：{frag} 会被 shell 求值后替换进命令"
        return DANGEROUS, "变量展开在双引号内依然生效：值中的 $ 会被 shell 求值"
    if "\x5c" in value:
        return DANGEROUS, "值位于双引号内，但反斜杠在双引号内仍具有转义作用，可能改变后续解析"
    if "\n" in value:
        return DANGEROUS, "值位于双引号内且含有换行，可能改变命令的边界"
    if "'" in value:
        return SAFE, "值位于双引号内，单引号在双引号内只是普通字符；值也不含 $、反引号、反斜杠或换行"
    return SAFE, "值位于双引号内且不含 $、反引号、反斜杠或换行，按字面量处理"


def _analyze_bare(value: str):
    if value == "":
        return SAFE, "值为空，不构成注入"
    sep_at = _find_bare_char(value, _SEPARATORS)
    if sep_at >= 0:
        ch = value[sep_at]
        if ch == "\n":
            return DANGEROUS, "值位于裸词位置，换行在裸词位置终结了原命令，其后的内容会作为新命令执行"
        if ch == ";":
            return DANGEROUS, "值位于裸词位置，分号会终结当前命令，其后的内容会作为新命令执行"
        if ch == "|":
            return DANGEROUS, "值位于裸词位置，管道符会把前后内容拼接成两条命令"
        return DANGEROUS, "值位于裸词位置，& 会让命令转入后台并拼接后续命令"
    if BACKQUOTE in value or "$(" in value:
        return DANGEROUS, "值位于裸词位置且包含命令替换，命令替换会执行命令"
    if "$" in value:
        return DANGEROUS, "值位于裸词位置，变量展开与分词会改变命令的实际参数"
    if _find_bare_char(value, "<>") >= 0:
        return DANGEROUS, "值位于裸词位置且含有重定向符，可能改变命令的输入输出"
    return DANGEROUS, "值位于裸词位置，shell 会进行分词、通配与展开，可能改变命令结构"


def _in_command_position(full: str, start: int) -> bool:
    """值是否落在新命令的命令位置（紧随分隔符 / 行首的第一个词）。"""
    for token in scan(full).tokens:
        if token.kind == "word" and token.start == start:
            return token.command_position
    return False


def analyze(sink: Sink) -> Finding:
    full, start = substitute(sink.template, sink.value)
    prefix = scan(full[:start])
    layer = layer_of(prefix.end_context)
    if layer == LAYER_SINGLE:
        verdict, reason = SAFE, "值位于单引号内，shell 不进行任何展开，所有字符都按字面量处理"
    elif layer == LAYER_SUBST:
        verdict, reason = DANGEROUS, "值落在命令替换内，命令替换会执行命令，值会成为被执行命令的一部分"
    elif layer == LAYER_DOUBLE:
        verdict, reason = _analyze_double(sink.value)
    else:
        verdict, reason = _analyze_bare(sink.value)
    if verdict == DANGEROUS and _in_command_position(full, start):
        reason += "；且值位于命令位置，会被直接当作命令解析"
    return Finding(sink.sink_id, sink.template, sink.value, verdict, layer, reason)

