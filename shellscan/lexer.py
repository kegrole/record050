"""Shell 词法切分。

只做静态分析，不执行任何命令。把命令文本切成词法 token，并为每个字符
记录引号 / 命令替换上下文。支持的语法：

- 单引号（内部完全字面量，反斜杠也不特殊）
- 双引号（内部仍识别 $VAR、${VAR}、$(...) 与反引号，反斜杠仅部分转义）
- 反斜杠转义与反斜杠续行
- 注释（# 出现在词首时到行尾为止）
- 分号、管道、后台符与重定向等分隔符
- 命令替换：$(...) 与反引号，可嵌套
- 变量展开：$VAR 与 ${VAR}
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

BACKQUOTE = "\x60"


class Quote(Enum):
    BARE = "bare"
    SINGLE = "single"
    DOUBLE = "double"


@dataclass(frozen=True)
class Context:
    """某个字符位置所处的引号 / 命令替换上下文。"""

    quote: Quote = Quote.BARE
    substitution_depth: int = 0

    @property
    def in_substitution(self) -> bool:
        return self.substitution_depth > 0


@dataclass
class Token:
    kind: str  # "word" | "sep" | "newline"
    text: str
    start: int
    end: int
    command_position: bool = False


@dataclass
class Span:
    start: int
    end: int
    kind: str


@dataclass
class ScanResult:
    text: str
    tokens: List[Token]
    contexts: List[Context]  # 每个字符对应的上下文
    end_context: Context  # 扫描完最后一个字符后的上下文（用于判定占位符落点）
    substitutions: List[Span]
    variables: List[Span]


@dataclass
class _Frame:
    kind: str  # "single" | "double" | "subst" | "backquote"
    pos: int
    saved_word_start: Optional[int] = None
    saved_word_cmd: bool = False
    saved_command_position: bool = False


_NAME_START = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
_NAME_CHARS = _NAME_START + "0123456789"
_SPECIAL_VARS = "?$!#@*-0123456789"
_DQUOTE_ESCAPABLE = frozenset("$" + BACKQUOTE + '"\\\n')
_BACKQUOTE_ESCAPABLE = frozenset("$" + BACKQUOTE + "\\\n")


def scan(text: str) -> ScanResult:
    n = len(text)
    contexts: List[Optional[Context]] = [None] * n
    tokens: List[Token] = []
    substitutions: List[Span] = []
    variables: List[Span] = []
    stack: List[_Frame] = []
    word_start: Optional[int] = None
    word_cmd = False
    command_position = True

    def ctx_now() -> Context:
        top = stack[-1].kind if stack else None
        if top == "single":
            quote = Quote.SINGLE
        elif top == "double":
            quote = Quote.DOUBLE
        else:
            quote = Quote.BARE
        depth = sum(1 for f in stack if f.kind in ("subst", "backquote"))
        return Context(quote, depth)

    def close_word(end: int) -> None:
        nonlocal word_start, word_cmd
        if word_start is not None:
            tokens.append(Token("word", text[word_start:end], word_start, end, word_cmd))
            word_start = None
            word_cmd = False

    def mark(pos: int) -> None:
        nonlocal word_start, word_cmd, command_position
        if word_start is None:
            word_start = pos
            word_cmd = command_position
            command_position = False

    def open_word_frame(kind: str, pos: int) -> None:
        # 进入 $(...) 或反引号：挂起外层单词，内部是全新的命令上下文
        nonlocal word_start, word_cmd, command_position
        stack.append(_Frame(kind, pos, word_start, word_cmd, command_position))
        word_start = None
        word_cmd = False
        command_position = True

    def close_word_frame(pos: int, span_kind: str) -> None:
        nonlocal word_start, word_cmd, command_position
        close_word(pos)
        frame = stack.pop()
        substitutions.append(Span(frame.pos, pos + 1, span_kind))
        word_start = frame.saved_word_start
        word_cmd = frame.saved_word_cmd
        command_position = frame.saved_command_position

    def consume_variable(i: int) -> int:
        ctx = ctx_now()
        if i + 1 < n and text[i + 1] == "{":
            depth = 0
            j = i + 1
            while j < n:
                ch = text[j]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            end = j + 1 if j < n else n
            for k in range(i + 1, end):
                contexts[k] = ctx
            variables.append(Span(i, end, "parameter"))
            return end
        j = i + 1
        if j < n and text[j] in _NAME_START:
            while j < n and text[j] in _NAME_CHARS:
                j += 1
        elif j < n and text[j] in _SPECIAL_VARS:
            j += 1
        if j > i + 1:
            for k in range(i + 1, j):
                contexts[k] = ctx
            variables.append(Span(i, j, "variable"))
            return j
        return i + 1  # 孤立的 $ 只是普通字符

    i = 0
    while i < n:
        ch = text[i]
        top = stack[-1].kind if stack else None
        contexts[i] = ctx_now()

        if top == "single":
            mark(i)
            if ch == "'":
                stack.pop()
            i += 1
            continue

        if top == "double":
            mark(i)
            if ch == '"':
                stack.pop()
                i += 1
            elif ch == "\\" and i + 1 < n and text[i + 1] in _DQUOTE_ESCAPABLE:
                contexts[i + 1] = ctx_now()
                i += 2
            elif ch == BACKQUOTE:
                open_word_frame("backquote", i)
                i += 1
            elif ch == "$" and i + 1 < n and text[i + 1] == "(":
                contexts[i + 1] = ctx_now()
                open_word_frame("subst", i)
                i += 2
            elif ch == "$":
                i = consume_variable(i)
            else:
                i += 1
            continue

        if top == "backquote":
            mark(i)
            if ch == BACKQUOTE:
                close_word_frame(i, "backquote")
                i += 1
            elif ch == "\\" and i + 1 < n and text[i + 1] in _BACKQUOTE_ESCAPABLE:
                contexts[i + 1] = ctx_now()
                i += 2
            else:
                i += 1
            continue

        # 裸词上下文或 $(...) 内部
        if ch in " \t\r":
            close_word(i)
            i += 1
        elif ch == "\n":
            close_word(i)
            tokens.append(Token("newline", "\n", i, i + 1))
            command_position = True
            i += 1
        elif ch == "\\":
            mark(i)
            if i + 1 < n:
                contexts[i + 1] = ctx_now()
                i += 2
            else:
                i += 1
        elif ch == "'":
            mark(i)
            stack.append(_Frame("single", i))
            i += 1
        elif ch == '"':
            mark(i)
            stack.append(_Frame("double", i))
            i += 1
        elif ch == BACKQUOTE:
            mark(i)
            open_word_frame("backquote", i)
            i += 1
        elif ch == "$":
            mark(i)
            if i + 1 < n and text[i + 1] == "(":
                contexts[i + 1] = ctx_now()
                open_word_frame("subst", i)
                i += 2
            else:
                i = consume_variable(i)
        elif ch == ")" and top == "subst":
            close_word_frame(i, "dollar_paren")
            i += 1
        elif ch == "#" and word_start is None:
            j = i
            while j < n and text[j] != "\n":
                contexts[j] = ctx_now()
                j += 1
            i = j
        elif ch in ";|&<>":
            close_word(i)
            j = i + 1
            if j < n and text[j] == ch and ch in "|&;>":
                j += 1
            elif ch in "<>" and j < n and text[j] in "&<>|":
                j += 1
            for k in range(i + 1, j):
                contexts[k] = ctx_now()
            tokens.append(Token("sep", text[i:j], i, j))
            command_position = ch in ";|&"
            i = j
        else:
            mark(i)
            i += 1

    close_word(n)
    final_contexts = [c if c is not None else Context() for c in contexts]
    return ScanResult(text, tokens, final_contexts, ctx_now(), substitutions, variables)

