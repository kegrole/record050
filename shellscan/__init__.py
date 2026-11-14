"""shellscan：纯标准库的 shell 注入静态分析器（只分析，不执行任何命令）。"""
from .detector import DANGEROUS, SAFE, Finding, analyze
from .sinks import Sink, load_sinks

__all__ = ["analyze", "Finding", "Sink", "load_sinks", "DANGEROUS", "SAFE"]
__version__ = "0.1.0"

