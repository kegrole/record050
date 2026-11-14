"""shellscan 判定口径测试：10 条夹具逐条覆盖，另含词法 / 展开 / 禁执行检查。"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shellscan.detector import DANGEROUS, SAFE, analyze
from shellscan.expansion import find_command_substitutions, find_variable_expansions
from shellscan.lexer import Quote, scan
from shellscan.quoting import LAYER_VALUES
from shellscan.report import build_report
from shellscan.sinks import load_sinks

SINKS_PATH = ROOT / "demo" / "sinks.json"

EXPECTED_VERDICTS = {
    "sq_single_quoted": SAFE,
    "dq_plain_text": SAFE,
    "dq_with_variable": DANGEROUS,
    "bare_with_semicolon": DANGEROUS,
    "inside_command_substitution": DANGEROUS,
    "dq_with_single_quote": SAFE,
    "dq_with_backquote": DANGEROUS,
    "dq_closing_quote_semicolon": DANGEROUS,
    "bare_with_newline": DANGEROUS,
    "sq_flag_appended": SAFE,
}


class TestFixtureVerdicts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sinks = load_sinks(SINKS_PATH)
        cls.findings = {f.sink_id: f for f in (analyze(s) for s in cls.sinks)}

    def test_exactly_ten_fixtures(self):
        self.assertEqual(len(self.sinks), 10)
        self.assertEqual(set(self.findings), set(EXPECTED_VERDICTS))

    def test_verdict_of_each_fixture(self):
        for sink_id, expected in EXPECTED_VERDICTS.items():
            with self.subTest(sink_id=sink_id):
                self.assertEqual(self.findings[sink_id].verdict, expected)

    def test_exactly_six_dangerous_four_safe(self):
        verdicts = [f.verdict for f in self.findings.values()]
        self.assertEqual(verdicts.count(DANGEROUS), 6)
        self.assertEqual(verdicts.count(SAFE), 4)

    def test_single_quoted_is_safe_with_single_layer(self):
        finding = self.findings["sq_single_quoted"]
        self.assertEqual(finding.verdict, SAFE)
        self.assertEqual(finding.layer, "单引号")

    def test_double_quoted_variable_expansion_reason(self):
        finding = self.findings["dq_with_variable"]
        self.assertEqual(finding.verdict, DANGEROUS)
        self.assertEqual(finding.layer, "双引号")
        self.assertIn("变量展开在双引号内依然生效", finding.reason)

    def test_command_substitution_layer_and_reason(self):
        finding = self.findings["inside_command_substitution"]
        self.assertEqual(finding.verdict, DANGEROUS)
        self.assertEqual(finding.layer, "命令替换内")
        self.assertIn("命令替换", finding.reason)
        self.assertIn("执行命令", finding.reason)

    def test_closing_quote_then_semicolon_reason(self):
        finding = self.findings["dq_closing_quote_semicolon"]
        self.assertEqual(finding.verdict, DANGEROUS)
        self.assertIn("闭合", finding.reason)
        self.assertIn("分号", finding.reason)
        self.assertIn("终止", finding.reason)

    def test_bare_newline_reason(self):
        finding = self.findings["bare_with_newline"]
        self.assertEqual(finding.verdict, DANGEROUS)
        self.assertEqual(finding.layer, "裸词")
        self.assertIn("换行", finding.reason)
        self.assertIn("裸词", finding.reason)
        self.assertIn("终结", finding.reason)

    def test_single_quote_inside_double_quotes_is_safe(self):
        finding = self.findings["dq_with_single_quote"]
        self.assertEqual(finding.verdict, SAFE)
        self.assertEqual(finding.layer, "双引号")
        self.assertIn("单引号在双引号内只是普通字符", finding.reason)

    def test_flag_appended_inside_single_quotes_is_safe(self):
        finding = self.findings["sq_flag_appended"]
        self.assertEqual(finding.verdict, SAFE)
        self.assertEqual(finding.layer, "单引号")

    def test_report_fields_and_layer_domain(self):
        report = build_report(list(self.findings.values()))
        self.assertEqual(report["summary"], {"total": 10, "dangerous": 6, "safe": 4})
        required = {"sink_id", "template", "value", "verdict", "layer", "reason"}
        for item in report["findings"]:
            with self.subTest(sink_id=item["sink_id"]):
                self.assertEqual(set(item), required)
                self.assertIn(item["layer"], LAYER_VALUES)
                self.assertEqual(set(LAYER_VALUES), {"单引号", "双引号", "裸词", "命令替换内"})
                self.assertIn(item["verdict"], (DANGEROUS, SAFE))
                self.assertTrue(item["reason"])


class TestLexer(unittest.TestCase):
    def test_words_and_quotes(self):
        result = scan("echo 'a b' \"c\" d")
        words = [t.text for t in result.tokens if t.kind == "word"]
        self.assertEqual(words, ["echo", "'a b'", '"c"', "d"])

    def test_comment_and_newline(self):
        result = scan("echo a # 注释\nls")
        words = [t.text for t in result.tokens if t.kind == "word"]
        self.assertEqual(words, ["echo", "a", "ls"])
        self.assertTrue(any(t.kind == "newline" for t in result.tokens))

    def test_line_continuation(self):
        result = scan("echo a\\\nb")
        words = [t for t in result.tokens if t.kind == "word"]
        self.assertEqual(len(words), 2)
        self.assertEqual(words[1].text, "a\\\nb")

    def test_separators(self):
        result = scan("a;b|c>d")
        seps = [t.text for t in result.tokens if t.kind == "sep"]
        self.assertEqual(seps, [";", "|", ">"])

    def test_command_position(self):
        result = scan("echo x; id")
        positions = {t.text: t.command_position for t in result.tokens if t.kind == "word"}
        self.assertTrue(positions["echo"])
        self.assertFalse(positions["x"])
        self.assertTrue(positions["id"])

    def test_quote_contexts(self):
        result = scan("echo 'a' \"b\" c")
        contexts = result.contexts
        text = result.text
        self.assertIs(contexts[text.index("a")].quote, Quote.SINGLE)
        self.assertIs(contexts[text.index("b")].quote, Quote.DOUBLE)
        self.assertIs(contexts[text.rindex("c")].quote, Quote.BARE)


class TestExpansion(unittest.TestCase):
    def test_command_substitutions(self):
        text = "echo $(cat x) \u0060id\u0060"
        subs = find_command_substitutions(text)
        kinds = sorted(s.kind for s in subs)
        self.assertEqual(kinds, ["backquote", "dollar_paren"])

    def test_nested_substitution(self):
        subs = find_command_substitutions("echo $(a $(b))")
        self.assertEqual(len([s for s in subs if s.kind == "dollar_paren"]), 2)

    def test_variable_expansions(self):
        text = "echo $HOME ${PATH}"
        variables = find_variable_expansions(text)
        frags = [text[s.start:s.end] for s in variables]
        self.assertEqual(frags, ["$HOME", "${PATH}"])

    def test_single_quotes_disable_expansion(self):
        self.assertEqual(find_variable_expansions("echo '$HOME'"), [])
        self.assertEqual(find_command_substitutions("echo '$(id)'"), [])


class TestNoCommandExecution(unittest.TestCase):
    def test_package_has_no_execution_primitives(self):
        banned = ("subprocess", "os.system", "os.popen", "pty.spawn", "commands.getoutput")
        package_dir = ROOT / "shellscan"
        sources = list(package_dir.glob("*.py"))
        self.assertGreaterEqual(len(sources), 8)
        for path in sources:
            source = path.read_text(encoding="utf-8")
            for token in banned:
                with self.subTest(file=path.name, token=token):
                    self.assertNotIn(token, source)

    def test_report_contains_no_command_output(self):
        sinks = load_sinks(SINKS_PATH)
        report = build_report([analyze(s) for s in sinks])
        blob = json.dumps(report, ensure_ascii=False)
        self.assertNotIn("uid=", blob)
        self.assertNotIn("root:", blob)
        for item in report["findings"]:
            self.assertEqual(set(item), {"sink_id", "template", "value", "verdict", "layer", "reason"})


class TestCli(unittest.TestCase):
    def test_cli_writes_report_and_prints_summary(self):
        from shellscan.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                rc = main(["--sinks", str(SINKS_PATH), "--out", str(out)])
            self.assertEqual(rc, 0)
            line = buffer.getvalue().strip()
            self.assertIn("检查 10 条", line)
            self.assertIn("危险 6 条", line)
            self.assertIn("安全 4 条", line)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"], {"total": 10, "dangerous": 6, "safe": 4})


if __name__ == "__main__":
    unittest.main()

