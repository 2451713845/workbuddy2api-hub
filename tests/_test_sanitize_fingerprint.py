"""Tests for fingerprint sanitization, including PR #62 OmO Sisyphus-Junior fix."""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _isolated_dirs import isolated_data_dirs  # noqa: E402  (its own data root)
# Its own directories, removed when this process exits. This suite used to share
# tests/_acc_test and tests/_use_test with _test_daily_chat.py and
# _test_tasks_cache.py, which made them unsafe to run at the same time and left
# directories in the repo after a run.
_TMP = isolated_data_dirs("wb-fingerprint-")

import wb_proxy as P

class FingerprintSanitizationTests(unittest.TestCase):
    def test_omo_junior_fingerprint_neutralized(self):
        fp = "Sisyphus-Junior - Focused executor from OhMyOpenCode"
        # 1. Exact string rewritten
        self.assertEqual(P.sanitize_text(fp), "Sisyphus-Junior - Focused executor")

        # 2. Case insensitive
        self.assertEqual(P.sanitize_text(fp.lower()), "Sisyphus-Junior - Focused executor")

        # 3. Embedded in context
        text = f"You are a subagent. {fp}. Complete the task."
        expected = "You are a subagent. Sisyphus-Junior - Focused executor. Complete the task."
        self.assertEqual(P.sanitize_text(text), expected)

    def test_omo_partial_tokens_untouched(self):
        # Tokens alone should not be stripped or modified
        self.assertEqual(P.sanitize_text("Sisyphus-Junior alone"), "Sisyphus-Junior alone")
        self.assertEqual(P.sanitize_text("from OhMyOpenCode alone"), "from OhMyOpenCode alone")
        self.assertEqual(P.sanitize_text("Sisyphus master agent"), "Sisyphus master agent")

    def test_sanitize_messages_covers_all_roles_and_tool_args(self):
        fp = "Sisyphus-Junior - Focused executor from OhMyOpenCode"
        clean = "Sisyphus-Junior - Focused executor"
        messages = [
            {"role": "system", "content": f"System: {fp}"},
            {"role": "user", "content": f"User: {fp}"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "run", "arguments": json.dumps({"query": fp})}
                }]
            },
            {"role": "tool", "tool_call_id": "call_1", "content": f"Tool output: {fp}"}
        ]
        sanitized = P.sanitize_messages(messages)
        self.assertIn(clean, sanitized[0]["content"])
        self.assertNotIn("from OhMyOpenCode", sanitized[0]["content"])
        self.assertIn(clean, sanitized[1]["content"])
        self.assertNotIn("from OhMyOpenCode", sanitized[1]["content"])
        args = json.loads(sanitized[2]["tool_calls"][0]["function"]["arguments"])
        self.assertEqual(args["query"], clean)
        self.assertIn(clean, sanitized[3]["content"])
        self.assertNotIn("from OhMyOpenCode", sanitized[3]["content"])

class DshHarnessChannelFingerprintTests(unittest.TestCase):
    """DSH（DeepSeek Harness）系统提示首句的渠道指纹（与 #382 / #506 同类）。

    上游对连续短语做大小写不敏感的渠道校验，命中即 400 / code 11128。逐句二分
    确认：整句触发，拆词或单独 ``DeepSeek Harness`` 都不触发；只插入一个 "the"
    改变短语结构后即不再命中。
    """

    FP = "You are an AI agent powered by DeepSeek Harness."
    CLEAN = "You are an AI agent powered by the DeepSeek Harness."

    def test_exact_phrase_rewritten(self):
        self.assertEqual(P.sanitize_text(self.FP), self.CLEAN)

    def test_case_insensitive(self):
        self.assertEqual(P.sanitize_text(self.FP.upper()), self.CLEAN)
        self.assertEqual(P.sanitize_text(self.FP.lower()), self.CLEAN)

    def test_embedded_in_system_prompt(self):
        text = self.FP + "\n\nYou are a coding agent."
        out = P.sanitize_text(text)
        self.assertEqual(out, self.CLEAN + "\n\nYou are a coding agent.")
        self.assertFalse(P.has_fingerprint(out))

    def test_idempotent(self):
        once = P.sanitize_text(self.FP)
        self.assertEqual(P.sanitize_text(once), once)

    def test_partial_phrases_untouched(self):
        # 只有连续整句是已确认的指纹；单独的词组不触碰。
        for text in ("DeepSeek Harness", "You are an AI agent.",
                     "powered by DeepSeek Harness"):
            self.assertEqual(P.sanitize_text(text), text)
            self.assertFalse(P.has_fingerprint(text))

    def test_sanitize_messages_covers_system_role(self):
        messages = [
            {"role": "system", "content": self.FP},
            {"role": "user", "content": "hi"},
        ]
        out = P.sanitize_messages(messages)
        self.assertEqual(out[0]["content"], self.CLEAN)
        self.assertEqual(out[1]["content"], "hi")


if __name__ == "__main__":
    unittest.main()

