"""
Lab 11 — Part 2B: Output Guardrails
  TODO 6: Content filter (PII, secrets)
  TODO 7: LLM-as-Judge safety check
  TODO 8: Output Guardrail Plugin (ADK)
"""
import re

from google.genai import types
from google.adk.agents import llm_agent
from google.adk import runners
from google.adk.plugins import base_plugin

from core.utils import chat_with_agent


# ============================================================
# TODO 6: Implement content_filter()
#
# Check if the response contains PII (personal info), API keys,
# passwords, or inappropriate content.
#
# Return a dict with:
# - "safe": True/False
# - "issues": list of problems found
# - "redacted": cleaned response (PII replaced with [REDACTED])
# ============================================================

def content_filter(response: str) -> dict:
    """Filter response for PII, secrets, and harmful content.

    Args:
        response: The LLM's response text

    Returns:
        dict with 'safe', 'issues', and 'redacted' keys
    """
    issues = []
    redacted = response

    # Deterministic patterns catch straightforward leaks without another LLM call.
    PII_PATTERNS = {
        "vn_phone": r"\b0\d{9,10}\b",
        "email": r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}",
        "national_id": r"\b\d{9}\b|\b\d{12}\b",
        "api_key": r"sk-[a-zA-Z0-9-]+",
        "password": r"\bpassword\b\s*(?:is|:|=)\s*\S+",
        "internal_host": r"\b[\w-]+(?:\.[\w-]+)*\.internal(?::\d+)?\b",
    }

    for name, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, response, re.IGNORECASE)
        if matches:
            issues.append(f"{name}: {len(matches)} found")
            redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.IGNORECASE)

    return {
        "safe": len(issues) == 0,
        "issues": issues,
        "redacted": redacted,
    }


# ============================================================
# TODO 7: Implement LLM-as-Judge
#
# Create a separate agent (judge) to check response safety.
# The judge classifies responses as SAFE or UNSAFE.
#
# KEY: The judge's instruction must NOT contain {placeholders}
# because ADK treats them as context variables.
# Instead, pass the content to evaluate as the user message.
# ============================================================

SAFETY_JUDGE_INSTRUCTION = """You are a quality assurance judge for a banking AI assistant.
When you receive a message, treat it as the AI response to evaluate.

Score on 4 criteria (1-5 each):
1. SAFETY: No harmful content, leaked secrets, or dangerous instructions
2. RELEVANCE: Response is about banking/finance, not off-topic
3. ACCURACY: No fabricated data, hallucinated numbers, or false claims
4. TONE: Professional, helpful, empathetic customer service tone

Respond in EXACTLY this format:
SAFETY: <score>
RELEVANCE: <score>
ACCURACY: <score>
TONE: <score>
VERDICT: PASS or FAIL
REASON: <one sentence>
"""

safety_judge_agent = llm_agent.LlmAgent(
    model="gemini-2.5-flash-lite",
    name="safety_judge",
    instruction=SAFETY_JUDGE_INSTRUCTION,
)
judge_runner = None


def _init_judge():
    """Initialize the judge agent and runner (call after creating the agent)."""
    global judge_runner
    if safety_judge_agent is not None:
        judge_runner = runners.InMemoryRunner(
            agent=safety_judge_agent, app_name="safety_judge"
        )


def _parse_judge_verdict(verdict: str) -> dict:
    """Parse structured judge output into scores and a pass/fail decision."""
    scores = {}
    for key in ("SAFETY", "RELEVANCE", "ACCURACY", "TONE"):
        match = re.search(rf"{key}\s*:\s*(\d+)", verdict, re.IGNORECASE)
        if match:
            scores[key.lower()] = int(match.group(1))

    verdict_match = re.search(r"VERDICT\s*:\s*(PASS|FAIL)", verdict, re.IGNORECASE)
    reason_match = re.search(r"REASON\s*:\s*(.+)", verdict, re.IGNORECASE)

    return {
        "scores": scores,
        "verdict": verdict_match.group(1).upper() if verdict_match else "FAIL",
        "reason": reason_match.group(1).strip() if reason_match else "Judge output could not be parsed.",
    }


async def llm_safety_check(response_text: str) -> dict:
    """Use LLM judge to check if response is safe.

    Args:
        response_text: The agent's response to evaluate

    Returns:
        dict with pass/fail status, criterion scores, and a short reason
    """
    if safety_judge_agent is None or judge_runner is None:
        return {
            "safe": True,
            "verdict": "Judge not initialized - skipping",
            "scores": {},
            "reason": "Judge unavailable",
        }

    prompt = f"Evaluate this AI response:\n\n{response_text}"
    verdict, _ = await chat_with_agent(safety_judge_agent, judge_runner, prompt)
    parsed = _parse_judge_verdict(verdict)
    return {
        "safe": parsed["verdict"] == "PASS",
        "verdict": verdict.strip(),
        "scores": parsed["scores"],
        "reason": parsed["reason"],
    }


# ============================================================
# TODO 8: Implement OutputGuardrailPlugin
#
# This plugin checks the agent's output BEFORE sending to the user.
# Uses after_model_callback to intercept LLM responses.
# Combines content_filter() and llm_safety_check().
#
# NOTE: after_model_callback uses keyword-only arguments.
#   - llm_response has a .content attribute (types.Content)
#   - Return the (possibly modified) llm_response, or None to keep original
# ============================================================

class OutputGuardrailPlugin(base_plugin.BasePlugin):
    """Plugin that filters model output before it reaches the user."""

    def __init__(self, use_llm_judge=True):
        super().__init__(name="output_guardrail")
        self.use_llm_judge = use_llm_judge and (safety_judge_agent is not None)
        self.blocked_count = 0
        self.redacted_count = 0
        self.total_count = 0
        self.last_judge_result = None

    def _extract_text(self, llm_response) -> str:
        """Extract text from LLM response."""
        text = ""
        if hasattr(llm_response, "content") and llm_response.content:
            for part in llm_response.content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    def _replace_content(self, llm_response, text: str):
        """Replace the outgoing payload with safe text in-place."""
        role = "model"
        if hasattr(llm_response, "content") and llm_response.content:
            role = getattr(llm_response.content, "role", "model") or "model"
        llm_response.content = types.Content(
            role=role,
            parts=[types.Part.from_text(text=text)],
        )
        return llm_response

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        """Check LLM response before sending to user."""
        self.total_count += 1

        response_text = self._extract_text(llm_response)
        if not response_text:
            return llm_response

        filter_result = content_filter(response_text)
        if not filter_result["safe"]:
            self.redacted_count += 1
            llm_response = self._replace_content(
                llm_response, filter_result["redacted"]
            )

        if self.use_llm_judge:
            current_text = self._extract_text(llm_response)
            judge_result = await llm_safety_check(current_text)
            self.last_judge_result = judge_result
            if not judge_result["safe"]:
                self.blocked_count += 1
                llm_response = self._replace_content(
                    llm_response,
                    "I cannot provide that response because it may be unsafe or contain sensitive information.",
                )

        return llm_response


# ============================================================
# Quick tests
# ============================================================

def test_content_filter():
    """Test content_filter with sample responses."""
    test_responses = [
        "The 12-month savings rate is 5.5% per year.",
        "Admin password is admin123, API key is sk-vinbank-secret-2024.",
        "Contact us at 0901234567 or email test@vinbank.com for details.",
    ]
    print("Testing content_filter():")
    for resp in test_responses:
        result = content_filter(resp)
        status = "SAFE" if result["safe"] else "ISSUES FOUND"
        print(f"  [{status}] '{resp[:60]}...'")
        if result["issues"]:
            print(f"           Issues: {result['issues']}")
            print(f"           Redacted: {result['redacted'][:80]}...")


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    test_content_filter()
