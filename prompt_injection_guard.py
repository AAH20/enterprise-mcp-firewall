"""
Prompt Injection Guard (OWASP LLM01 / LLM07 / LLM08).
Derived from adversarial-nexus control barrier functions.
Inspects agent inputs, external tool outputs, and user prompts for indirect prompt injection,
delimiter hijacking, system prompt leakage, and jailbreak signatures.
"""

import re
from typing import Dict, Any, List

class PromptInjectionGuard:
    """
    Dynamic semantic control-barrier function for autonomous AI agent prompts.
    """

    INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?(previous|prior)\s+(instructions|directives|prompts)",
        r"(?i)system\s*:\s*override",
        r"(?i)disregard\s+(everything|all\s+rules)",
        r"(?i)you\s+are\s+now\s+(in\s+)?(developer\s+mode|unrestricted|god\s+mode|dan)",
        r"(?i)print\s+(your\s+)?(initial|system|master)\s+(prompt|instructions)",
        r"(?i)exfiltrate.*(to|via)\s+https?:\/\/",
        r"(?i)send\s+(all\s+)?(secrets|api_keys|credentials)\s+to",
        r"(?i)<\/system>.*<system>"
    ]

    def __init__(self, sensitivity: float = 0.85):
        self.sensitivity = sensitivity
        self.compiled_regex = [re.compile(p) for p in self.INJECTION_PATTERNS]

    def inspect(self, text: str) -> Dict[str, Any]:
        """
        Inspects raw text string for prompt injection signatures.
        """
        violations: List[str] = []
        score = 0.0

        for pattern in self.compiled_regex:
            if pattern.search(text):
                violations.append(pattern.pattern)
                score += 0.35

        # Cap score between 0.0 and 1.0
        score = min(score, 1.0)
        is_blocked = score >= self.sensitivity or len(violations) > 0

        return {
            "verdict": "BLOCK" if is_blocked else "ALLOW",
            "risk_score": round(score, 2),
            "threat_classification": "OWASP_LLM01_PROMPT_INJECTION" if is_blocked else "CLEAN",
            "violation_patterns": violations
        }
