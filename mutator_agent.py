from __future__ import annotations

import re

from llm_client import LLMClient


class MutatorAgent:
    """MUTATOR: re-attacks a patch that already blocked HUNTER's winning payload.

    Scope is intentionally narrow (see CLAUDE.md Module 2): mutate the *attack
    payload* into a handful of same-attack-class variants and hand them back
    for VALIDATOR to re-run against the same patch. MUTATOR never generates
    patch variants; that is YATA-X and explicitly out of scope.
    """

    MAX_MUTATIONS = 4
    TEMPERATURE = 0.95

    def __init__(self) -> None:
        self.llm = LLMClient()
        self.verbose = False

    def generate_mutations(self, vulnerability_type: str, winning_payload: str, count: int | None = None) -> list[str]:
        cap = count or self.MAX_MUTATIONS
        mutations: list[str] = []

        for candidate in self._deterministic_mutations(vulnerability_type, winning_payload):
            if candidate and candidate != winning_payload and candidate not in mutations:
                mutations.append(candidate)
            if len(mutations) >= cap:
                return mutations[:cap]

        if LLMClient.execution_mode not in ("autonomous_fallback", "demo") and len(mutations) < cap:
            for candidate in self._llm_mutations(vulnerability_type, winning_payload, cap - len(mutations)):
                if candidate and candidate != winning_payload and candidate not in mutations:
                    mutations.append(candidate)
                if len(mutations) >= cap:
                    break

        return mutations[:cap]

    def capability_matrix(self) -> dict[str, str]:
        return {
            "SQL Injection": "implemented",
            "Command Injection": "implemented",
            "Path Traversal": "implemented",
            "Hardcoded Secret": "not applicable",
            "Cross-Site Scripting": "framework-ready, mutation strategy pending",
        }

    def _llm_mutations(self, vulnerability_type: str, winning_payload: str, count: int) -> list[str]:
        response = self.llm.generate(
            system_prompt=(
                "You are MUTATOR in YATA. A patch just blocked the exploit payload below. Produce alternate "
                "payloads of the exact same attack class (encoding tricks, case changes, alternate syntax) "
                "that a defender should also test the patch against. Do not invent a different vulnerability "
                "class. Return one payload per line, nothing else."
            ),
            user_prompt=(
                f"Vulnerability Type: {vulnerability_type}\n"
                f"Blocked Payload: {winning_payload}\n\n"
                f"Produce up to {count} alternate payloads, one per line."
            ),
            fallback_text="",
            temperature=self.TEMPERATURE,
            max_tokens=200,
            request_type="mutator",
        )
        if response.used_fallback or not response.content.strip():
            return []
        return [line.strip().strip("`") for line in response.content.splitlines() if line.strip()]

    def _deterministic_mutations(self, vulnerability_type: str, payload: str) -> list[str]:
        slug = re.sub(r"[^a-z0-9]+", "_", vulnerability_type.lower())
        strategy = getattr(self, f"_mutate_{slug}", None)
        if strategy is None:
            return []
        return strategy(payload)

    def _mutate_sql_injection(self, payload: str) -> list[str]:
        variants = [
            _toggle_case_keyword(payload, "or"),
            _toggle_case_keyword(payload, "and"),
        ]
        if "--" in payload:
            variants.append(payload.replace("--", "#"))
            variants.append(payload.replace("--", "/**/"))
        elif "#" in payload:
            variants.append(payload.replace("#", "--"))
        variants.append(payload.replace(" OR ", "/**/OR/**/").replace(" or ", "/**/or/**/"))
        variants.append(payload.replace("1=1", "2=2").replace("'1'='1'", "'a'='a'"))
        return variants

    def _mutate_command_injection(self, payload: str) -> list[str]:
        separators = [";", "&&", "|", "&"]
        base_command = payload
        for sep in separators:
            if payload.startswith(sep):
                base_command = payload[len(sep):].strip()
                break

        variants = []
        for sep in separators:
            variants.append(f"{sep}{base_command}")
            variants.append(f"{sep} {base_command}")
        variants.append(f"`{base_command}`")
        variants.append(f"$({base_command})")
        return variants

    def _mutate_path_traversal(self, payload: str) -> list[str]:
        target = payload.replace("\\", "/").split("/")[-1]
        variants = [f"{depth}{target}" for depth in ("../", "../../", "../../../", "../../../../")]
        variants.append(payload.replace("/", "\\"))
        variants.append(f"./{payload}")
        return variants

    def _mutate_hardcoded_secret(self, payload: str) -> list[str]:
        return []


def _toggle_case_keyword(payload: str, keyword: str) -> str:
    pattern = re.compile(re.escape(keyword), re.IGNORECASE)

    def repl(match: re.Match) -> str:
        text = match.group(0)
        return "".join(ch.upper() if i % 2 == 0 else ch.lower() for i, ch in enumerate(text))

    return pattern.sub(repl, payload)
