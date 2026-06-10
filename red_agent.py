from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from attack_library import AttackLibrary
from llm_client import LLMClient


@dataclass(slots=True)
class VulnerabilityFinding:
    vulnerability_type: str
    severity: str
    affected_file: str
    line_number: int
    exploit_payload: str
    evidence: str
    detector_id: str
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class AttackPlan:
    finding: VulnerabilityFinding
    payload: str
    attack_path: str
    explanation: str
    used_llm: bool


class VulnerabilityDetector:
    vulnerability_type = "Generic"
    detector_id = "generic.detector"

    def scan(self, source_file: Path) -> list[VulnerabilityFinding]:
        raise NotImplementedError


class SQLInjectionDetector(VulnerabilityDetector):
    vulnerability_type = "SQL Injection"
    detector_id = "sqli.ast-string-interpolation"

    def scan(self, source_file: Path) -> list[VulnerabilityFinding]:
        try:
            source_text = source_file.read_text(encoding="utf-8")
            tree = ast.parse(source_text)
        except Exception:
            return []

        findings: list[VulnerabilityFinding] = []
        lines = source_text.splitlines()
        query_assignments = self._find_vulnerable_assignments(tree, source_text, lines)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute) or node.func.attr != "execute":
                continue
            if not node.args:
                continue

            first_arg = node.args[0]
            query_info = None
            vulnerable_line = None

            if isinstance(first_arg, ast.Name) and first_arg.id in query_assignments:
                query_info = dict(query_assignments[first_arg.id])
                vulnerable_line = int(query_info.get("query_line", getattr(first_arg, "lineno", getattr(node, "lineno", 1))))
            else:
                query_info = self._extract_query_info(first_arg, source_text)
                if query_info is not None:
                    vulnerable_line = getattr(first_arg, "lineno", getattr(node, "lineno", 1))
                    query_info["query_var_name"] = "query"
                    query_info["query_line"] = vulnerable_line
                    query_info["query_indent"] = self._line_indent(lines, vulnerable_line)

            if query_info is None or vulnerable_line is None:
                continue

            evidence = lines[vulnerable_line - 1].strip() if 0 <= vulnerable_line - 1 < len(lines) else ""
            query_info.update(
                {
                    "execute_line": getattr(node, "lineno", vulnerable_line),
                    "execute_indent": self._line_indent(lines, getattr(node, "lineno", vulnerable_line)),
                    "execute_receiver": ast.get_source_segment(source_text, node.func.value) or "cursor",
                }
            )

            findings.append(
                VulnerabilityFinding(
                    vulnerability_type=self.vulnerability_type,
                    severity="CRITICAL",
                    affected_file=str(source_file),
                    line_number=vulnerable_line,
                    exploit_payload="' OR '1'='1' -- ",
                    evidence=evidence,
                    detector_id=self.detector_id,
                    metadata=query_info,
                )
            )
        return findings

    def _find_vulnerable_assignments(
        self,
        tree: ast.AST,
        source_text: str,
        lines: list[str],
    ) -> dict[str, dict[str, object]]:
        assignments: dict[str, dict[str, object]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue

            if isinstance(node, ast.Assign):
                targets = node.targets
                value = node.value
                line_number = getattr(node, "lineno", 1)
            else:
                targets = [node.target]
                value = node.value
                line_number = getattr(node, "lineno", 1)

            if value is None:
                continue

            query_info = self._extract_query_info(value, source_text)
            if query_info is None:
                continue

            for target in targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = {
                        **query_info,
                        "query_var_name": target.id,
                        "query_line": line_number,
                        "query_indent": self._line_indent(lines, line_number),
                    }
        return assignments

    def _extract_query_info(self, node: ast.AST, source_text: str) -> dict[str, object] | None:
        if isinstance(node, ast.JoinedStr):
            pieces: list[str] = []
            parameter_names: list[str] = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    pieces.append(value.value)
                    continue
                if isinstance(value, ast.FormattedValue):
                    parameter_name = self._extract_name(value.value)
                    if parameter_name is None:
                        return None
                    parameter_names.append(parameter_name)
                    pieces.append("?")
                    continue
                return None
            return {
                "query_style": "fstring",
                "parameterized_query": self._normalize_parameterized_query("".join(pieces)),
                "parameter_names": parameter_names,
            }

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            template = node.func.value.value if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str) else None
            if template is None:
                return None
            parameter_names = [self._extract_name(argument) for argument in node.args]
            if any(name is None for name in parameter_names):
                return None
            parameterized_query = re.sub(r"\{[^}]*\}", "?", template)
            return {
                "query_style": "format",
                "parameterized_query": self._normalize_parameterized_query(parameterized_query),
                "parameter_names": [str(name) for name in parameter_names],
            }

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            template = node.left.value if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str) else None
            if template is None:
                return None
            parameter_names = self._extract_mod_parameters(node.right)
            if not parameter_names:
                return None
            parameterized_query = re.sub(r"%[a-zA-Z]", "?", template)
            return {
                "query_style": "percent",
                "parameterized_query": self._normalize_parameterized_query(parameterized_query),
                "parameter_names": parameter_names,
            }

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            flattened = self._flatten_concat(node)
            if flattened is None:
                return None
            pieces: list[str] = []
            parameter_names: list[str] = []
            for part_type, value in flattened:
                if part_type == "text":
                    pieces.append(value)
                else:
                    parameter_names.append(value)
                    pieces.append("?")
            return {
                "query_style": "concat",
                "parameterized_query": self._normalize_parameterized_query("".join(pieces)),
                "parameter_names": parameter_names,
            }

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            lowered = node.value.lower()
            if "select" in lowered and ("{" in node.value or "%s" in node.value):
                parameterized_query = re.sub(r"\{[^}]*\}", "?", node.value).replace("%s", "?")
                return {
                    "query_style": "constant",
                    "parameterized_query": self._normalize_parameterized_query(parameterized_query),
                    "parameter_names": [],
                }
        return None

    def _flatten_concat(self, node: ast.AST) -> list[tuple[str, str]] | None:
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._flatten_concat(node.left)
            right = self._flatten_concat(node.right)
            if left is None or right is None:
                return None
            return [*left, *right]
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [("text", node.value)]
        parameter_name = self._extract_name(node)
        if parameter_name is not None:
            return [("param", parameter_name)]
        return None

    def _extract_mod_parameters(self, node: ast.AST) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, ast.Tuple):
            names: list[str] = []
            for element in node.elts:
                parameter_name = self._extract_name(element)
                if parameter_name is None:
                    return []
                names.append(parameter_name)
            return names
        return []

    def _extract_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        return None

    def _normalize_parameterized_query(self, query: str) -> str:
        normalized = query.replace("'?'", "?").replace('"?"', "?")
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized

    def _line_indent(self, lines: list[str], line_number: int) -> str:
        if not (0 <= line_number - 1 < len(lines)):
            return ""
        line = lines[line_number - 1]
        return line[: len(line) - len(line.lstrip())]


class HardcodedSecretDetector(VulnerabilityDetector):
    vulnerability_type = "Hardcoded Secret"
    detector_id = "secret.literal-assignment"

    _NAME_PATTERN = re.compile(
        r"(secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|passwd|password)",
        re.IGNORECASE,
    )
    _VALUE_HINT_PATTERN = re.compile(
        r"(nvapi-|sk[_-]|tok[_-]|ghp_|AIza|AKIA|[A-Za-z0-9_\-]{16,})"
    )

    def scan(self, source_file: Path) -> list[VulnerabilityFinding]:
        try:
            source_text = source_file.read_text(encoding="utf-8")
            tree = ast.parse(source_text)
        except Exception:
            return []

        findings: list[VulnerabilityFinding] = []
        lines = source_text.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue

            if isinstance(node, ast.Assign):
                targets = node.targets
                value = node.value
                line_number = getattr(node, "lineno", 1)
            else:
                targets = [node.target]
                value = node.value
                line_number = getattr(node, "lineno", 1)

            if value is None or not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                continue

            secret_value = value.value.strip()
            if not secret_value:
                continue

            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                variable_name = target.id
                if not self._looks_secret(variable_name, secret_value):
                    continue

                env_var_name = self._to_env_var(variable_name)
                evidence = lines[line_number - 1].strip() if 0 <= line_number - 1 < len(lines) else ""
                findings.append(
                    VulnerabilityFinding(
                        vulnerability_type=self.vulnerability_type,
                        severity="HIGH",
                        affected_file=str(source_file),
                        line_number=line_number,
                        exploit_payload=env_var_name,
                        evidence=evidence,
                        detector_id=self.detector_id,
                        metadata={
                            "variable_name": variable_name,
                            "env_var_name": env_var_name,
                            "secret_preview": self._redact_secret(secret_value),
                        },
                    )
                )
        return findings

    def _looks_secret(self, variable_name: str, secret_value: str) -> bool:
        if not self._NAME_PATTERN.search(variable_name):
            return False
        if len(secret_value) >= 12:
            return True
        return bool(self._VALUE_HINT_PATTERN.search(secret_value))

    def _to_env_var(self, variable_name: str) -> str:
        env_name = re.sub(r"[^A-Z0-9]+", "_", variable_name.upper()).strip("_")
        return env_name or "SECRET_VALUE"

    def _redact_secret(self, secret_value: str) -> str:
        if len(secret_value) <= 6:
            return "*" * len(secret_value)
        return f"{secret_value[:3]}...{secret_value[-3:]}"


class RedAgent:
    def __init__(
        self,
        *,
        llm_client: LLMClient | None = None,
        detectors: list[VulnerabilityDetector] | None = None,
    ) -> None:
        self.llm = llm_client or LLMClient()
        self.detectors = detectors or [SQLInjectionDetector(), HardcodedSecretDetector()]
        self.attack_library = AttackLibrary()

    def scan(self, target_root: Path) -> list[VulnerabilityFinding]:
        target_root = target_root.resolve()
        findings: list[VulnerabilityFinding] = []
        for source_file in target_root.rglob("*.py"):
            if any(part in (".yata", ".git", ".venv", "__pycache__") for part in source_file.parts):
                continue
            for detector in self.detectors:
                detector_findings = detector.scan(source_file)
                for finding in detector_findings:
                    finding.metadata.setdefault("relative_file", str(source_file.relative_to(target_root)))
                findings.extend(detector_findings)
        return self.prioritize(findings)

    def prioritize(self, findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return sorted(
            findings,
            key=lambda finding: (
                -severity_order.get(finding.severity, 0),
                finding.vulnerability_type,
                finding.affected_file,
                finding.line_number,
            ),
        )

    def generate_exploit_payload(self, finding: VulnerabilityFinding) -> str:
        return finding.exploit_payload

    def get_payloads_for_finding(self, finding: VulnerabilityFinding) -> list[str]:
        return self.attack_library.get_payloads(finding.vulnerability_type, finding.exploit_payload)

    def plan_attack(self, finding: VulnerabilityFinding, payload: str | None = None) -> AttackPlan:
        if payload is None:
            payload = self.generate_exploit_payload(finding)
        attack_path, fallback_explanation = self._build_attack_context(finding, payload)
        llm_response = self.llm.generate(
            system_prompt=(
                "You are the RED agent in YATA. Explain a concrete software attack path using only the "
                "provided evidence. Do not invent extra vulnerabilities."
            ),
            user_prompt=(
                f"Vulnerability Type: {finding.vulnerability_type}\n"
                f"Severity: {finding.severity}\n"
                f"Affected File: {finding.affected_file}\n"
                f"Line: {finding.line_number}\n"
                f"Evidence: {finding.evidence}\n"
                f"Payload: {payload}\n\n"
                "Write a concise explanation of how the exploit works and why it is risky."
            ),
            fallback_text=fallback_explanation,
            max_tokens=220,
        )
        return AttackPlan(
            finding=finding,
            payload=payload,
            attack_path=attack_path,
            explanation=llm_response.content,
            used_llm=not llm_response.used_fallback,
        )

    def capability_matrix(self) -> dict[str, str]:
        return {
            "SQL Injection": "implemented",
            "Hardcoded Secrets": "implemented",
            "Cross-Site Scripting": "framework-ready, detector pending",
            "Command Injection": "framework-ready, detector pending",
            "Path Traversal": "framework-ready, detector pending",
        }

    def _build_attack_context(self, finding: VulnerabilityFinding, payload: str) -> tuple[str, str]:
        if finding.vulnerability_type == "Hardcoded Secret":
            env_var_name = str(finding.metadata.get("env_var_name", payload))
            attack_path = (
                f"Read the repository or deployed source to recover the embedded credential, then reuse the secret "
                f"outside the application boundary. The leaked credential maps to environment variable {env_var_name!r} "
                "once remediated."
            )
            fallback_explanation = (
                "Rule-based assessment: a credential-like string is embedded directly in source code, so anyone "
                "with repository or artifact access can extract and reuse it without breaching runtime controls."
            )
            return attack_path, fallback_explanation

        attack_path = (
            f"Send the payload {payload!r} through the vulnerable request flow so the interpolated SQL statement "
            "evaluates to a tautology and bypasses the intended record filter."
        )
        fallback_explanation = (
            "Rule-based assessment: the query is built from unsanitized user input and executed without "
            "bound parameters, allowing the payload to alter SQL logic and return unauthorized rows."
        )
        return attack_path, fallback_explanation
