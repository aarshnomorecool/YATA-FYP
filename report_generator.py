from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from red_agent import VulnerabilityFinding


VULNERABILITY_MAPPING = {
    "SQL Injection": {
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
        "impact": "Authentication bypass, Data exfiltration",
        "severity": "CRITICAL",
    },
    "Hardcoded Secret": {
        "owasp": "A02:2021 – Cryptographic Failures",
        "cwe": "CWE-798",
        "impact": "Credential exposure, Access compromise",
        "severity": "HIGH",
    },
    "Cross-Site Scripting": {
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-79",
        "impact": "Session hijacking, Client-side code execution",
        "severity": "MEDIUM",
    },
    "Command Injection": {
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-78",
        "impact": "Remote code execution, Full system takeover",
        "severity": "CRITICAL",
    },
    "Path Traversal": {
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-22",
        "impact": "Arbitrary file read, Information disclosure",
        "severity": "MEDIUM",
    }
}


def _clean_path(path: object) -> str:
    path_str = str(path).replace("\\", "/")
    if "yata_patched_" in path_str:
        parts = path_str.split("/")
        for i, part in enumerate(parts):
            if "yata_patched_" in part:
                return ".yata/sandbox/" + "/".join(parts[i+1:])
    return path_str


@dataclass(slots=True)
class SecurityReport:
    generated_at: str
    repository_name: str
    mode: str
    patch_mode: str
    patch_applied_to_original: str
    verification_result: str
    target_root: str
    final_root: str
    battle_status: str
    termination_reason: str
    rounds_completed: int
    final_security_score: int
    remaining_findings: list[dict]
    capability_matrix: dict[str, dict[str, str]]
    rounds: list[dict]
    performance_telemetry: dict[str, float]
    execution_mode: str


class ReportGenerator:
    def __init__(self, reports_root: Path | None = None) -> None:
        self.reports_root = reports_root or Path(__file__).resolve().parent / "reports"

    def build_report(
        self,
        *,
        repository_name: str,
        mode: str,
        patch_mode: str,
        patch_applied_to_original: str,
        verification_result: str,
        target_root: Path,
        final_root: Path,
        battle_status: str,
        termination_reason: str,
        final_security_score: int,
        remaining_findings: list[VulnerabilityFinding],
        rounds: list[dict],
        capability_matrix: dict[str, dict[str, str]],
        performance_telemetry: dict[str, float],
        execution_mode: str,
    ) -> SecurityReport:
        cleaned_target = _clean_path(target_root)
        cleaned_final = _clean_path(final_root)

        cleaned_remaining = []
        for finding in remaining_findings:
            fd = asdict(finding)
            fd["affected_file"] = _clean_path(finding.affected_file)
            cleaned_remaining.append(fd)

        cleaned_rounds = []
        for rd in rounds:
            rd_copy = json.loads(json.dumps(rd))
            rd_copy["finding"]["affected_file"] = _clean_path(rd_copy["finding"]["affected_file"])
            rd_copy["patch"]["patched_root"] = _clean_path(rd_copy["patch"]["patched_root"])
            rd_copy["patch"]["patched_file"] = _clean_path(rd_copy["patch"]["patched_file"])
            rd_copy["patch"]["changed_files"] = [
                _clean_path(f) for f in rd_copy["patch"]["changed_files"]
            ]
            cleaned_rounds.append(rd_copy)

        return SecurityReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            repository_name=repository_name,
            mode=mode,
            patch_mode=patch_mode,
            patch_applied_to_original=patch_applied_to_original,
            verification_result=verification_result,
            target_root=cleaned_target,
            final_root=cleaned_final,
            battle_status=battle_status,
            termination_reason=termination_reason,
            rounds_completed=len(rounds),
            final_security_score=final_security_score,
            remaining_findings=cleaned_remaining,
            capability_matrix=capability_matrix,
            rounds=cleaned_rounds,
            performance_telemetry=performance_telemetry,
            execution_mode=execution_mode,
        )

    def write_reports(self, report: SecurityReport) -> dict[str, str]:
        reports_dir = self.reports_root
        reports_dir.mkdir(parents=True, exist_ok=True)
        stem = datetime.now().strftime("assessment_%Y-%m-%d")

        json_path = reports_dir / f"{stem}.json"
        md_path = reports_dir / f"{stem}.md"

        json_path.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
        md_path.write_text(self._to_markdown(report), encoding="utf-8")
        return {"json": str(json_path), "markdown": str(md_path)}

    def _to_markdown(self, report: SecurityReport) -> str:
        lines = [
            "# YATA Security Assessment Report",
            "",
            f"- Generated at: {report.generated_at}",
            f"- Repository: {report.repository_name}",
            f"- Mode: {report.mode}",
            f"- Patch Mode: {report.patch_mode}",
            f"- Patch Applied To Original Repository: {report.patch_applied_to_original}",
            f"- Verification Result: {report.verification_result}",
            f"- Target Root: {report.target_root}",
            f"- Final Root: {report.final_root}",
            f"- Assessment Status: {report.battle_status}",
            f"- Termination Reason: {report.termination_reason}",
            f"- Rounds Completed: {report.rounds_completed}",
            f"- Final Security Score: {report.final_security_score}",
            "",
            "## Execution Information",
            "",
        ]
        if report.execution_mode in ("autonomous_fallback", "demo"):
            lines.extend([
                f"- Execution Mode: {report.execution_mode}",
                "- Hunter Strategy: deterministic",
                "- Healer Strategy: deterministic",
                "- LLM Requests: 0",
            ])
        else:
            lines.extend([
                "- Execution Mode: nvidia_assisted",
            ])
        lines.extend([
            "",
            "## Performance Telemetry",
            "",
            "| Metric | Value |",
            "|----------|----------|",
            f"| Hunter Discovery | {report.performance_telemetry.get('hunter_discovery', 0.0):.1f}s |",
            f"| Hunter Attack Evaluation | {report.performance_telemetry.get('hunter_attack', 0.0):.1f}s |",
            f"| Healer Patch Generation | {report.performance_telemetry.get('healer_patch', 0.0):.1f}s |",
            f"| Validator Verification | {report.performance_telemetry.get('validator_verification', 0.0):.1f}s |",
            f"| LLM Requests | {int(report.performance_telemetry.get('llm_requests', 0))} |",
            f"| LLM Time | {report.performance_telemetry.get('llm_time', 0.0):.1f}s |",
            f"| Average LLM Response | {report.performance_telemetry.get('avg_llm_response', 0.0):.1f}s |",
            f"| Report Generation | {report.performance_telemetry.get('report_generation', 0.0):.1f}s |",
            f"| Total Runtime | {report.performance_telemetry.get('total_runtime', 0.0):.1f}s |",
            "",
            "## Round Summary",
            "",
        ])

        if not report.rounds:
            lines.append("- No rounds were executed.")
        else:
            for round_data in report.rounds:
                finding = round_data["finding"]
                attack = round_data["attack"]
                patch = round_data["patch"]
                referee = round_data["referee"]
                
                mapping = VULNERABILITY_MAPPING.get(finding["vulnerability_type"], {})
                owasp = mapping.get("owasp", "N/A")
                cwe = mapping.get("cwe", "N/A")
                impact = mapping.get("impact", "N/A")
                
                lines.extend(
                    [
                        f"### Round {round_data['round_number']}",
                        "",
                        f"- Vulnerability: {finding['vulnerability_type']}",
                        f"- Severity: {finding['severity']}",
                        f"- OWASP: {owasp}",
                        f"- CWE: {cwe}",
                        f"- Impact: {impact}",
                        f"- Location: {finding['affected_file']}:{finding['line_number']}",
                        f"- Payload: {attack['payload']}",
                        f"- Attack Succeeded: {referee['attack_succeeded']}",
                        f"- Patch Succeeded: {referee['patch_succeeded']}",
                        f"- Score: {referee['score_before']} -> {referee['score_after']} ({referee['score_delta']:+d})",
                        f"- Patch Summary: {patch['patch_text']}",
                        f"- Mitigation: {patch['mitigation_explanation']}",
                        f"- Defense Strategy: {patch['defense_strategy']}",
                        "",
                    ]
                )

        lines.extend(["## Remaining Findings", ""])
        if not report.remaining_findings:
            lines.append("- None")
        else:
            for finding in report.remaining_findings:
                mapping = VULNERABILITY_MAPPING.get(finding['vulnerability_type'], {})
                owasp = mapping.get('owasp', 'N/A')
                cwe = mapping.get('cwe', 'N/A')
                impact = mapping.get('impact', 'N/A')
                lines.extend([
                    f"### {finding['vulnerability_type']} (Severity: {finding['severity']})",
                    f"- Location: {finding['affected_file']}:{finding['line_number']}",
                    f"- OWASP: {owasp}",
                    f"- CWE: {cwe}",
                    f"- Impact: {impact}",
                    ""
                ])

        lines.extend(["", "## Capability Matrix", ""])
        for agent_name, capabilities in report.capability_matrix.items():
            lines.append(f"### {agent_name}")
            lines.append("")
            for capability, status in capabilities.items():
                lines.append(f"- {capability}: {status}")
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"
