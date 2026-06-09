from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from red_agent import VulnerabilityFinding


@dataclass(slots=True)
class SecurityReport:
    generated_at: str
    repository_name: str
    mode: str
    target_root: str
    final_root: str
    battle_status: str
    termination_reason: str
    rounds_completed: int
    final_security_score: int
    remaining_findings: list[dict]
    capability_matrix: dict[str, dict[str, str]]
    rounds: list[dict]


class ReportGenerator:
    def __init__(self, reports_root: Path | None = None) -> None:
        self.reports_root = reports_root or Path(__file__).resolve().parent / "reports"

    def build_report(
        self,
        *,
        repository_name: str,
        mode: str,
        target_root: Path,
        final_root: Path,
        battle_status: str,
        termination_reason: str,
        final_security_score: int,
        remaining_findings: list[VulnerabilityFinding],
        rounds: list[dict],
        capability_matrix: dict[str, dict[str, str]],
    ) -> SecurityReport:
        return SecurityReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            repository_name=repository_name,
            mode=mode,
            target_root=str(target_root),
            final_root=str(final_root),
            battle_status=battle_status,
            termination_reason=termination_reason,
            rounds_completed=len(rounds),
            final_security_score=final_security_score,
            remaining_findings=[asdict(finding) for finding in remaining_findings],
            capability_matrix=capability_matrix,
            rounds=rounds,
        )

    def write_reports(self, report: SecurityReport) -> dict[str, str]:
        reports_dir = self.reports_root
        reports_dir.mkdir(parents=True, exist_ok=True)
        stem = datetime.now().strftime(f"yata_{report.repository_name}_%Y%m%d_%H%M%S")

        json_path = reports_dir / f"{stem}.json"
        md_path = reports_dir / f"{stem}.md"

        json_path.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
        md_path.write_text(self._to_markdown(report), encoding="utf-8")
        return {"json": str(json_path), "markdown": str(md_path)}

    def _to_markdown(self, report: SecurityReport) -> str:
        lines = [
            "# YATA Battle Report",
            "",
            f"- Generated at: {report.generated_at}",
            f"- Repository: {report.repository_name}",
            f"- Mode: {report.mode}",
            f"- Target Root: {report.target_root}",
            f"- Final Root: {report.final_root}",
            f"- Battle Status: {report.battle_status}",
            f"- Termination Reason: {report.termination_reason}",
            f"- Rounds Completed: {report.rounds_completed}",
            f"- Final Security Score: {report.final_security_score}",
            "",
            "## Round Summary",
            "",
        ]

        if not report.rounds:
            lines.append("- No rounds were executed.")
        else:
            for round_data in report.rounds:
                finding = round_data["finding"]
                attack = round_data["attack"]
                patch = round_data["patch"]
                referee = round_data["referee"]
                lines.extend(
                    [
                        f"### Round {round_data['round_number']}",
                        "",
                        f"- Vulnerability: {finding['vulnerability_type']}",
                        f"- Severity: {finding['severity']}",
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
                lines.append(
                    f"- {finding['vulnerability_type']} at {finding['affected_file']}:{finding['line_number']}"
                )

        lines.extend(["", "## Capability Matrix", ""])
        for agent_name, capabilities in report.capability_matrix.items():
            lines.append(f"### {agent_name}")
            lines.append("")
            for capability, status in capabilities.items():
                lines.append(f"- {capability}: {status}")
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"
