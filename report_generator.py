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
        "impact": "Remote Command Execution, Privilege Escalation, System Enumeration, Data Exfiltration",
        "severity": "CRITICAL",
    },
    "Path Traversal": {
        "owasp": "A01:2021 Broken Access Control",
        "cwe": "CWE-22",
        "impact": "Unauthorized File Access, Source Code Disclosure, Configuration Exposure, Sensitive Data Leakage",
        "severity": "HIGH",
    }
}


def _clean_path(path: object) -> str:
    path_str = str(path).replace("\\", "/")
    project_root_str = str(Path(__file__).resolve().parent).replace("\\", "/")
    if path_str.startswith(project_root_str):
        rel = path_str[len(project_root_str):].lstrip("/")
        if rel.startswith(".yata"):
            return rel
        if "yata_patched_" in path_str:
            parts = path_str.split("/")
            for i, part in enumerate(parts):
                if "yata_patched_" in part:
                    return ".yata/sandbox/" + "/".join(parts[i+1:])
        return rel

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
        html_path = reports_dir / f"{stem}.html"

        json_path.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
        md_path.write_text(self._to_markdown(report), encoding="utf-8")
        html_path.write_text(self._to_html(report), encoding="utf-8")
        return {"json": str(json_path), "markdown": str(md_path), "html": str(html_path)}

    def _escape_html(self, s: object) -> str:
        if s is None:
            return ""
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def _to_html(self, report: SecurityReport) -> str:
        initial_score = report.rounds[0]["referee"]["score_before"] if report.rounds else report.final_security_score
        score_diff = report.final_security_score - initial_score
        
        def get_score_color(score: int) -> str:
            if score >= 90:
                return "#3fb950"
            elif score >= 70:
                return "#d29922"
            elif score >= 40:
                return "#f85149"
            return "#db6d28"
            
        initial_color = get_score_color(initial_score)
        final_color = get_score_color(report.final_security_score)

        # 3. Vulnerabilities Found Section
        vulns_found_html = ""
        if not report.rounds and not report.remaining_findings:
            vulns_found_html = "<p>No vulnerabilities found.</p>"
        else:
            if report.rounds:
                vulns_found_html += "<ul>"
                for rd in report.rounds:
                    finding = rd["finding"]
                    mapping = VULNERABILITY_MAPPING.get(finding["vulnerability_type"], {})
                    owasp = mapping.get("owasp", "N/A")
                    cwe = mapping.get("cwe", "N/A")
                    impact = mapping.get("impact", "N/A")
                    vulns_found_html += f"""
                    <li>
                        <strong>{self._escape_html(finding['vulnerability_type'])}</strong> (Severity: {finding['severity']})
                        <ul>
                            <li>OWASP: {self._escape_html(owasp)}</li>
                            <li>CWE: {self._escape_html(cwe)}</li>
                            <li>Location: <code>{self._escape_html(finding['affected_file'])}:{finding['line_number']}</code></li>
                            <li>Impact: {self._escape_html(impact)}</li>
                            <li>Evidence: <code>{self._escape_html(finding['evidence'])}</code></li>
                        </ul>
                    </li>
                    """
                vulns_found_html += "</ul>"
            
            if report.remaining_findings:
                vulns_found_html += "<h3>Remaining Weaknesses</h3><ul>"
                for finding in report.remaining_findings:
                    mapping = VULNERABILITY_MAPPING.get(finding['vulnerability_type'], {})
                    owasp = mapping.get('owasp', 'N/A')
                    cwe = mapping.get('cwe', 'N/A')
                    vulns_found_html += f"""
                    <li>
                        <strong>{self._escape_html(finding['vulnerability_type'])}</strong> (Severity: {finding['severity']})
                        <ul>
                            <li>Location: <code>{self._escape_html(finding['affected_file'])}:{finding['line_number']}</code></li>
                            <li>OWASP: {self._escape_html(owasp)} | CWE: {self._escape_html(cwe)}</li>
                        </ul>
                    </li>
                    """
                vulns_found_html += "</ul>"

        # 4. Exploits Proven Section
        exploits_proven_html = ""
        if not report.rounds:
            exploits_proven_html = "<p>No exploits proven.</p>"
        else:
            exploits_proven_html += "<ul>"
            for rd in report.rounds:
                finding = rd["finding"]
                attack = rd["attack"]
                referee = rd["referee"]
                exploits_proven_html += f"""
                <li>
                    <strong>{self._escape_html(finding['vulnerability_type'])} Exploit Proof</strong>
                    <ul>
                        <li>Payload Attempted: <code>{self._escape_html(attack['payload'])}</code></li>
                        <li>Attack Succeeded: <strong>{referee['attack_succeeded']}</strong></li>
                        <li>Explanation: {self._escape_html(attack['explanation'])}</li>
                    </ul>
                </li>
                """
            exploits_proven_html += "</ul>"

        # 5. Patches Applied Section
        patches_applied_html = ""
        if not report.rounds:
            patches_applied_html = "<p>No patches applied.</p>"
        else:
            patches_applied_html += "<ul>"
            for rd in report.rounds:
                finding = rd["finding"]
                patch = rd["patch"]
                
                patch_text = self._escape_html(patch["patch_text"])
                diff_lines = []
                for line in patch_text.splitlines():
                    if line.startswith("+"):
                        diff_lines.append(f'<span style="color:#56d364; background-color:rgba(46,160,67,0.15); display:inline-block; width:100%;">{self._escape_html(line)}</span>')
                    elif line.startswith("-"):
                        diff_lines.append(f'<span style="color:#ff7b72; background-color:rgba(248,81,73,0.15); display:inline-block; width:100%;">{self._escape_html(line)}</span>')
                    else:
                        diff_lines.append(self._escape_html(line))
                pretty_diff = "\n".join(diff_lines)

                patches_applied_html += f"""
                <li>
                    <strong>{self._escape_html(finding['vulnerability_type'])} Remediation</strong>
                    <ul>
                        <li>File Patched: <code>{self._escape_html(patch['patched_file'])}</code></li>
                        <li>Mitigation: {self._escape_html(patch['mitigation_explanation'])}</li>
                        <li>Defense Strategy: {self._escape_html(patch['defense_strategy'])}</li>
                        <li>Patch Diff:
                            <pre style="background:#0d1117; border:1px solid #30363d; border-radius:6px; padding:12px; overflow-x:auto; font-family: monospace;"><code>{pretty_diff}</code></pre>
                        </li>
                    </ul>
                </li>
                """
            patches_applied_html += "</ul>"

        # 6. Validation Results Section
        validation_results_html = ""
        if not report.rounds:
            validation_results_html = "<p>No validation executed.</p>"
        else:
            validation_results_html += "<ul>"
            for rd in report.rounds:
                finding = rd["finding"]
                referee = rd["referee"]
                status_text = "Blocked ✓" if referee["patch_succeeded"] else "Bypassed (Failed) ✗"
                status_color = "#3fb950" if referee["patch_succeeded"] else "#f85149"
                validation_results_html += f"""
                <li>
                    <strong>{self._escape_html(finding['vulnerability_type'])} Validation</strong>
                    <ul>
                        <li>Result: <span style="color: {status_color}; font-weight: bold;">{status_text}</span></li>
                        <li>Pre-Patch Status Code: {referee['pre_patch']['status_code']} | Pre-Patch Evidence: <code>{self._escape_html(referee['pre_patch']['evidence'])}</code></li>
                        <li>Post-Patch Status Code: {referee['post_patch']['status_code']} | Post-Patch Evidence: <code>{self._escape_html(referee['post_patch']['evidence'])}</code></li>
                    </ul>
                </li>
                """
            validation_results_html += "</ul>"

        # 7. Timeline Section
        timeline_steps = []
        if len(report.rounds) > 1:
            timeline_steps = [
                "Vulnerabilities Discovered",
                "Exploits Verified",
                "Patches Generated",
                "Validation Executed",
                "Security Score Updated"
            ]
        else:
            timeline_steps = [
                "Vulnerability Found",
                "Exploit Verified",
                "Patch Generated",
                "Validation Executed",
                "Exploit Blocked" if report.verification_result == "Passed" else "Exploit Bypassed (Patch Failed)"
            ]
        timeline_html = "<ol>"
        for step in timeline_steps:
            timeline_html += f"<li>{self._escape_html(step)}</li>"
        timeline_html += "</ol>"

        # 8. Agent Status Section
        hunter_status = "COMPLETE"
        healer_status = "COMPLETE"
        validator_status = "COMPLETE" if report.verification_result == "Passed" else "PATCH FAILED"
        validator_color = "#3fb950" if report.verification_result == "Passed" else "#f85149"
        
        agent_status_html = f"""
        <table class="table-info">
            <tr><th>Agent</th><th>Status</th></tr>
            <tr><td>HUNTER</td><td><span style="color:#3fb950; font-weight:bold;">✓ {hunter_status}</span></td></tr>
            <tr><td>HEALER</td><td><span style="color:#3fb950; font-weight:bold;">✓ {healer_status}</span></td></tr>
            <tr><td>VALIDATOR</td><td><span style="color:{validator_color}; font-weight:bold;">{ '✓' if report.verification_result == 'Passed' else '✗' } {validator_status}</span></td></tr>
        </table>
        """

        # 9. Metrics Section
        metrics_html = f"""
        <table class="table-info">
            <thead>
                <tr><th>Metric</th><th>Value</th></tr>
            </thead>
            <tbody>
                <tr><td>Hunter Discovery</td><td>{report.performance_telemetry.get('hunter_discovery', 0.0):.1f}s</td></tr>
                <tr><td>Hunter Attack Evaluation</td><td>{report.performance_telemetry.get('hunter_attack', 0.0):.1f}s</td></tr>
                <tr><td>Healer Patch Generation</td><td>{report.performance_telemetry.get('healer_patch', 0.0):.1f}s</td></tr>
                <tr><td>Validator Verification</td><td>{report.performance_telemetry.get('validator_verification', 0.0):.1f}s</td></tr>
                <tr><td>LLM Requests</td><td>{int(report.performance_telemetry.get('llm_requests', 0))}</td></tr>
                <tr><td>LLM Time</td><td>{report.performance_telemetry.get('llm_time', 0.0):.1f}s</td></tr>
                <tr><td>Average LLM Response</td><td>{report.performance_telemetry.get('avg_llm_response', 0.0):.1f}s</td></tr>
                <tr><td>Report Generation</td><td>{report.performance_telemetry.get('report_generation', 0.0):.1f}s</td></tr>
                <tr style="font-weight:bold; background: rgba(56, 139, 253, 0.05);"><td>Total Runtime</td><td>{report.performance_telemetry.get('total_runtime', 0.0):.1f}s</td></tr>
            </tbody>
        </table>
        """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="YATA Security Assessment Report for {self._escape_html(report.repository_name)}.">
    <title>YATA Security Report - {self._escape_html(report.repository_name)}</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
        }}
        body {{
            background-color: var(--bg-color);
            color: var(--text-primary);
            font-family: var(--font-family);
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 25px;
        }}
        h1, h2, h3 {{
            color: var(--accent-blue);
        }}
        .table-info {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
        }}
        .table-info th, .table-info td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #21262d;
        }}
        .table-info th {{
            color: var(--text-secondary);
            width: 220px;
        }}
        .score-bar-bg {{
            background: #21262d;
            border-radius: 4px;
            height: 12px;
            overflow: hidden;
            width: 100%;
            max-width: 300px;
            display: inline-block;
            vertical-align: middle;
            margin-right: 10px;
        }}
        .score-bar-fill {{
            height: 100%;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>YATA Security Assessment Report</h1>
            <p style="color: var(--text-secondary);">Autonomous Security Defense Summary</p>
        </header>

        <main>
            <section class="card" id="executive-summary">
                <h2>Executive Summary</h2>
                <table class="table-info">
                    <tr><th>Repository</th><td>{self._escape_html(report.repository_name)}</td></tr>
                    <tr><th>Mode</th><td><code>{self._escape_html(report.mode.upper())}</code></td></tr>
                    <tr><th>Execution Mode</th><td><code>{self._escape_html(report.execution_mode.upper())}</code></td></tr>
                    <tr><th>Verification Result</th><td><strong style="color: {'#3fb950' if report.verification_result == 'Passed' else '#f85149'}">{self._escape_html(report.verification_result.upper())}</strong></td></tr>
                    <tr><th>Rounds Completed</th><td>{report.rounds_completed}</td></tr>
                    <tr><th>Battle Status</th><td><code>{self._escape_html(report.battle_status.upper())}</code></td></tr>
                    <tr><th>Termination Reason</th><td>{self._escape_html(report.termination_reason)}</td></tr>
                    <tr><th>Generated At</th><td>{self._escape_html(report.generated_at)}</td></tr>
                </table>
            </section>

            <section class="card" id="security-score-evolution">
                <h2>Security Score Evolution</h2>
                <table class="table-info">
                    <tr>
                        <th>Before</th>
                        <td>
                            <div class="score-bar-bg">
                                <div class="score-bar-fill" style="width: {initial_score}%; background-color: {initial_color};"></div>
                            </div>
                            <strong>{initial_score}/100</strong>
                        </td>
                    </tr>
                    <tr>
                        <th>After</th>
                        <td>
                            <div class="score-bar-bg">
                                <div class="score-bar-fill" style="width: {report.final_security_score}%; background-color: {final_color};"></div>
                            </div>
                            <strong>{report.final_security_score}/100</strong>
                        </td>
                    </tr>
                    <tr>
                        <th>Improvement</th>
                        <td><strong style="color: {'#3fb950' if score_diff >= 0 else '#f85149'}">{score_diff:+d}</strong></td>
                    </tr>
                </table>
            </section>

            <section class="card" id="vulnerabilities-found">
                <h2>Vulnerabilities Found</h2>
                {vulns_found_html}
            </section>

            <section class="card" id="exploits-proven">
                <h2>Exploits Proven</h2>
                {exploits_proven_html}
            </section>

            <section class="card" id="patches-applied">
                <h2>Patches Applied</h2>
                {patches_applied_html}
            </section>

            <section class="card" id="validation-results">
                <h2>Validation Results</h2>
                {validation_results_html}
            </section>

            <section class="card" id="timeline">
                <h2>Timeline</h2>
                {timeline_html}
            </section>

            <section class="card" id="agent-status">
                <h2>Agent Status</h2>
                {agent_status_html}
            </section>

            <section class="card" id="metrics">
                <h2>Metrics</h2>
                {metrics_html}
            </section>
        </main>
    </div>
</body>
</html>
"""

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
