from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from blue_agent import BlueAgent, PatchResult
from red_agent import AttackPlan, RedAgent, VulnerabilityFinding
from report_generator import ReportGenerator
from verifier import Referee, VerificationResult


console = Console()


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


def _robust_rmtree(path: Path) -> bool:
    import os
    import stat
    import time

    def remove_readonly(func, file_path, exc_info):
        try:
            os.chmod(file_path, stat.S_IWRITE)
            func(file_path)
        except Exception:
            pass

    if not path.exists():
        return True

    for attempt in range(5):
        try:
            try:
                shutil.rmtree(path, onexc=remove_readonly)
            except TypeError:
                shutil.rmtree(path, onerror=remove_readonly)
            if not path.exists():
                return True
        except Exception:
            pass
        time.sleep(0.1)

    return not path.exists()


@dataclass(slots=True)
class RepositoryRunSummary:
    repository_name: str
    vulnerabilities_found: int
    patches_generated: int
    verification_result: str
    security_score: int
    battle_status: str
    report_paths: dict[str, str]


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    banner = """
██╗   ██╗ █████╗ ████████╗ █████╗ 
╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔══██╗
 ╚████╔╝ ███████║   ██║   ███████║
  ╚██╔╝  ██╔══██║   ██║   ██╔══██║
   ██║   ██║  ██║   ██║   ██║  ██║
   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
"""
    splash_text = (
        f"[bold red]{banner}[/bold red]\n"
        f"[bold white]       YATA (Yet Another Threat Antagonist)[/bold white]\n"
        f"        [dim]Autonomous Cyber Defense & Patching Agent[/dim]\n"
    )
    console.print(Panel(splash_text, border_style="bold red", expand=False))

    if args.max_rounds < 1:
        console.print("[red]--max-rounds must be at least 1[/red]")
        return 1

    if args.demo:
        src_demo = Path(__file__).resolve().parent / "test_repositories" / "repo5_mixed"
        dest_demo = Path(__file__).resolve().parent / "demo_repo5_mixed"
        
        if not _robust_rmtree(dest_demo):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest_demo = Path(__file__).resolve().parent / f"demo_repo5_mixed_{timestamp}"
            _robust_rmtree(dest_demo)
            
        shutil.copytree(
            src_demo,
            dest_demo,
            ignore=shutil.ignore_patterns(".yata", ".git", ".venv", "__pycache__")
        )
        
        target_path = dest_demo
        args.mode = "safe"
    else:
        if args.mode is None:
            try:
                from InquirerPy import inquirer
                mode_choices = [
                    {"name": "SAFE (Patched copy only)", "value": "safe"},
                    {"name": "APPLY (Apply verified patches automatically)", "value": "apply"},
                    {"name": "INTERACTIVE (User approves each patch)", "value": "interactive"}
                ]
                args.mode = inquirer.select(
                    message="Select execution mode:",
                    choices=mode_choices,
                    default="safe"
                ).execute()
            except Exception:
                console.print("[yellow]Non-interactive terminal detected or menu selection failed. Defaulting to SAFE mode.[/yellow]")
                args.mode = "safe"

        if args.target is None:
            try:
                from InquirerPy import inquirer
                args.target = inquirer.text(
                    message="Enter repository path:",
                    default="."
                ).execute()
            except Exception:
                args.target = "."

        target_path = Path(args.target).resolve()
        if not target_path.exists():
            console.print(f"[red]Target path does not exist:[/red] {target_path}")
            return 1

    repository_roots = _resolve_repository_roots(target_path)
    console.print(
        Panel.fit(
            f"[bold cyan][YATA] Autonomous Security Assessment Started[/bold cyan]\n"
            f"[white]Target:[/white] {_clean_path(target_path)}\n"
            f"[white]Repositories:[/white] {len(repository_roots)}\n"
            f"[white]Mode:[/white] {args.mode.upper()}"
        )
    )

    red_agent = RedAgent()
    blue_agent = BlueAgent()
    report_generator = ReportGenerator(Path(__file__).resolve().parent / "reports")
    summaries: list[RepositoryRunSummary] = []

    for repository_root in repository_roots:
        summary = _run_repository(
            repository_root=repository_root,
            mode=args.mode,
            max_rounds=args.max_rounds,
            red_agent=red_agent,
            blue_agent=blue_agent,
            report_generator=report_generator,
        )
        summaries.append(summary)

    _print_suite_summary(summaries)
    return 0 if all(summary.battle_status == "complete" for summary in summaries) else 1


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if raw_args and raw_args[0] not in ("scan", "assess"):
        raw_args = ["assess", *raw_args]
    elif not raw_args:
        raw_args = ["assess"]

    parser = argparse.ArgumentParser(description="YATA - Yet Another Threat Antagonist autonomous cyber immune system")
    subparsers = parser.add_subparsers(dest="command", required=True)

    assess_parser = subparsers.add_parser("assess", aliases=["scan"], help="Assess one repository or a directory of repositories")
    assess_parser.add_argument("target", nargs="?", default=None, help="Repository path or a directory containing repositories")
    assess_parser.add_argument("--demo", action="store_true", help="Run in demo mode with bundled repositories")
    
    mode_group = assess_parser.add_mutually_exclusive_group()
    mode_group.add_argument("--safe", action="store_true", help="Patch and verify on safe copies only")
    mode_group.add_argument("--apply", action="store_true", help="Apply verified patches automatically")
    mode_group.add_argument("--interactive", action="store_true", help="User approves each patch")
    assess_parser.add_argument(
        "--max-rounds",
        type=int,
        default=5,
        help="Maximum number of attack/patch/verify rounds before stopping",
    )

    args = parser.parse_args(raw_args)

    if getattr(args, "apply", False):
        args.mode = "apply"
    elif getattr(args, "interactive", False):
        args.mode = "interactive"
    elif getattr(args, "safe", False):
        args.mode = "safe"
    else:
        args.mode = None
    return args


def _resolve_repository_roots(target_path: Path) -> list[Path]:
    if _looks_like_repository_root(target_path):
        return [target_path]

    repository_roots = sorted(
        child
        for child in target_path.iterdir()
        if child.is_dir() and _looks_like_repository_root(child)
    )
    if repository_roots:
        return repository_roots

    raise SystemExit(f"No repositories found at {target_path}")


def _looks_like_repository_root(path: Path) -> bool:
    return (path / "app.py").exists() or (path / "yata_profile.json").exists()


def _run_repository(
    *,
    repository_root: Path,
    mode: str,
    max_rounds: int,
    red_agent: RedAgent,
    blue_agent: BlueAgent,
    report_generator: ReportGenerator,
) -> RepositoryRunSummary:
    global console
    console = Console(record=True)

    start_time = time.time()

    console.print(
        Panel.fit(
            f"[bold cyan]Repository: {repository_root.name}[/bold cyan]\n"
            f"[white]Path:[/white] {_clean_path(repository_root)}"
        )
    )

    referee = Referee()
    target_root = repository_root.resolve()

    yata_dir = target_root / ".yata"
    reports_dir = yata_dir / "reports"
    patches_dir = yata_dir / "patches"
    analysis_dir = yata_dir / "analysis"
    logs_dir = yata_dir / "logs"

    yata_dir.mkdir(exist_ok=True)
    reports_dir.mkdir(exist_ok=True)
    patches_dir.mkdir(exist_ok=True)
    analysis_dir.mkdir(exist_ok=True)
    logs_dir.mkdir(exist_ok=True)

    metadata_file = yata_dir / "metadata.json"
    metadata_content = {
        "version": "0.4.1",
        "workspace_initialized": True,
        "created_by": "YATA"
    }
    metadata_file.write_text(json.dumps(metadata_content, indent=2), encoding="utf-8")

    report_generator.reports_root = reports_dir

    console.print("[bold cyan][YATA][/bold cyan] Workspace initialized at:")
    console.print(f"  {_clean_path(yata_dir)}")
    console.print("[bold cyan][YATA][/bold cyan] Reports:             .yata/reports/")
    console.print("[bold cyan][YATA][/bold cyan] Patched Files:       .yata/patches/")
    console.print("[bold cyan][YATA][/bold cyan] Security Assessment: .yata/analysis/")
    console.print("[bold cyan][YATA][/bold cyan] Logs:                .yata/logs/\n")

    current_root = target_root
    round_reports: list[dict] = []
    remaining_findings: list[VulnerabilityFinding] = []
    discovered_findings: set[tuple[str, str, int, str]] = set()
    battle_status = "complete"
    termination_reason = "No validator-verified weaknesses remain."
    patches_generated = 0
    healed_count = 0
    patch_applied = False

    all_findings: dict[tuple, dict] = {}

    score_before_all = 100

    for round_number in range(1, max_rounds + 1):
        console.print(Panel(f"[bold magenta]Assessment Round {round_number}[/bold magenta]", border_style="magenta", expand=False))
        console.print("[bold red][HUNTER][/bold red] Evaluating attack paths...")

        findings = red_agent.scan(current_root)
        for finding in findings:
            discovered_findings.add(_finding_key(finding))
            
            key = _finding_key(finding)
            if key not in all_findings:
                rel_file = finding.metadata.get("relative_file", finding.affected_file)
                all_findings[key] = {
                    "vulnerability_type": finding.vulnerability_type,
                    "file": str(rel_file),
                    "line_number": finding.line_number,
                    "severity": finding.severity,
                    "status": "active",
                    "payloads_attempted": [],
                    "winning_payload": None,
                    "attack_success": False
                }

        remaining_findings = findings
        score_before = referee.calculate_security_score(findings)
        if round_number == 1:
            score_before_all = score_before

        if not findings:
            console.print("[bold green][VALIDATOR][/bold green] Repository is clean. No further weaknesses found.")
            break

        selection = _select_verified_attack(red_agent, referee, current_root, findings, all_findings)
        if selection is None:
            battle_status = "stalled"
            termination_reason = "Detectors flagged suspicious patterns, but VALIDATOR could not reproduce an exploit."
            console.print("[bold yellow][VALIDATOR][/bold yellow] Weakness could not be exploited. Halting cycle.")
            break

        finding, attack_plan, vulnerable_check = selection

        mapping = VULNERABILITY_MAPPING.get(finding.vulnerability_type, {})
        severity = mapping.get("severity", finding.severity).upper()
        severity_colors = {
            "CRITICAL": "bold red",
            "HIGH": "bold red",
            "MEDIUM": "bold yellow",
            "LOW": "bold blue"
        }
        sev_color = severity_colors.get(severity, "bold white")
        
        console.print(f"[bold red][HUNTER][/bold red] Prioritized weakness: [bold cyan]{finding.vulnerability_type}[/bold cyan]")
        console.print(f" └─ Severity:  [{sev_color}]{severity}[/{sev_color}]")
        console.print(f" └─ Location:  {_clean_path(finding.metadata.get('relative_file', finding.affected_file))}:{finding.line_number}")
        console.print(f" └─ OWASP:     {mapping.get('owasp', 'N/A')}")
        console.print(f" └─ CWE:       {mapping.get('cwe', 'N/A')}")
        impact_str = ", ".join(mapping.get('impact', 'N/A').split(", "))
        console.print(f" └─ Impact:    {impact_str}")
        console.print(f" └─ Payload:   [cyan]{attack_plan.payload}[/cyan]")
        console.print(f"[bold green][VALIDATOR][/bold green] Vulnerability verified: {vulnerable_check.evidence}")

        console.print("[bold blue][HEALER][/bold blue] Generating secure patch...")

        patch_result = blue_agent.generate_patch(current_root, finding)
        patches_generated += 1
        rel_patch_path = Path(".yata/patches") / Path(patch_result.patched_file).name
        console.print(f" └─ Patch written → {rel_patch_path}")
        console.print("[bold cyan][VALIDATOR][/bold cyan] Attacking patched code...")

        patched_check = referee.verify_exploit(patch_result.patched_root, finding, attack_plan.payload)
        patch_succeeded = not patched_check.attack_succeeded

        if patch_succeeded:
            console.print(" └─ Exploit blocked ✓")
            console.print("[bold blue][HEALER][/bold blue] Patch verified.\n")
            healed_count += 1

            all_findings[_finding_key(finding)]["status"] = "patched"

            for relative_path in patch_result.changed_files:
                relative = Path(relative_path)
                source_path = patch_result.patched_root / relative
                destination_path = patches_dir / relative
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_path, destination_path)

            apply_verified = False
            if mode == "apply":
                apply_verified = True
            elif mode == "interactive":
                console.print()
                try:
                    response = input("Apply verified patch to original repository? [Y/N]: ").strip().upper()
                except (KeyboardInterrupt, EOFError):
                    response = "N"
                if response in ("Y", "YES"):
                    apply_verified = True

            if apply_verified:
                console.print("[bold cyan][YATA][/bold cyan] Applying verified patch to original repository...\n")
                _apply_patch_to_original(target_root, patch_result)
                current_root = target_root
                patch_applied = True
                console.print("[bold cyan][YATA][/bold cyan] Repository healed successfully.")
            else:
                current_root = patch_result.patched_root

            remaining_findings = red_agent.scan(current_root)
            for next_finding in remaining_findings:
                discovered_findings.add(_finding_key(next_finding))
            console.print("[bold green][VALIDATOR][/bold green] Patch verification successful. Changes promoted.")
        else:
            remaining_findings = findings
            battle_status = "stalled"
            termination_reason = "The patched copy still allowed the exploit."
            console.print(" └─ Exploit succeeded ✗")
            console.print("[bold red][VALIDATOR][/bold red] Patch verification failed. Exploit bypass found.")

        score_after = referee.calculate_security_score(remaining_findings)
        round_score = referee.record_round(
            round_number=round_number,
            finding=finding,
            attack_verification=vulnerable_check,
            patch_verification=patched_check,
            score_before=score_before,
            score_after=score_after,
        )
        console.print(
            f"[bold cyan][VALIDATOR][/bold cyan] Security score updated: {round_score.score_before} -> "
            f"{round_score.score_after} ({round_score.score_delta:+d})"
        )

        round_reports.append(
            _build_round_report(
                round_number=round_number,
                finding=finding,
                attack_plan=attack_plan,
                patch_result=patch_result,
                vulnerable_check=vulnerable_check,
                patched_check=patched_check,
                patch_succeeded=patch_succeeded,
                round_score=round_score,
                mode=mode,
            )
        )

        if patch_succeeded:
            continue
        break
    else:
        remaining_findings = red_agent.scan(current_root)
        for finding in remaining_findings:
            discovered_findings.add(_finding_key(finding))
        battle_status = "max_rounds_reached"
        termination_reason = f"Reached max round limit ({max_rounds}) before the system became clean."
        console.print("[bold yellow][VALIDATOR][/bold yellow] Maximum rounds reached before the repository became clean.")

    verification_result = "Passed" if battle_status == "complete" and not remaining_findings else "Failed"
    final_score = referee.calculate_security_score(remaining_findings)
    report = report_generator.build_report(
        repository_name=repository_root.name,
        mode=mode,
        patch_mode=mode.upper(),
        patch_applied_to_original="Yes" if patch_applied else "No",
        verification_result=verification_result,
        target_root=target_root,
        final_root=current_root,
        battle_status=battle_status,
        termination_reason=termination_reason,
        final_security_score=final_score,
        remaining_findings=remaining_findings,
        rounds=round_reports,
        capability_matrix={
            "HUNTER": red_agent.capability_matrix(),
            "HEALER": blue_agent.capability_matrix(),
            "VALIDATOR": referee.capability_matrix(),
        },
    )
    report_paths = report_generator.write_reports(report)

    findings_data = []
    for f in all_findings.values():
        mapping = VULNERABILITY_MAPPING.get(f["vulnerability_type"], {
            "owasp": "N/A",
            "cwe": "N/A",
            "impact": "N/A",
            "severity": f["severity"]
        })
        findings_data.append({
            "vulnerability_type": f["vulnerability_type"],
            "file": f["file"],
            "line_number": f["line_number"],
            "severity": mapping["severity"],
            "status": f["status"],
            "owasp": mapping["owasp"],
            "cwe": mapping["cwe"],
            "impact": mapping["impact"],
            "payloads_attempted": f["payloads_attempted"],
            "winning_payload": f["winning_payload"],
            "attack_success": f["attack_success"]
        })
    findings_file = analysis_dir / "security_assessment.json"
    findings_file.write_text(json.dumps(findings_data, indent=2), encoding="utf-8")

    log_content = console.export_text()
    log_file = logs_dir / f"run_{datetime.now().strftime('%Y-%m-%d')}.log"
    log_file.write_text(log_content, encoding="utf-8")

    elapsed_time = int(time.time() - start_time)
    _print_security_assessment_card(
        repository_root.name,
        score_before_all,
        final_score,
        healed_count,
        elapsed_time
    )

    console.print("[bold cyan][YATA] Security assessment complete.[/bold cyan]")
    cleaned_report_paths = {k: _clean_path(v) for k, v in report_paths.items()}
    console.print(json.dumps(cleaned_report_paths, indent=2))

    verification_result = "Passed" if battle_status == "complete" and not remaining_findings else "Failed"
    return RepositoryRunSummary(
        repository_name=repository_root.name,
        vulnerabilities_found=len(discovered_findings),
        patches_generated=patches_generated,
        verification_result=verification_result,
        security_score=final_score,
        battle_status=battle_status,
        report_paths=report_paths,
    )


def _select_verified_attack(
    red_agent: RedAgent,
    referee: Referee,
    current_root: Path,
    findings: list[VulnerabilityFinding],
    findings_tracker: dict[tuple, dict] | None = None,
) -> tuple[VulnerabilityFinding, AttackPlan, VerificationResult] | None:
    for finding in red_agent.prioritize(findings):
        payloads = red_agent.get_payloads_for_finding(finding)
        
        console.print(f"[bold red][HUNTER][/bold red] Evaluating attack paths for {finding.vulnerability_type}...")
        console.print(f" └─ Payloads loaded: {len(payloads)}")

        winning_payload = None
        vulnerable_check = None
        payloads_attempted = []
        attack_success = False

        for idx, payload in enumerate(payloads, 1):
            payloads_attempted.append(payload)

            if finding.vulnerability_type == "Hardcoded Secret" and payload != finding.exploit_payload:
                console.print(f" └─ Payload {idx}/{len(payloads)} FAIL")
                continue

            check = referee.verify_exploit(current_root, finding, payload)
            if check.attack_succeeded:
                console.print(f" └─ Payload {idx}/{len(payloads)} SUCCESS ✓")
                winning_payload = payload
                vulnerable_check = check
                attack_success = True
                break
            else:
                console.print(f" └─ Payload {idx}/{len(payloads)} FAIL")

        if findings_tracker is not None:
            key = _finding_key(finding)
            if key in findings_tracker:
                findings_tracker[key].update({
                    "payloads_attempted": payloads_attempted,
                    "winning_payload": winning_payload,
                    "attack_success": attack_success
                })

        if attack_success and vulnerable_check is not None and winning_payload is not None:
            attack_plan = red_agent.plan_attack(finding, winning_payload)
            return finding, attack_plan, vulnerable_check

        console.print("[bold yellow][VALIDATOR][/bold yellow] Weakness could not be exploited. Continuing search.")
    return None


def _apply_patch_to_original(target_root: Path, patch_result: PatchResult) -> None:
    for relative_path in patch_result.changed_files:
        relative = Path(relative_path)
        source_path = patch_result.patched_root / relative
        destination_path = target_root / relative
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination_path)


def _build_round_report(
    *,
    round_number: int,
    finding: VulnerabilityFinding,
    attack_plan: AttackPlan,
    patch_result: PatchResult,
    vulnerable_check: VerificationResult,
    patched_check: VerificationResult,
    patch_succeeded: bool,
    round_score,
    mode: str,
) -> dict:
    return {
        "round_number": round_number,
        "finding": {
            "vulnerability_type": finding.vulnerability_type,
            "severity": finding.severity,
            "affected_file": finding.affected_file,
            "line_number": finding.line_number,
            "exploit_payload": finding.exploit_payload,
            "evidence": finding.evidence,
            "detector_id": finding.detector_id,
            "metadata": finding.metadata,
        },
        "attack": {
            "payload": attack_plan.payload,
            "attack_path": attack_plan.attack_path,
            "explanation": attack_plan.explanation,
            "used_llm": attack_plan.used_llm,
        },
        "patch": {
            "patched_root": str(patch_result.patched_root),
            "patched_file": str(patch_result.patched_file),
            "changed_files": patch_result.changed_files,
            "patch_text": patch_result.patch_text,
            "used_llm": patch_result.used_llm,
            "mitigation_explanation": patch_result.mitigation_explanation,
            "defense_strategy": patch_result.defense_strategy,
            "mode": mode,
        },
        "referee": {
            "attack_succeeded": vulnerable_check.attack_succeeded,
            "patch_succeeded": patch_succeeded,
            "score_before": round_score.score_before,
            "score_after": round_score.score_after,
            "score_delta": round_score.score_delta,
            "pre_patch": {
                "attack_succeeded": vulnerable_check.attack_succeeded,
                "status_code": vulnerable_check.status_code,
                "response_text": vulnerable_check.response_text,
                "evidence": vulnerable_check.evidence,
            },
            "post_patch": {
                "attack_succeeded": patched_check.attack_succeeded,
                "status_code": patched_check.status_code,
                "response_text": patched_check.response_text,
                "evidence": patched_check.evidence,
            },
        },
    }


def _finding_key(finding: VulnerabilityFinding) -> tuple[str, str, str, str]:
    metadata = finding.metadata
    identity_hint = (
        str(metadata.get("variable_name"))
        or str(metadata.get("query_var_name"))
        or str(metadata.get("parameterized_query"))
        or finding.evidence
    )
    return (
        finding.vulnerability_type,
        str(metadata.get("relative_file", finding.affected_file)),
        identity_hint,
        finding.detector_id,
    )


def _print_security_assessment_card(
    repo_name: str,
    score_before: int,
    score_after: int,
    healed_count: int,
    elapsed_time_seconds: int
) -> None:
    def make_bar(score: int, color: str) -> str:
        filled = int(score / 5)
        empty = 20 - filled
        return f"[{color}]" + "█" * filled + f"[dim]" + "░" * empty + f"[/dim] ({score}/100)"

    def get_status(score: int) -> tuple[str, str]:
        if score == 100 or score >= 90:
            return "SECURE", "green"
        elif score >= 70:
            return "MEDIUM RISK", "yellow"
        elif score >= 40:
            return "HIGH RISK", "red"
        else:
            return "CRITICAL", "bold red"

    before_status, before_color = get_status(score_before)
    after_status, after_color = get_status(score_after)

    hours, remainder = divmod(elapsed_time_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    card_content = (
        f"[bold white]REPOSITORY SECURITY ASSESSMENT[/bold white]\n"
        f"[bold dim]──────────────────────────────────────────────[/bold dim]\n"
        f"[bold]Repository:[/bold] {repo_name}\n\n"
        f"[bold]BEFORE[/bold]\n"
        f"Score: {make_bar(score_before, before_color)}  [[{before_color}]{before_status}[/{before_color}]]\n\n"
        f"[bold]AFTER[/bold]\n"
        f"Score: {make_bar(score_after, after_color)}  [[{after_color}]{after_status}[/{after_color}]]\n\n"
        f"[bold dim]──────────────────────────────────────────────[/bold dim]\n"
        f"[bold]Vulnerabilities Healed:[/bold] {healed_count}\n"
        f"[bold]Human Interventions:[/bold]    0\n"
        f"[bold]Time Elapsed:[/bold]           {time_str}\n"
    )
    console.print(Panel(card_content, border_style="cyan", expand=False))


def _print_suite_summary(summaries: list[RepositoryRunSummary]) -> None:
    table = Table(title="YATA Security Assessment Summary")
    table.add_column("Repository", style="cyan")
    table.add_column("Vulnerabilities Found", justify="right")
    table.add_column("Patches Generated", justify="right")
    table.add_column("Verification Result", style="green")
    table.add_column("Security Score", justify="right")

    for summary in summaries:
        table.add_row(
            summary.repository_name,
            str(summary.vulnerabilities_found),
            str(summary.patches_generated),
            summary.verification_result,
            str(summary.security_score),
        )

    console.print(table)


if __name__ == "__main__":
    raise SystemExit(main())
