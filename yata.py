from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from blue_agent import BlueAgent, PatchResult
from red_agent import AttackPlan, RedAgent, VulnerabilityFinding
from report_generator import ReportGenerator
from verifier import Referee, VerificationResult


console = Console()


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
    target_path = Path(args.target).resolve()
    if not target_path.exists():
        console.print(f"[red]Target path does not exist:[/red] {target_path}")
        return 1

    if args.max_rounds < 1:
        console.print("[red]--max-rounds must be at least 1[/red]")
        return 1

    repository_roots = _resolve_repository_roots(target_path)
    console.print(
        Panel.fit(
            f"[bold cyan][YATA] Autonomous Scan Started[/bold cyan]\n"
            f"[white]Target:[/white] {target_path}\n"
            f"[white]Repositories:[/white] {len(repository_roots)}\n"
            f"[white]Mode:[/white] {args.mode}"
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
    if raw_args and raw_args[0] != "scan":
        raw_args = ["scan", *raw_args]

    parser = argparse.ArgumentParser(description="YATA - Yata no Kagami autonomous cyber immune system")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan one repository or a directory of repositories")
    scan_parser.add_argument("target", help="Repository path or a directory containing repositories")
    mode_group = scan_parser.add_mutually_exclusive_group()
    mode_group.add_argument("--safe", action="store_true", help="Patch and verify on safe copies only")
    mode_group.add_argument("--apply", action="store_true", help="Apply verified patches back to the original repository")
    scan_parser.add_argument(
        "--max-rounds",
        type=int,
        default=5,
        help="Maximum number of attack/patch/verify rounds before stopping",
    )

    args = parser.parse_args(raw_args)
    args.mode = "apply" if getattr(args, "apply", False) else "safe"
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
    console.print(
        Panel.fit(
            f"[bold cyan]Repository: {repository_root.name}[/bold cyan]\n"
            f"[white]Path:[/white] {repository_root}"
        )
    )

    referee = Referee()
    target_root = repository_root.resolve()
    current_root = target_root
    round_reports: list[dict] = []
    remaining_findings: list[VulnerabilityFinding] = []
    discovered_findings: set[tuple[str, str, int, str]] = set()
    battle_status = "complete"
    termination_reason = "No referee-verified vulnerabilities remain."
    patches_generated = 0

    for round_number in range(1, max_rounds + 1):
        console.print(Panel.fit(f"[bold magenta]{repository_root.name} :: Round {round_number}[/bold magenta]"))
        console.print("[bold red][RED][/bold red] Searching for additional weaknesses...")

        findings = red_agent.scan(current_root)
        for finding in findings:
            discovered_findings.add(_finding_key(finding))
        remaining_findings = findings
        score_before = referee.calculate_security_score(findings)

        if not findings:
            console.print("[green][REFEREE] No verified weaknesses remain. Autonomous cycle complete.[/green]")
            break

        selection = _select_verified_attack(red_agent, referee, current_root, findings)
        if selection is None:
            battle_status = "stalled"
            termination_reason = "Detectors found suspicious code, but the referee could not reproduce an exploit."
            console.print("[yellow][REFEREE] No candidate exploit could be reproduced. Battle halted.[/yellow]")
            break

        finding, attack_plan, vulnerable_check = selection
        console.print(
            f"[red][RED][/red] {finding.vulnerability_type} prioritized at "
            f"{finding.metadata.get('relative_file', finding.affected_file)}:{finding.line_number}"
        )
        console.print(f"[red][RED][/red] Payload prepared: {attack_plan.payload}")
        console.print(f"[green][REFEREE] Attack succeeded.[/green] {vulnerable_check.evidence}")
        console.print("[bold blue][BLUE][/bold blue] Generating patch on a safe copy...")

        patch_result = blue_agent.generate_patch(current_root, finding)
        patches_generated += 1
        console.print(f"[green][BLUE][/green] Patch staged: {patch_result.patched_file}")
        console.print("[bold cyan][REFEREE][/bold cyan] Retesting patched candidate...")

        patched_check = referee.verify_exploit(patch_result.patched_root, finding, attack_plan.payload)
        patch_succeeded = not patched_check.attack_succeeded

        if patch_succeeded:
            if mode == "apply":
                _apply_patch_to_original(target_root, patch_result)
                current_root = target_root
                console.print("[green][BLUE] Verified patch applied to the original repository.[/green]")
            else:
                current_root = patch_result.patched_root

            remaining_findings = red_agent.scan(current_root)
            for next_finding in remaining_findings:
                discovered_findings.add(_finding_key(next_finding))
            console.print("[green][REFEREE] Exploit blocked. Patch promoted to the next round.[/green]")
        else:
            remaining_findings = findings
            battle_status = "stalled"
            termination_reason = "The patched copy still allowed the exploit."
            console.print("[red][REFEREE] Exploit still works after patching. Battle halted.[/red]")

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
            f"[cyan][REFEREE] Security score:[/cyan] {round_score.score_before} -> "
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
        console.print("[yellow][REFEREE] Maximum rounds reached before the battle fully converged.[/yellow]")

    final_score = referee.calculate_security_score(remaining_findings)
    report = report_generator.build_report(
        repository_name=repository_root.name,
        mode=mode,
        target_root=target_root,
        final_root=current_root,
        battle_status=battle_status,
        termination_reason=termination_reason,
        final_security_score=final_score,
        remaining_findings=remaining_findings,
        rounds=round_reports,
        capability_matrix={
            "RED": red_agent.capability_matrix(),
            "BLUE": blue_agent.capability_matrix(),
            "REFEREE": referee.capability_matrix(),
        },
    )
    report_paths = report_generator.write_reports(report)
    console.print("[bold cyan][YATA] Repository cycle finished[/bold cyan]")
    console.print(json.dumps(report_paths, indent=2))

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
) -> tuple[VulnerabilityFinding, AttackPlan, VerificationResult] | None:
    for finding in red_agent.prioritize(findings):
        attack_plan = red_agent.plan_attack(finding)
        console.print(
            f"[bold red][RED][/bold red] Evaluating {finding.vulnerability_type} "
            f"({Path(str(finding.metadata.get('relative_file', finding.affected_file))).name}:{finding.line_number})"
        )
        console.print("[bold cyan][REFEREE][/bold cyan] Replaying exploit...")
        vulnerable_check = referee.verify_exploit(current_root, finding, attack_plan.payload)
        if vulnerable_check.attack_succeeded:
            return finding, attack_plan, vulnerable_check
        console.print("[yellow][REFEREE] Candidate did not reproduce. Continuing search.[/yellow]")
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


def _print_suite_summary(summaries: list[RepositoryRunSummary]) -> None:
    table = Table(title="YATA Repository Summary")
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
