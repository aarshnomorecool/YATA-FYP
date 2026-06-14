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

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.align import Align

from blue_agent import BlueAgent, PatchResult
from red_agent import AttackPlan, RedAgent, VulnerabilityFinding
from report_generator import ReportGenerator
from verifier import Referee, VerificationResult
from llm_client import LLMClient


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
    initial_security_score: int
    battle_status: str
    report_paths: dict[str, str]
    vulnerability_summary: str
    vulnerabilities_healed: int
    human_interventions: int


def assess_entrypoint(args: argparse.Namespace) -> int:
    start_time_all = time.time()

    banner = """
██╗   ██╗ █████╗ ████████╗ █████╗ 
╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔══██╗
 ╚████╔╝ ███████║   ██║   ███████║
  ╚██╔╝  ██╔══██║   ██║   ██╔══██║
   ██║   ██║  ██║   ██║   ██║  ██║
   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
"""
    banner_lines = [line for line in banner.split("\n") if line.strip()]
    logo_block = "\n".join(banner_lines)

    splash_group = Group(
        Align.center(f"[bold red]{logo_block}[/bold red]"),
        Align.center(""),
        Align.center("[bold white]Yet Another Threat Antagonist[/bold white]"),
        Align.center("[dim]Autonomous Cyber Defense & Patching Agent[/dim]")
    )
    if not args.quiet:
        console.print(Panel(splash_group, border_style="bold red", expand=True))

    if args.max_rounds < 1:
        console.print("[red]--max-rounds must be at least 1[/red]")
        return 1

    if args.demo:
        LLMClient.execution_mode = "demo"
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
    red_agent = RedAgent()
    blue_agent = BlueAgent()
    red_agent.verbose = args.verbose
    blue_agent.verbose = args.verbose
    report_generator = ReportGenerator(Path(__file__).resolve().parent / "reports")
    summaries: list[RepositoryRunSummary] = []

    if not args.quiet:
        if args.verbose:
            console.print(
                Panel(
                    f"[bold cyan][YATA] Autonomous Security Assessment Started[/bold cyan]\n"
                    f"[white]Target:[/white] {_clean_path(target_path)}\n"
                    f"[white]Repositories:[/white] {len(repository_roots)}\n"
                    f"[white]Mode:[/white] {args.mode.upper() if args.mode else 'AUTO'}",
                    expand=True
                )
            )
        else:
            mode_str = "NVIDIA Assisted"
            if LLMClient.execution_mode == "autonomous_fallback":
                mode_str = "Autonomous Fallback"
            elif LLMClient.execution_mode == "demo":
                temp_client = LLMClient()
                mode_str = "NVIDIA Assisted" if temp_client.api_key else "Autonomous Fallback"

            from learner_agent import LearnerAgent
            learner = LearnerAgent()
            if len(repository_roots) == 1:
                pre_mem = learner.load_memory(repository_roots[0].name)
                if pre_mem:
                    pre_assessments = pre_mem.get("total_assessments", 0)
                    mem_summary = f"{pre_assessments} Assessment{'s' if pre_assessments != 1 else ''}"
                else:
                    mem_summary = "First Assessment"
            else:
                total_assessments = 0
                all_first = True
                for root in repository_roots:
                    pre_mem = learner.load_memory(root.name)
                    if pre_mem:
                        total_assessments += pre_mem.get("total_assessments", 0)
                        all_first = False
                if all_first:
                    mem_summary = "First Assessment"
                else:
                    mem_summary = f"{total_assessments} Assessment{'s' if total_assessments != 1 else ''}"

            startup_content = (
                f"Mode: {mode_str}\n"
                f"Target: {target_path.name}\n"
                f"Memory: {mem_summary}"
            )
            console.print(Panel(startup_content, border_style="cyan", expand=True))
            console.print()

    if args.verbose and not args.quiet:
        if LLMClient.execution_mode == "demo":
            console.print("[YATA]")
            console.print("Demo Mode\n")
            console.print("Using Autonomous Demonstration Environment.\n")
            console.print("AI Reasoning:")
            console.print("Disabled")
        elif LLMClient.execution_mode == "autonomous_fallback":
            console.print("[YATA]")
            console.print("Execution Mode:")
            console.print("Autonomous Fallback\n")
            console.print("Capabilities:")
            console.print("✓ SQL Injection")
            console.print("✓ Hardcoded Secret")
            console.print("✓ Patch Verification")
            console.print("✓ Security Assessment\n")
            console.print("AI Reasoning:")
            console.print("Disabled")
            if not LLMClient.fallback_message_printed:
                LLMClient.fallback_message_printed = True
                console.print("\n[YATA]\nAutonomous Fallback Mode Activated\n\nNVIDIA API unavailable or timed out.\nSwitching to offline deterministic models.")
        else:
            console.print("[YATA]")
            console.print("Execution Mode:")
            console.print("NVIDIA Assisted\n")
            console.print("Capabilities:")
            console.print("✓ AI Reasoning")
            console.print("✓ Dynamic Patch Generation")
            console.print("✓ Attack Validation")
            console.print("✓ Security Assessment")
    else:
        if not args.quiet:
            if LLMClient.execution_mode == "autonomous_fallback":
                if not LLMClient.fallback_message_printed:
                    LLMClient.fallback_message_printed = True
                    console.print("Autonomous Fallback Mode Activated\n")
                    console.print("NVIDIA API unavailable or timed out.")
                    console.print("Switching to offline deterministic models.\n")

    for repository_root in repository_roots:
        if len(repository_roots) > 1 and not args.verbose and not args.quiet:
            console.print("Current Repository:")
            console.print(f"{repository_root.name}")

        summary = _run_repository(
            repository_root=repository_root,
            mode=args.mode,
            max_rounds=args.max_rounds,
            red_agent=red_agent,
            blue_agent=blue_agent,
            report_generator=report_generator,
            verbose=args.verbose,
            live=args.live,
            quiet=args.quiet,
            multi_repo=(len(repository_roots) > 1),
        )
        summaries.append(summary)

        if len(repository_roots) > 1 and not args.verbose and not args.quiet:
            checkmark = "[bold green]✓[/bold green]" if summary.verification_result == "Passed" else "[bold red]✗[/bold red]"
            max_repo_len = max(len(r.name) for r in repository_roots)
            console.print(f"{summary.repository_name:<{max_repo_len}}      {checkmark} {summary.vulnerability_summary:<18}   {summary.initial_security_score} → {summary.security_score}\n")

    if len(repository_roots) > 1 and not args.quiet:
        console.print("\n[bold white]Repository Summary Table[/bold white]\n")
        table = Table(border_style="cyan")
        table.add_column("Repository", style="cyan")
        table.add_column("Before", justify="right")
        table.add_column("After", justify="right")
        for summary in summaries:
            table.add_row(
                summary.repository_name,
                str(summary.initial_security_score),
                str(summary.security_score)
            )
        console.print(table)
        console.print()



    return 0 if all(summary.battle_status == "complete" for summary in summaries) else 1


def dispatch_command(args: argparse.Namespace) -> int:
    if args.command in ("assess", "scan"):
        from commands import assess
        return assess.run(args)
    elif args.command == "discover":
        from commands import discover
        return discover.run(args)
    elif args.command == "memory":
        from commands import memory
        return memory.run(args)
    elif args.command == "history":
        from commands import history
        return history.run(args)
    elif args.command == "report":
        from commands import report
        return report.run(args)
    elif args.command == "status":
        from commands import status
        return status.run(args)
    elif args.command == "version":
        from commands import version
        return version.run(args)
    elif args.command == "help":
        from commands import help as help_cmd
        return help_cmd.run(args)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    return dispatch_command(args)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    
    subcommands = {"assess", "scan", "discover", "memory", "history", "report", "status", "version", "help"}
    
    if not raw_args:
        raw_args = ["assess"]
    elif raw_args[0] not in subcommands and raw_args[0] not in ("-h", "--help"):
        raw_args = ["assess", *raw_args]

    parser = argparse.ArgumentParser(description="YATA - Yet Another Threat Antagonist CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. assess
    assess_parser = subparsers.add_parser("assess", aliases=["scan"], help="Assess a repository or directory of repositories")
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
    assess_parser.add_argument("--verbose", action="store_true", help="Display verbose debugging information")
    assess_parser.add_argument("--live", action="store_true", help="Enable live feedback mode (future feature placeholder)")
    assess_parser.add_argument("--quiet", action="store_true", help="Run in quiet mode (future feature placeholder)")

    # 2. discover
    discover_parser = subparsers.add_parser("discover", help="Discover repositories in a directory path")
    discover_parser.add_argument("target", help="Directory path to scan recursively")

    # 3. memory
    memory_parser = subparsers.add_parser("memory", help="Display memory statistics for a repository")
    memory_parser.add_argument("target", help="Repository name")

    # 4. history
    history_parser = subparsers.add_parser("history", help="Display chronological history for a repository")
    history_parser.add_argument("target", help="Repository name")

    # 5. report
    report_parser = subparsers.add_parser("report", help="Locate the newest report for a repository")
    report_parser.add_argument("target", help="Repository name")

    # 6. status
    subparsers.add_parser("status", help="Display aggregate platform status")

    # 7. version
    subparsers.add_parser("version", help="Display version and capability checklist")

    # 8. help
    help_parser = subparsers.add_parser("help", help="Display YATA CLI help")
    help_parser.add_argument("subcommand", nargs="?", default=None, help="Optional subcommand to show help for")

    args = parser.parse_args(raw_args)

    if args.command in ("assess", "scan"):
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
    verbose: bool = False,
    live: bool = False,
    quiet: bool = False,
    multi_repo: bool = False,
) -> RepositoryRunSummary:
    global console
    console = Console(record=True)

    # Initialize Telemetry
    start_time = time.time()
    human_interventions = 0
    red_agent.llm.llm_requests = 0
    red_agent.llm.llm_time = 0.0
    blue_agent.llm.llm_requests = 0
    blue_agent.llm.llm_time = 0.0

    t_hunter_discovery = 0.0
    t_hunter_attack = 0.0
    t_healer_patch = 0.0
    t_validator_verification = 0.0

    if verbose:
        console.print(
            Panel.fit(
                f"[bold cyan]Repository: {repository_root.name}[/bold cyan]\n"
                f"[white]Path:[/white] {_clean_path(repository_root)}"
            )
        )
    else:
        if not multi_repo:
            console.print("Working On:")
            console.print(f"{repository_root.name}\n")
            if LLMClient.execution_mode in ("autonomous_fallback", "demo"):
                console.print("HUNTER      → Deterministic Mode")
                console.print("HEALER      → Deterministic Mode\n")

    referee = Referee()
    target_root = repository_root.resolve()

    project_root = Path(__file__).resolve().parent
    yata_dir = project_root / ".yata"
    repo_name = repository_root.name

    # Repository Memory load & startup display
    from learner_agent import LearnerAgent
    learner = LearnerAgent()
    pre_mem = learner.load_memory(repo_name)
    pre_assessments = pre_mem.get("total_assessments", 0) if pre_mem else 0
    post_mem = None

    if not quiet:
        if pre_mem:
            vulns_list = ", ".join(pre_mem.get("vulnerabilities_seen", {}).keys())
            if not vulns_list:
                vulns_list = "None"
            mem_text = (
                "[bold white]Repository Memory[/bold white]\n\n"
                f"Assessments: {pre_assessments}\n"
                f"Last Score: {pre_mem.get('last_score', 0)}\n"
                f"Known Vulnerabilities: {vulns_list}"
            )
            console.print(Panel(mem_text, border_style="yellow", expand=True))
            console.print()
        else:
            mem_text = (
                "[bold white]Repository Memory[/bold white]\n\n"
                "First Assessment\n"
                "No Prior Knowledge"
            )
            console.print(Panel(mem_text, border_style="yellow", expand=True))
            console.print()

    reports_dir = yata_dir / "reports" / repo_name
    patches_dir = yata_dir / "patches" / repo_name
    analysis_dir = yata_dir / "analysis" / repo_name
    logs_dir = yata_dir / "logs" / repo_name
    metadata_dir = yata_dir / "metadata" / repo_name

    yata_dir.mkdir(exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    patches_dir.mkdir(parents=True, exist_ok=True)
    analysis_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    metadata_dir.mkdir(parents=True, exist_ok=True)

    metadata_file = metadata_dir / "metadata.json"
    metadata_content = {
        "version": "0.4.2",
        "workspace_initialized": True,
        "created_by": "YATA"
    }
    metadata_file.write_text(json.dumps(metadata_content, indent=2), encoding="utf-8")

    report_generator.reports_root = reports_dir

    if verbose:
        console.print("[bold cyan][YATA][/bold cyan] Workspace initialized at:")
        console.print(f"  {_clean_path(yata_dir)}")
        console.print(f"[bold cyan][YATA][/bold cyan] Reports:             {_clean_path(reports_dir)}/")
        console.print(f"[bold cyan][YATA][/bold cyan] Patched Files:       {_clean_path(patches_dir)}/")
        console.print(f"[bold cyan][YATA][/bold cyan] Security Assessment: {_clean_path(analysis_dir)}/")
        console.print(f"[bold cyan][YATA][/bold cyan] Logs:                {_clean_path(logs_dir)}/\n")

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
        if verbose:
            console.print(Panel(f"[bold magenta]Assessment Round {round_number}[/bold magenta]", border_style="magenta", expand=True))
            console.print("[bold red][HUNTER][/bold red] Evaluating attack paths...")

        start_disc = time.time()
        findings = red_agent.scan(current_root)
        t_hunter_discovery += time.time() - start_disc

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
            if verbose:
                console.print("[bold green][VALIDATOR][/bold green] Repository is clean. No further weaknesses found.")
            break

        start_att = time.time()
        selection = _select_verified_attack(red_agent, referee, current_root, findings, all_findings, verbose=verbose, multi_repo=multi_repo)
        t_hunter_attack += time.time() - start_att

        if selection is None:
            battle_status = "stalled"
            termination_reason = "Detectors flagged suspicious patterns, but VALIDATOR could not reproduce an exploit."
            if verbose:
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
        
        if verbose:
            console.print(f"[bold red][HUNTER][/bold red] Prioritized weakness: [bold cyan]{finding.vulnerability_type}[/bold cyan]")
            console.print(f" └─ Severity:  [{sev_color}]{severity}[/{sev_color}]")
            console.print(f" └─ Location:  {_clean_path(finding.metadata.get('relative_file', finding.affected_file))}:{finding.line_number}")
            console.print(f" └─ OWASP:     {mapping.get('owasp', 'N/A')}")
            console.print(f" └─ CWE:       {mapping.get('cwe', 'N/A')}")
            impact_str = ", ".join(mapping.get('impact', 'N/A').split(", "))
            console.print(f" └─ Impact:    {impact_str}")
            console.print(f" └─ Payload:   [cyan]{attack_plan.payload}[/cyan]")
            console.print(f"[bold green][VALIDATOR][/bold green] Vulnerability verified: {vulnerable_check.evidence}")
        else:
            if not multi_repo:
                console.print(f"Location: {_clean_path(finding.metadata.get('relative_file', finding.affected_file))}:{finding.line_number}")
                console.print(f"Severity: {severity}")

        if verbose:
            console.print("[bold blue][HEALER][/bold blue] Generating secure patch...")

        start_patch = time.time()
        patch_result = blue_agent.generate_patch(current_root, finding)
        t_healer_patch += time.time() - start_patch
        patches_generated += 1
        try:
            rel_file = Path(patch_result.patched_file).relative_to(patch_result.patched_root)
        except ValueError:
            rel_file = Path(patch_result.patched_file).name
        rel_patch_path = _clean_path(patches_dir / rel_file)
        if verbose:
            console.print(f" └─ Patch written → {rel_patch_path}")
        else:
            if not multi_repo:
                console.print()
                console.print("HEALER      [bold green]✓[/bold green] Patch Generated\n")

        if verbose:
            if LLMClient.execution_mode in ("autonomous_fallback", "demo"):
                print("[VALIDATOR]")
            else:
                console.print("[bold cyan][VALIDATOR][/bold cyan] Attacking patched code...")

        start_verify = time.time()
        patched_check = referee.verify_exploit(patch_result.patched_root, finding, attack_plan.payload)
        t_validator_verification += time.time() - start_verify
        patch_succeeded = not patched_check.attack_succeeded

        if verbose:
            if LLMClient.execution_mode in ("autonomous_fallback", "demo"):
                if patch_succeeded:
                    print("Exploit blocked.\n")
                    print("Patch verified.")
                else:
                    print("Exploit succeeded.\n")
                    print("Patch failed.")
            else:
                if patch_succeeded:
                    console.print(" └─ Exploit blocked ✓")
                    console.print("[bold blue][HEALER][/bold blue] Patch verified.\n")
        else:
            if not multi_repo:
                if patch_succeeded:
                    val_msg = "Secret Externalized" if finding.vulnerability_type == "Hardcoded Secret" else "Exploit Blocked"
                    console.print(f"VALIDATOR   [bold green]✓[/bold green] {val_msg}\n")
                else:
                    console.print("VALIDATOR   [bold red]✗[/bold red] Exploit Succeeded\n")

        if patch_succeeded:
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
                human_interventions += 1
                try:
                    response = input("Apply verified patch to original repository? [Y/N]: ").strip().upper()
                except (KeyboardInterrupt, EOFError):
                    response = "N"
                if response in ("Y", "YES"):
                    apply_verified = True

            if apply_verified:
                if verbose:
                    console.print("[bold cyan][YATA][/bold cyan] Applying verified patch to original repository...\n")
                _apply_patch_to_original(target_root, patch_result)
                current_root = target_root
                patch_applied = True
                if verbose:
                    console.print("[bold cyan][YATA][/bold cyan] Repository healed successfully.")
            else:
                current_root = patch_result.patched_root

            start_disc = time.time()
            remaining_findings = red_agent.scan(current_root)
            t_hunter_discovery += time.time() - start_disc
            for next_finding in remaining_findings:
                discovered_findings.add(_finding_key(next_finding))
            if verbose and LLMClient.execution_mode not in ("autonomous_fallback", "demo"):
                console.print("[bold green][VALIDATOR][/bold green] Patch verification successful. Changes promoted.")
        else:
            remaining_findings = findings
            battle_status = "stalled"
            termination_reason = "The patched copy still allowed the exploit."
            if verbose and LLMClient.execution_mode not in ("autonomous_fallback", "demo"):
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
        if verbose:
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
        start_disc = time.time()
        remaining_findings = red_agent.scan(current_root)
        t_hunter_discovery += time.time() - start_disc
        for finding in remaining_findings:
            discovered_findings.add(_finding_key(finding))
        battle_status = "max_rounds_reached"
        termination_reason = f"Reached max round limit ({max_rounds}) before the system became clean."
        if verbose:
            console.print("[bold yellow][VALIDATOR][/bold yellow] Maximum rounds reached before the repository became clean.")

    verification_result = "Passed" if battle_status == "complete" and not remaining_findings else "Failed"
    final_score = referee.calculate_security_score(remaining_findings)

    # Run LEARNER Agent to update repository memory
    successful_patches = []
    failed_patches = []
    for rd in round_reports:
        vtype = rd["finding"]["vulnerability_type"]
        if rd["referee"]["patch_succeeded"]:
            successful_patches.append(vtype)
        else:
            failed_patches.append(vtype)

    today = datetime.now().strftime("%Y-%m-%d")
    post_mem = learner.update_memory(
        repository_name=repo_name,
        timestamp=today,
        findings_count=len(discovered_findings),
        vulnerability_types=[f[0] for f in discovered_findings],
        successful_patches=successful_patches,
        failed_patches=failed_patches,
        initial_score=score_before_all,
        final_score=final_score,
        validation_outcome=verification_result
    )

    # Initial Report build
    start_rep = time.time()
    llm_requests = red_agent.llm.llm_requests + blue_agent.llm.llm_requests
    llm_time = red_agent.llm.llm_time + blue_agent.llm.llm_time
    avg_llm_response = llm_time / llm_requests if llm_requests > 0 else 0.0

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
        performance_telemetry={
            "hunter_discovery": t_hunter_discovery,
            "hunter_attack": t_hunter_attack,
            "healer_patch": t_healer_patch,
            "validator_verification": t_validator_verification,
            "llm_requests": int(llm_requests) if LLMClient.execution_mode not in ("autonomous_fallback", "demo") else 0,
            "llm_time": llm_time if LLMClient.execution_mode not in ("autonomous_fallback", "demo") else 0.0,
            "avg_llm_response": avg_llm_response if LLMClient.execution_mode not in ("autonomous_fallback", "demo") else 0.0,
            "report_generation": 0.0,
            "total_runtime": 0.0,
        },
        execution_mode=LLMClient.execution_mode,
    )
    report_paths = report_generator.write_reports(report)
    
    t_report_generation = time.time() - start_rep
    t_total_runtime = time.time() - start_time

    # Update report metrics and write again to persist accurate durations
    report.performance_telemetry["report_generation"] = t_report_generation
    report.performance_telemetry["total_runtime"] = t_total_runtime
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

    assessment_data = {
        "assessment_date": datetime.now().strftime("%Y-%m-%d"),
        "performance_telemetry": {
            "hunter_discovery": round(t_hunter_discovery, 1),
            "hunter_attack": round(t_hunter_attack, 1),
            "healer_patch": round(t_healer_patch, 1),
            "validator_verification": round(t_validator_verification, 1),
            "llm_requests": int(llm_requests) if LLMClient.execution_mode not in ("autonomous_fallback", "demo") else 0,
            "llm_time": round(llm_time, 1) if LLMClient.execution_mode not in ("autonomous_fallback", "demo") else 0.0,
            "avg_llm_response": round(avg_llm_response, 1) if LLMClient.execution_mode not in ("autonomous_fallback", "demo") else 0.0,
            "report_generation": round(t_report_generation, 1),
            "total_runtime": round(t_total_runtime, 1),
        },
        "findings": findings_data
    }
    if LLMClient.execution_mode in ("autonomous_fallback", "demo"):
        assessment_data.update({
            "execution_mode": LLMClient.execution_mode,
            "llm_requests": 0,
            "llm_time": 0.0,
            "fallback_actions": {
                "hunter_deterministic": True,
                "healer_deterministic": True
            }
        })
    else:
        assessment_data.update({
            "execution_mode": "nvidia_assisted"
        })
    findings_file = analysis_dir / "security_assessment.json"
    findings_file.write_text(json.dumps(assessment_data, indent=2), encoding="utf-8")

    log_content = console.export_text()
    log_file = logs_dir / f"run_{datetime.now().strftime('%Y-%m-%d')}.log"
    log_file.write_text(log_content, encoding="utf-8")

    v_types = {f[0] for f in discovered_findings}
    if not v_types:
        v_summary = "Clean"
    elif len(v_types) == 1:
        v_summary = list(v_types)[0]
    else:
        v_summary = "Mixed"

    exec_mode_str = "NVIDIA Assisted"
    if LLMClient.execution_mode == "autonomous_fallback":
        exec_mode_str = "Autonomous Fallback"
    elif LLMClient.execution_mode == "demo":
        temp_client = LLMClient()
        if not temp_client.api_key:
            exec_mode_str = "Autonomous Fallback"

    if not quiet:
        if verbose or not multi_repo:
            _print_assessment_summary_pass(
                repo_name=repository_root.name,
                healed_count=healed_count,
                initial_score=score_before_all,
                final_score=final_score,
                runtime=t_total_runtime,
                vulnerabilities_found=len(discovered_findings),
                verification_result=verification_result,
                human_interventions=human_interventions,
                exec_mode=exec_mode_str,
                pre_assessments=pre_assessments,
                post_mem=post_mem,
                llm_requests=llm_requests,
                llm_time=llm_time,
                avg_llm_response=avg_llm_response
            )

        if verbose:
            # Performance Telemetry Dashboard Output
            console.print("\n[bold cyan][YATA] Performance Metrics[/bold cyan]\n")
            console.print(f"HUNTER Discovery:         {t_hunter_discovery:.1f}s")
            console.print(f"HUNTER Attack Eval:       {t_hunter_attack:.1f}s\n")
            console.print(f"HEALER Patch Generation: {t_healer_patch:.1f}s\n")
            console.print(f"VALIDATOR Verification:   {t_validator_verification:.1f}s\n")
            console.print(f"LLM Requests:             {llm_requests}")
            console.print(f"LLM Time:                {llm_time:.1f}s")
            console.print(f"Average Response:         {avg_llm_response:.1f}s\n")
            console.print(f"Report Generation:        {t_report_generation:.1f}s\n")
            console.print(f"TOTAL Runtime:           {t_total_runtime:.1f}s")

            # Runtime Warnings
            if t_total_runtime > 120:
                console.print("\n[bold red][YATA] Critical Runtime Warning[/bold red]\n")
                console.print("Assessment duration may impact interactive workflows.")
            elif t_total_runtime > 60:
                console.print("\n[bold yellow][YATA] Performance Warning[/bold yellow]\n")
                console.print("Repository assessment exceeded recommended runtime.")
                console.print("Consider provider fallback or reducing attack library size.")
            console.print()

            console.print("[bold cyan][YATA] Security assessment complete.[/bold cyan]")
            cleaned_report_paths = {k: _clean_path(v) for k, v in report_paths.items()}
            console.print(json.dumps(cleaned_report_paths, indent=2))

    return RepositoryRunSummary(
        repository_name=repository_root.name,
        vulnerabilities_found=len(discovered_findings),
        patches_generated=patches_generated,
        verification_result=verification_result,
        security_score=final_score,
        initial_security_score=score_before_all,
        battle_status=battle_status,
        report_paths=report_paths,
        vulnerability_summary=v_summary,
        vulnerabilities_healed=healed_count,
        human_interventions=human_interventions,
    )


def _select_verified_attack(
    red_agent: RedAgent,
    referee: Referee,
    current_root: Path,
    findings: list[VulnerabilityFinding],
    findings_tracker: dict[tuple, dict] | None = None,
    verbose: bool = False,
    multi_repo: bool = False,
) -> tuple[VulnerabilityFinding, AttackPlan, VerificationResult] | None:
    for finding in red_agent.prioritize(findings):
        payloads = red_agent.get_payloads_for_finding(finding)
        
        if verbose:
            console.print(f"[bold red][HUNTER][/bold red] Evaluating attack paths for {finding.vulnerability_type}...")
            console.print(f" └─ Payloads loaded: {len(payloads)}")

        winning_payload = None
        vulnerable_check = None
        payloads_attempted = []
        attack_success = False

        for idx, payload in enumerate(payloads, 1):
            payloads_attempted.append(payload)

            if finding.vulnerability_type == "Hardcoded Secret" and payload != finding.exploit_payload:
                if verbose:
                    console.print(f" └─ Payload {idx}/{len(payloads)} FAIL")
                continue

            check = referee.verify_exploit(current_root, finding, payload)
            if check.attack_succeeded:
                if verbose:
                    console.print(f" └─ Payload {idx}/{len(payloads)} SUCCESS ✓")
                winning_payload = payload
                vulnerable_check = check
                attack_success = True
                break
            else:
                if verbose:
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
            if not verbose:
                if not multi_repo:
                    console.print(f"HUNTER      [bold green]✓[/bold green] {finding.vulnerability_type} Confirmed")
            return finding, attack_plan, vulnerable_check

        if verbose:
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


def _print_assessment_summary_pass(
    repo_name: str,
    healed_count: int,
    initial_score: int,
    final_score: int,
    runtime: float,
    vulnerabilities_found: int,
    verification_result: str,
    human_interventions: int,
    exec_mode: str,
    pre_assessments: int = 0,
    post_mem: dict | None = None,
    llm_requests: int = 0,
    llm_time: float = 0.0,
    avg_llm_response: float = 0.0,
) -> None:
    # 1. Final Assessment Card
    card_content = (
        "[bold white]Assessment Complete[/bold white]\n\n"
        "[bold]Repository:[/bold]\n"
        f"{repo_name}\n\n"
        "[bold]Execution Mode:[/bold]\n"
        f"{exec_mode}\n\n"
        "[bold]Security Score:[/bold]\n"
        f"{initial_score} → {final_score}\n\n"
        "[bold]Vulnerabilities Healed:[/bold]\n"
        f"{healed_count}\n\n"
        "[bold]Validation Result:[/bold]\n"
        f"{'PASSED' if verification_result == 'Passed' else 'FAILED'}\n\n"
        "[bold]Reports Generated:[/bold]\n"
        "✓"
    )
    console.print(Panel(card_content, border_style="cyan", expand=True))
    console.print()

    # End-of-Run Learning Summary
    if post_mem is not None:
        if pre_assessments == 0:
            summary_text = (
                "[bold white]Repository Learning Created[/bold white]\n\n"
                f"Assessments: {post_mem['total_assessments']}\n"
                f"Last Score: {post_mem['last_score']}\n"
                f"Known Vulnerabilities: {sum(post_mem['vulnerabilities_seen'].values())}"
            )
        else:
            summary_text = (
                "[bold white]Repository Learning Updated[/bold white]\n\n"
                f"Assessments: {pre_assessments} → {post_mem['total_assessments']}\n"
                f"Last Score: {post_mem['last_score']}\n"
                f"Known Vulnerabilities: {sum(post_mem['vulnerabilities_seen'].values())}"
            )
        console.print(Panel(summary_text, border_style="green", expand=True))
        console.print()

    # 2. Security Score Evolution
    def make_score_bar(score: int) -> str:
        if score == 0:
            return "░" * 10
        filled = max(1, min(10, int(round(score / 10.0))))
        return "█" * filled + "░" * (10 - filled)

    console.print("[bold white]Security Score[/bold white]\n")
    console.print(f"Before   {make_score_bar(initial_score)} {initial_score:>3}\n")
    console.print(f"After    {make_score_bar(final_score)} {final_score:>3}\n")
    console.print(f"Improvement: {final_score - initial_score:+d}\n")
    console.print(f"LLM Requests: {llm_requests}")
    console.print(f"LLM Time: {llm_time:.1f} seconds")
    console.print(f"Average Request: {avg_llm_response:.2f} seconds\n")


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
