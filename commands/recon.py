from __future__ import annotations

import importlib.util
import os
import shutil
import threading
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from llm_client import LLMClient
from recon import ReconAgent
from recon.profile import ReconProfile
from report_generator import ReportGenerator

console = Console()


def run(args) -> int:
    if args.serve_local:
        return _run_against_local_test_repo(args)
    if not args.target:
        console.print(
            "[red]Provide a base URL (e.g. yata recon http://127.0.0.1:8765) "
            "or --serve-local <test_repo_dir>.[/red]"
        )
        return 1
    return _run_against_base_url(args.target, args)


def _run_against_base_url(base_url: str, args) -> int:
    profile = ReconProfile.load(Path(args.profile)) if args.profile else None
    agent = ReconAgent()
    result = agent.run(base_url, profile=profile)

    console.print(
        Panel(
            f"RECON target: {base_url}\n"
            f"Endpoints checked: {result.endpoints_checked}\n"
            f"Findings: {len(result.findings)}",
            border_style="cyan",
        )
    )
    for finding in result.findings:
        console.print(f" - {finding.vulnerability_type} at {finding.affected_file} (payload: {finding.exploit_payload!r})")
        finding.metadata["explanation"] = agent.explain_finding(finding)
        console.print(f"   Explanation: {finding.metadata['explanation']}")

    _write_recon_report(base_url, result, agent)

    return 0 if not result.findings else 1


def _write_recon_report(base_url: str, result, agent: ReconAgent) -> dict[str, str]:
    project_root = Path(__file__).resolve().parent.parent
    # Windows-safe: repository_name and the reports directory both derive from
    # this slug. LearnerAgent.get_memory_file() does `memory_root / repository_name`
    # then mkdir()s it -- a raw URL (colons, slashes) would raise OSError there.
    host_slug = base_url.replace("://", "_").replace(":", "_").replace("/", "_")
    repository_name = f"recon_{host_slug}"
    generator = ReportGenerator(project_root / ".yata" / "reports" / repository_name)

    report = generator.build_report(
        repository_name=repository_name,
        mode="recon",
        patch_mode="N/A (RECON does not patch)",
        patch_applied_to_original="No",
        verification_result="Failed" if result.findings else "Passed",
        target_root=base_url,
        final_root=base_url,
        battle_status="complete",
        termination_reason=(
            "RECON found exploitable live weaknesses."
            if result.findings
            else "RECON scan complete; no exploitable weaknesses found."
        ),
        final_security_score=max(0, 100 - 30 * len(result.findings)),
        remaining_findings=result.findings,
        rounds=[],
        capability_matrix={"RECON": agent.capability_matrix()},
        performance_telemetry={
            "hunter_discovery": 0.0,
            "hunter_attack": 0.0,
            "healer_patch": 0.0,
            "validator_verification": 0.0,
            "llm_requests": 0,
            "llm_time": 0.0,
            "avg_llm_response": 0.0,
            "report_generation": 0.0,
            "total_runtime": result.scan_seconds + result.exploit_seconds,
        },
        execution_mode=LLMClient.execution_mode,
    )
    paths = generator.write_reports(report)
    console.print(f"Reports written: {paths}")
    return paths


def _run_against_local_test_repo(args) -> int:
    repo_dir = Path(args.serve_local).resolve()
    if not repo_dir.exists():
        console.print(f"[red]Repository path does not exist: {repo_dir}[/red]")
        return 1

    # Dev/test-only convenience: never touches the fixture in place (Golden
    # Rule 3), and lives here rather than inside the recon/ package so RECON
    # itself stays a pure black-box HTTP client.
    sandbox_dir = Path(__file__).resolve().parent.parent / ".yata" / "recon_sandbox" / repo_dir.name
    if sandbox_dir.exists():
        shutil.rmtree(sandbox_dir, ignore_errors=True)
    shutil.copytree(repo_dir, sandbox_dir, ignore=shutil.ignore_patterns(".yata", ".git", "__pycache__"))

    # Some fixtures (e.g. repo7_path_traversal) open relative paths like
    # "uploads/<file>" against the process cwd rather than the app's own
    # directory -- mirror verifier.py's _verify_path_traversal, which chdirs
    # into app_root for the same reason, and restore cwd afterward.
    old_cwd = os.getcwd()
    os.chdir(sandbox_dir)
    server = None
    thread = None
    try:
        unique_name = f"yata_recon_target_{abs(hash(str(sandbox_dir.resolve())))}"
        spec = importlib.util.spec_from_file_location(unique_name, sandbox_dir / "app.py")
        if spec is None or spec.loader is None:
            console.print(f"[red]Unable to load app module from {sandbox_dir / 'app.py'}[/red]")
            return 1
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        app = module.create_app(str(sandbox_dir / "database.db"))

        from werkzeug.serving import make_server

        server = make_server("127.0.0.1", args.port, app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.3)

        base_url = f"http://127.0.0.1:{args.port}"
        if not args.profile:
            candidate = sandbox_dir / "yata_profile.json"
            args.profile = str(candidate) if candidate.exists() else None

        console.print(f"[cyan]Serving {repo_dir.name} locally at {base_url}[/cyan]")
        return _run_against_base_url(base_url, args)
    finally:
        if server is not None:
            server.shutdown()
        if thread is not None:
            thread.join(timeout=5)
        os.chdir(old_cwd)
