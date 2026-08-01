from __future__ import annotations
import os
from pathlib import Path
from rich.console import Console

ASSESSABLE_INDICATORS = {"app.py", "yata_profile.json"}
IGNORED_DIRS = {".git", ".venv", "venv", ".yata", "node_modules", "__pycache__"}


def _find_assessable_repos(target_path: Path) -> list[Path]:
    found_repos: list[Path] = []
    for root, dirs, _files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        path_root = Path(root)

        if any((path_root / indicator).exists() for indicator in ASSESSABLE_INDICATORS):
            # This is an assessable repository root; do not descend into it further.
            dirs.clear()
            found_repos.append(path_root)

    found_repos.sort(key=lambda p: p.name)
    return found_repos


def run(args) -> int:
    target_path = Path(args.target).resolve()
    if not target_path.exists():
        print(f"Error: Path does not exist: {target_path}")
        return 1

    console = Console()
    found_repos = _find_assessable_repos(target_path)

    if not found_repos:
        console.print("[bold yellow]No repositories found.[/bold yellow]")
        return 0

    console.print(f"[bold white]Discovered {len(found_repos)} repositories:[/bold white]\n")
    for repo in found_repos:
        console.print(repo.name)
    console.print()

    import yata

    args.target = str(target_path)
    args.demo = False
    args.mode = "safe"
    args.max_rounds = getattr(args, "max_rounds", 5)
    args.verbose = getattr(args, "verbose", False)
    args.live = getattr(args, "live", False)
    args.quiet = getattr(args, "quiet", False)

    return yata.assess_entrypoint(args, repository_roots=found_repos)
