from __future__ import annotations
from rich.console import Console

def run(args) -> int:
    console = Console()
    version_text = (
        "[bold white]YATA v0.8.1[/bold white]\n\n"
        "HUNTER     [bold green]✓[/bold green]\n"
        "HEALER     [bold green]✓[/bold green]\n"
        "VALIDATOR  [bold green]✓[/bold green]\n"
        "LEARNER    [bold green]✓[/bold green]\n\n"
        "[bold white]Supported Vulnerabilities[/bold white]\n\n"
        "[bold green]✓[/bold green] SQL Injection\n"
        "[bold green]✓[/bold green] Hardcoded Secret\n"
        "[bold green]✓[/bold green] Command Injection\n"
        "[bold green]✓[/bold green] Path Traversal"
    )
    console.print(version_text)
    return 0
