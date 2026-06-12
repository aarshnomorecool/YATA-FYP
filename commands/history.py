from __future__ import annotations
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table

def run(args) -> int:
    repo_name = args.target
    console = Console()
    
    project_root = Path(__file__).resolve().parent.parent
    mem_file = project_root / ".yata" / "memory" / repo_name / "memory.json"
    
    if not mem_file.exists():
        console.print(f"[red]Error: No history found for repository: {repo_name}[/red]")
        return 1
        
    try:
        mem = json.loads(mem_file.read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[red]Error: Failed to read memory file: {e}[/red]")
        return 1
        
    history = mem.get("assessment_history", [])
    if not history:
        console.print(f"[yellow]No assessment history entries found for repository: {repo_name}[/yellow]")
        return 0
        
    table = Table(title=f"Assessment History: {repo_name}", border_style="cyan")
    table.add_column("Date", style="cyan")
    table.add_column("Before", justify="right")
    table.add_column("After", justify="right")
    table.add_column("Findings", justify="right")
    
    for entry in history:
        table.add_row(
            str(entry.get("date", "")),
            str(entry.get("score_before", 0)),
            str(entry.get("score_after", 0)),
            str(entry.get("findings", 0))
        )
        
    console.print(table)
    return 0
