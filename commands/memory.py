from __future__ import annotations
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

def run(args) -> int:
    repo_name = args.target
    console = Console()
    
    project_root = Path(__file__).resolve().parent.parent
    mem_file = project_root / ".yata" / "memory" / repo_name / "memory.json"
    
    if not mem_file.exists():
        console.print(f"[red]Error: No memory found for repository: {repo_name}[/red]")
        return 1
        
    try:
        mem = json.loads(mem_file.read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[red]Error: Failed to read memory file: {e}[/red]")
        return 1
        
    assessments = mem.get("total_assessments", 0)
    best_score = mem.get("best_score", 0)
    last_score = mem.get("last_score", 0)
    
    vulns = mem.get("vulnerabilities_seen", {})
    vulns_list = "\n".join(f"• {k}: {v}" for k, v in vulns.items()) if vulns else "• None"
    
    success = mem.get("successful_patches", {})
    success_list = "\n".join(f"• {k}: {v}" for k, v in success.items()) if success else "• None"
    
    mem_content = (
        f"[bold white]Repository Memory: {repo_name}[/bold white]\n\n"
        f"Assessments: {assessments}\n"
        f"Best Score:  {best_score}\n"
        f"Last Score:  {last_score}\n\n"
        "[bold white]Known Vulnerabilities:[/bold white]\n"
        f"{vulns_list}\n\n"
        "[bold white]Successful Patch Counts:[/bold white]\n"
        f"{success_list}"
    )
    
    console.print(Panel(mem_content, border_style="yellow", expand=True))
    return 0
