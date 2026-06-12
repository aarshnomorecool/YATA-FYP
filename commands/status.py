from __future__ import annotations
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

def run(args) -> int:
    console = Console()
    
    project_root = Path(__file__).resolve().parent.parent
    memory_root = project_root / ".yata" / "memory"
    
    if not memory_root.exists():
        status_text = (
            "[bold white]YATA System Status[/bold white]\n\n"
            "No repository memory found. Run YATA assessments first."
        )
        console.print(Panel(status_text, border_style="cyan", expand=True))
        return 0
        
    repo_dirs = [d for d in memory_root.iterdir() if d.is_dir() and (d / "memory.json").exists()]
    if not repo_dirs:
        status_text = (
            "[bold white]YATA System Status[/bold white]\n\n"
            "No repository memory found. Run YATA assessments first."
        )
        console.print(Panel(status_text, border_style="cyan", expand=True))
        return 0
        
    repositories_known = len(repo_dirs)
    total_assessments = 0
    successful_patches = 0
    failed_patches = 0
    vulns_counts: dict[str, int] = {}
    
    for d in repo_dirs:
        try:
            mem = json.loads((d / "memory.json").read_text(encoding="utf-8"))
            total_assessments += mem.get("total_assessments", 0)
            
            for v, c in mem.get("successful_patches", {}).items():
                successful_patches += c
                
            for v, c in mem.get("failed_patches", {}).items():
                failed_patches += c
                
            for v, c in mem.get("vulnerabilities_seen", {}).items():
                vulns_counts[v] = vulns_counts.get(v, 0) + c
        except Exception:
            pass
            
    if vulns_counts:
        most_common_vuln = max(vulns_counts.items(), key=lambda x: x[1])
        most_common_text = f"{most_common_vuln[0]} ({most_common_vuln[1]} instances)"
    else:
        most_common_text = "None"
        
    status_content = (
        "[bold white]YATA System Status[/bold white]\n\n"
        f"Repositories Known:     {repositories_known}\n"
        f"Total Assessments:      {total_assessments}\n"
        f"Successful Patches:     {successful_patches}\n"
        f"Failed Patches:         {failed_patches}\n"
        f"Most Common Weakness:   {most_common_text}"
    )
    
    console.print(Panel(status_content, border_style="cyan", expand=True))
    return 0
