from __future__ import annotations
from pathlib import Path
from rich.console import Console

def run(args) -> int:
    repo_name = args.target
    console = Console()
    
    project_root = Path(__file__).resolve().parent.parent
    reports_dir = project_root / ".yata" / "reports" / repo_name
    
    if not reports_dir.exists():
        console.print(f"[red]Error: No reports found for repository: {repo_name}[/red]")
        return 1
        
    files = [f for f in reports_dir.glob("*") if f.is_file()]
    if not files:
        console.print(f"[red]Error: No reports found in directory: {reports_dir}[/red]")
        return 1
        
    html_files = [f for f in files if f.suffix.lower() == ".html"]
    
    if html_files:
        newest_report = max(html_files, key=lambda f: f.stat().st_mtime)
    else:
        newest_report = max(files, key=lambda f: f.stat().st_mtime)
        
    try:
        rel_path = newest_report.relative_to(project_root)
        clean_path = str(rel_path).replace("\\", "/")
    except ValueError:
        clean_path = str(newest_report).replace("\\", "/")
        
    console.print("[bold white]Latest Report[/bold white]\n")
    console.print(clean_path)
    return 0
