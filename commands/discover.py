from __future__ import annotations
import os
from pathlib import Path
from rich.console import Console

def run(args) -> int:
    target_path = Path(args.target).resolve()
    if not target_path.exists():
        print(f"Error: Path does not exist: {target_path}")
        return 1

    console = Console()
    found_repos = []
    
    indicators = {".git", "app.py", "requirements.txt", "package.json", "yata_profile.json"}
    ignored_dirs = {".git", ".venv", "venv", ".yata", "node_modules", "__pycache__"}
    
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        path_root = Path(root)
        
        has_indicator = False
        for ind in indicators:
            if (path_root / ind).exists():
                has_indicator = True
                break
                
        if has_indicator:
            # We found a repository root. We do not walk into subfolders of this repository
            dirs.clear()
            found_repos.append(path_root)
            
    if not found_repos:
        console.print("[bold yellow]No repositories found.[/bold yellow]")
        return 0
        
    console.print("[bold white]Found Repositories[/bold white]\n")
    found_repos.sort(key=lambda p: p.name)
    for repo in found_repos:
        console.print(repo.name)
        
    return 0
