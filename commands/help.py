from __future__ import annotations
from rich.console import Console

def run(args) -> int:
    console = Console()
    help_text = (
        "[bold white]Usage[/bold white]\n\n"
        "yata assess <repository>\n\n"
        "yata discover <path>\n\n"
        "yata memory <repository>\n\n"
        "yata history <repository>\n\n"
        "yata report <repository>\n\n"
        "yata status\n\n"
        "yata version\n\n"
        "yata help"
    )
    console.print(help_text)
    return 0
