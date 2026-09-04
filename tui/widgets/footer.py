from __future__ import annotations

from textual.app import ComposeResult
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static


class YataFooter(Widget):
    """Context-sensitive persistent footer showing keyboard controls."""

    DEFAULT_CSS = """
    YataFooter {
        dock: bottom;
        height: 1;
        background: #0B0F14;
        color: #94A3B8;
        border-top: solid #1E293B;
        padding: 0 1;
    }
    """

    help_text: reactive[str] = reactive("↑↓ Navigate   ENTER Select   / Search   B Browse   Q Quit")

    def compose(self) -> ComposeResult:
        yield Static(id="footer-controls")

    def on_mount(self) -> None:
        self.update_content()

    def watch_help_text(self, new_val: str) -> None:
        self.update_content()

    def update_content(self) -> None:
        widget = self.query_one("#footer-controls", Static)
        # Format key combinations with high contrast color
        parts = self.help_text.split("   ")
        formatted_parts = []
        for part in parts:
            tokens = part.strip().split(" ", 1)
            if len(tokens) == 2:
                key, label = tokens
                formatted_parts.append(f"[bold #00D2FF]{key}[/] [white]{label}[/]")
            elif tokens and tokens[0]:
                formatted_parts.append(f"[bold #00D2FF]{tokens[0]}[/]")
        widget.update("    ".join(formatted_parts))
