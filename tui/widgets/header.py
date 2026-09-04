from __future__ import annotations

from textual.app import ComposeResult
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static


class YataHeader(Widget):
    """Persistent compact YATA header with status indicator and breadcrumb trail."""

    DEFAULT_CSS = """
    YataHeader {
        dock: top;
        height: 3;
        background: #0B0F14;
        color: #E2E8F0;
        border-bottom: heavy #1E293B;
        padding: 0 1;
    }
    .header-top {
        height: 1;
        width: 100%;
        layout: horizontal;
    }
    .header-logo {
        width: 32;
    }
    .header-center {
        width: 1fr;
        text-align: center;
    }
    .header-status {
        width: 28;
        text-align: right;
    }
    .breadcrumbs {
        height: 1;
        color: #64748B;
        text-style: italic;
    }
    """

    status: reactive[str] = reactive("READY")
    breadcrumbs: reactive[str] = reactive("Target › Select Repository")
    target_name: reactive[str] = reactive("")
    mode_name: reactive[str] = reactive("")

    def compose(self) -> ComposeResult:
        yield Static(id="header-top-line", classes="header-top")
        yield Static(id="breadcrumbs-line", classes="breadcrumbs")

    def on_mount(self) -> None:
        self.update_content()

    def watch_status(self, new_val: str) -> None:
        self.update_content()

    def watch_breadcrumbs(self, new_val: str) -> None:
        self.update_content()

    def watch_target_name(self, new_val: str) -> None:
        self.update_content()

    def watch_mode_name(self, new_val: str) -> None:
        self.update_content()

    def update_content(self) -> None:
        try:
            top_widget = self.query_one("#header-top-line", Static)
            crumb_widget = self.query_one("#breadcrumbs-line", Static)
        except Exception:
            return

        # Status badge formatting
        status_styles = {
            "READY": "[bold #00FF9D]● READY[/]",
            "RUNNING": "[bold #00D2FF]● RUNNING[/]",
            "DECISION REQUIRED": "[bold #FFB800]● DECISION REQUIRED[/]",
            "PAUSED": "[bold #F59E0B]● PAUSED[/]",
            "FAILED": "[bold #FF3366]● VALIDATION FAILED[/]",
            "COMPLETE": "[bold #00FF9D]● MISSION COMPLETE[/]",
        }
        status_badge = status_styles.get(self.status, f"[bold #94A3B8]● {self.status}[/]")

        center_parts = []
        if self.target_name:
            center_parts.append(f"[bold white]{self.target_name}[/]")
        if self.mode_name:
            center_parts.append(f"[bold #00D2FF][{self.mode_name.upper()}][/]")
        center_info = f"  {'  '.join(center_parts)}  " if center_parts else "    "

        top_line = (
            f"[bold #00D2FF]YATA[/] [white]Security Console[/]    "
            f"{center_info}    "
            f"{status_badge}  [dim white]v0.9[/]"
        )
        top_widget.update(top_line)

        crumb_widget.update(f"[bold #00D2FF]›[/] [white]{self.breadcrumbs}[/]")
