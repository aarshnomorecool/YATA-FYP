from __future__ import annotations

from textual.app import ComposeResult
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static


class TelemetryBarWidget(Widget):
    """Telemetry bar displaying current agent, active operation, and findings metrics."""

    DEFAULT_CSS = """
    TelemetryBarWidget {
        width: 100%;
        height: auto;
        background: #0F172A;
        border: heavy #1E293B;
        padding: 1;
        margin-bottom: 1;
    }
    .telemetry-title {
        color: #94A3B8;
        text-style: bold;
        margin-bottom: 1;
    }
    .telemetry-content {
        height: auto;
    }
    """

    agent: reactive[str] = reactive("SYSTEM")
    operation: reactive[str] = reactive("Ready")
    current_file: reactive[str] = reactive("")
    total_findings: reactive[int] = reactive(0)
    critical_count: reactive[int] = reactive(0)
    high_count: reactive[int] = reactive(0)
    medium_count: reactive[int] = reactive(0)
    score_before: reactive[int] = reactive(100)
    score_after: reactive[int] = reactive(100)

    def compose(self) -> ComposeResult:
        yield Static("CURRENT OPERATION & TELEMETRY", classes="telemetry-title")
        yield Static(id="telemetry-content-box", classes="telemetry-content")

    def on_mount(self) -> None:
        self.update_content()

    def watch_agent(self, new_val: str) -> None:
        self.update_content()

    def watch_operation(self, new_val: str) -> None:
        self.update_content()

    def watch_current_file(self, new_val: str) -> None:
        self.update_content()

    def watch_total_findings(self, new_val: int) -> None:
        self.update_content()

    def watch_critical_count(self, new_val: int) -> None:
        self.update_content()

    def watch_high_count(self, new_val: int) -> None:
        self.update_content()

    def watch_score_after(self, new_val: int) -> None:
        self.update_content()

    def update_content(self) -> None:
        content_widget = self.query_one("#telemetry-content-box", Static)

        agent_colors = {
            "HUNTER": "bold #FF3366",
            "HEALER": "bold #3B82F6",
            "VALIDATOR": "bold #00D2FF",
            "MUTATOR": "bold #A855F7",
            "SCHOLAR": "bold #EAB308",
            "SYSTEM": "bold #94A3B8",
        }
        agent_color = agent_colors.get(self.agent, "bold white")

        file_line = f"\n  [dim white]Target File:[/] [cyan]{self.current_file}[/]" if self.current_file else ""

        findings_badge = (
            f"  [white]Findings:[/] [bold]{self.total_findings}[/]  "
            f"([bold #FF3366]CRIT: {self.critical_count}[/]  "
            f"[bold #F97316]HIGH: {self.high_count}[/]  "
            f"[bold #FBBF24]MED: {self.medium_count}[/])"
        )

        score_line = f"  [white]Security Score:[/] [bold cyan]{self.score_before}[/] → [bold green]{self.score_after}[/]"

        text = (
            f"  [{agent_color}]{self.agent}[/]  [white]{self.operation}[/]"
            f"{file_line}\n\n"
            f"{findings_badge}\n"
            f"{score_line}"
        )
        content_widget.update(text)
