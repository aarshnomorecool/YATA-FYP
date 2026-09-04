from __future__ import annotations

from textual.app import ComposeResult
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static

from tui.state import Stage


class WorkflowPipelineWidget(Widget):
    """Visual pipeline indicator showing progress through security agents."""

    DEFAULT_CSS = """
    WorkflowPipelineWidget {
        width: 100%;
        height: auto;
        background: #111827;
        border: heavy #1E293B;
        padding: 1;
        margin-bottom: 1;
    }
    .pipeline-title {
        color: #94A3B8;
        text-style: bold;
        margin-bottom: 1;
    }
    .pipeline-stages {
        height: auto;
    }
    """

    current_stage: reactive[str] = reactive("IDLE")
    validation_failed: reactive[bool] = reactive(False)

    STAGES = [
        ("DISCOVERY", "01 DISCOVERY"),
        ("HUNTER", "02 HUNTER"),
        ("HUMAN_REVIEW", "03 HUMAN REVIEW"),
        ("HEALER", "04 HEALER"),
        ("VALIDATOR", "05 VALIDATOR"),
        ("SCHOLAR", "06 SCHOLAR"),
    ]

    STAGE_ORDER = ["DISCOVERY", "HUNTER", "HUMAN_REVIEW", "HEALER", "VALIDATOR", "MUTATOR", "SCHOLAR"]

    def compose(self) -> ComposeResult:
        yield Static("MISSION WORKFLOW PIPELINE", classes="pipeline-title")
        yield Static(id="pipeline-stages-content", classes="pipeline-stages")

    def on_mount(self) -> None:
        self.update_content()

    def watch_current_stage(self, new_val: str) -> None:
        self.update_content()

    def watch_validation_failed(self, new_val: bool) -> None:
        self.update_content()

    def update_content(self) -> None:
        content_widget = self.query_one("#pipeline-stages-content", Static)
        curr = self.current_stage.upper()

        curr_idx = -1
        if curr in self.STAGE_ORDER:
            curr_idx = self.STAGE_ORDER.index(curr)
        elif curr == "COMPLETE":
            curr_idx = 999
        elif curr == "FAILURE":
            curr_idx = self.STAGE_ORDER.index("VALIDATOR")

        lines = []
        for stage_key, label in self.STAGES:
            stage_idx = self.STAGE_ORDER.index(stage_key) if stage_key in self.STAGE_ORDER else -1

            if self.validation_failed and stage_key == "VALIDATOR":
                prefix = "[bold #FF3366]✗[/]"
                text = f"[bold #FF3366]{label}[/]"
            elif curr == "FAILURE" and stage_key == "VALIDATOR":
                prefix = "[bold #FF3366]✗[/]"
                text = f"[bold #FF3366]{label}[/]"
            elif stage_idx < curr_idx or curr == "COMPLETE":
                prefix = "[bold #00FF9D]✓[/]"
                text = f"[white]{label}[/]"
            elif stage_key == curr or (curr == "MUTATOR" and stage_key == "VALIDATOR"):
                prefix = "[bold #00D2FF]→[/]"
                text = f"[bold #00D2FF]{label}[/]"
            else:
                prefix = "[#475569]○[/]"
                text = f"[#64748B]{label}[/]"

            lines.append(f"  {prefix} {text}")

        content_widget.update("\n".join(lines))
