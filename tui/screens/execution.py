from __future__ import annotations

from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import RichLog, Static

from tui.engine import AssessmentEngine
from tui.state import MissionState, Stage
from tui.widgets.footer import YataFooter
from tui.widgets.header import YataHeader
from tui.widgets.status_bar import TelemetryBarWidget
from tui.widgets.workflow import WorkflowPipelineWidget


class ExecutionScreen(Screen):
    """Persistent live execution console updating in place during assessment."""

    BINDINGS = [
        Binding("p", "toggle_pause", "Pause/Resume"),
        Binding("q", "abort_mission", "Abort Mission"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.engine: AssessmentEngine | None = None
        self._is_handling_modal = False

    def compose(self) -> ComposeResult:
        yield YataHeader(id="exec-header")
        with Container(classes="main-container"):
            with Horizontal(classes="split-horizontal"):
                with Vertical(classes="col-left"):
                    yield WorkflowPipelineWidget(id="exec-workflow")
                with Vertical(classes="col-right"):
                    yield TelemetryBarWidget(id="exec-telemetry")
                    yield Static("[dim white]MISSION AUDIT LOG[/dim white]", classes="panel-subtitle")
                    yield RichLog(id="exec-log", highlight=True, markup=True)
        yield YataFooter(id="exec-footer")

    def on_mount(self) -> None:
        target_name = self.app.mission_state.target_name
        mode_str = self.app.mission_state.mode.value.upper()

        header = self.query_one("#exec-header", YataHeader)
        header.status = "RUNNING"
        header.target_name = target_name
        header.mode_name = mode_str
        header.breadcrumbs = f"Mission › {target_name} › Assessment Running"

        footer = self.query_one("#exec-footer", YataFooter)
        footer.help_text = "P Pause   Q Abort Mission"

        # Initialize engine and run worker
        self.engine = AssessmentEngine(
            state=self.app.mission_state,
            on_state_change=self._on_engine_update_from_thread,
            on_log=self._on_engine_log_from_thread,
        )
        self.app.current_engine = self.engine
        self.run_assessment_worker()

    def _on_engine_update_from_thread(self, state: MissionState) -> None:
        self.app.call_from_thread(self._sync_ui_state, state)

    def _on_engine_log_from_thread(self, message: str) -> None:
        self.app.call_from_thread(self._append_log, message)

    def _append_log(self, message: str) -> None:
        try:
            log_widget = self.query_one("#exec-log", RichLog)
            log_widget.write(f"[dim]{message}[/dim]")
        except Exception:
            pass

    def _sync_ui_state(self, state: MissionState) -> None:
        try:
            header = self.query_one("#exec-header", YataHeader)
            workflow = self.query_one("#exec-workflow", WorkflowPipelineWidget)
            telemetry = self.query_one("#exec-telemetry", TelemetryBarWidget)

            workflow.current_stage = state.current_stage.value
            telemetry.agent = state.current_agent
            telemetry.operation = state.current_operation
            telemetry.current_file = state.current_file
            telemetry.total_findings = len(state.findings)
            telemetry.critical_count = state.critical_count
            telemetry.high_count = state.high_count
            telemetry.medium_count = state.medium_count
            telemetry.score_before = state.initial_score
            telemetry.score_after = state.final_score

            header.breadcrumbs = f"Mission › {state.target_name} › {state.current_agent} › {state.current_stage.value}"

            if state.current_stage == Stage.HUMAN_REVIEW and not self._is_handling_modal:
                self._is_handling_modal = True
                header.status = "DECISION REQUIRED"
                from tui.screens.review import HumanReviewScreen
                self.app.push_screen(HumanReviewScreen())
            elif state.current_stage == Stage.FAILURE and not self._is_handling_modal:
                self._is_handling_modal = True
                header.status = "FAILED"
                workflow.validation_failed = True
                from tui.screens.failure import FailureScreen
                self.app.push_screen(FailureScreen())
            elif state.current_stage == Stage.COMPLETE and not self._is_handling_modal:
                self._is_handling_modal = True
                header.status = "COMPLETE"
                from tui.screens.complete import CompleteScreen
                self.app.push_screen(CompleteScreen())
            elif state.current_stage in (Stage.HEALER, Stage.VALIDATOR, Stage.MUTATOR):
                self._is_handling_modal = False
                header.status = "RUNNING"
        except Exception:
            pass

    @work(thread=True)
    def run_assessment_worker(self) -> None:
        if self.engine:
            self.engine.run_mission()

    def action_toggle_pause(self) -> None:
        self.app.mission_state.is_paused = not self.app.mission_state.is_paused
        header = self.query_one("#exec-header", YataHeader)
        header.status = "PAUSED" if self.app.mission_state.is_paused else "RUNNING"

    def action_abort_mission(self) -> None:
        self.app.mission_state.is_aborted = True
        if self.engine:
            # Unblock any pending queues
            try:
                self.engine.human_review_queue.put_nowait("ABORT")
            except Exception:
                pass
            try:
                self.engine.failure_decision_queue.put_nowait("ABORT")
            except Exception:
                pass
        self.notify("Mission aborted by user.", severity="warning")
