from __future__ import annotations

from pathlib import Path

from textual.app import App
from textual.binding import Binding

from tui.engine import AssessmentEngine
from tui.screens.target import TargetSelectScreen
from tui.state import ExecutionMode, MissionState


class YataTuiApp(App[int]):
    """YATA Security Mission Console Textual Application."""

    CSS_PATH = "theme.tcss"
    TITLE = "YATA — Yet Another Threat Antagonist"
    SUB_TITLE = "Autonomous Cyber Defense & Patching Console"

    BINDINGS = [
        Binding("ctrl+c", "quit_app", "Quit", show=False),
    ]

    def __init__(self, initial_target: Path | None = None, initial_mode: str | None = None) -> None:
        super().__init__()
        self.mission_state = MissionState()
        self.current_engine: AssessmentEngine | None = None
        self._initial_target = initial_target
        self._initial_mode = initial_mode

    def on_mount(self) -> None:
        if self._initial_target and self._initial_target.exists():
            self.mission_state.reset_for_target(self._initial_target)
            if self._initial_mode:
                try:
                    self.mission_state.mode = ExecutionMode(self._initial_mode.lower())
                except ValueError:
                    pass
            from tui.screens.scope import ScopeSelectScreen
            self.push_screen(ScopeSelectScreen())
        else:
            self.push_screen(TargetSelectScreen())

    def action_quit_app(self) -> None:
        if self.current_engine:
            self.mission_state.is_aborted = True
        self.exit(0)


def run_tui(initial_target: Path | None = None, initial_mode: str | None = None) -> int:
    """Launch the interactive YATA TUI console."""
    app = YataTuiApp(initial_target=initial_target, initial_mode=initial_mode)
    return app.run() or 0
