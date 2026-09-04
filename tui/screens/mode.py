from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from tui.state import ExecutionMode
from tui.widgets.footer import YataFooter
from tui.widgets.header import YataHeader


class ModeSelectScreen(Screen):
    """Execution mode selection screen (SAFE / INTERACTIVE / APPLY)."""

    BINDINGS = [
        Binding("escape", "go_back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield YataHeader(id="mode-header")
        with Container(classes="main-container"):
            yield Static("[bold #00D2FF]EXECUTION MODE[/bold #00D2FF]\n[dim white]Choose the autonomous authorization model for this assessment[/dim white]\n", classes="panel-title")
            yield OptionList(
                Option("🛡 SAFE", id="mode:safe"),
                Option("🤝 INTERACTIVE", id="mode:interactive"),
                Option("⚡ APPLY", id="mode:apply"),
                id="mode-options",
            )
            yield Static(id="mode-desc-box", classes="panel-box")
        yield YataFooter(id="mode-footer")

    def on_mount(self) -> None:
        target_name = self.app.mission_state.target_name or "Target"
        scope_name = self.app.mission_state.scope_type.value.capitalize()

        header = self.query_one("#mode-header", YataHeader)
        header.status = "READY"
        header.target_name = target_name
        header.breadcrumbs = f"Target › {target_name} › Scope ({scope_name}) › Mode Selection"

        footer = self.query_one("#mode-footer", YataFooter)
        footer.help_text = "↑↓ Select Mode   ENTER Confirm   ESC Back"

        self._update_description("mode:safe")
        self.query_one("#mode-options", OptionList).focus()

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option and event.option.id:
            self._update_description(event.option.id)

    def _update_description(self, option_id: str) -> None:
        desc_box = self.query_one("#mode-desc-box", Static)
        descriptions = {
            "mode:safe": (
                "[bold #00D2FF]SAFE MODE (Recommended)[/bold #00D2FF]\n\n"
                "Analyze the target without modifying files.\n\n"
                "YATA creates isolated sandboxed copies for attack execution, patch generation, and validation.\n"
                "Verified patches are recorded under .yata/patches/ while leaving original source files 100% untouched."
            ),
            "mode:interactive": (
                "[bold #FFB800]INTERACTIVE MODE (Guided Autonomous)[/bold #FFB800]\n\n"
                "Guided autonomous assessment with human decision gates.\n\n"
                "YATA discovers and analyzes weaknesses, proves exploitability, and pauses at critical workflow points "
                "to allow human inspection of evidence and explicit authorization before remediation is generated."
            ),
            "mode:apply": (
                "[bold #00FF9D]APPLY MODE (Autonomous Remediation)[/bold #00FF9D]\n\n"
                "Autonomous remediation mode.\n\n"
                "YATA directly modifies the target repository after patches survive live adversarial validation and mutator attacks.\n"
                "Ideal for autonomous CI/CD security pipelines and trusted repositories."
            ),
        }
        desc_box.update(descriptions.get(option_id, ""))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        opt_id = event.option.id
        if not opt_id:
            return

        if opt_id == "mode:safe":
            self.app.mission_state.mode = ExecutionMode.SAFE
        elif opt_id == "mode:interactive":
            self.app.mission_state.mode = ExecutionMode.INTERACTIVE
        elif opt_id == "mode:apply":
            self.app.mission_state.mode = ExecutionMode.APPLY

        from tui.screens.mission import MissionPreviewScreen
        self.app.push_screen(MissionPreviewScreen())

    def action_go_back(self) -> None:
        self.app.pop_screen()
