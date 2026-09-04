from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from tui.state import ScopeType
from tui.widgets.footer import YataFooter
from tui.widgets.header import YataHeader


class ScopeSelectScreen(Screen):
    """Scope selection screen for tailoring assessment boundaries."""

    BINDINGS = [
        Binding("escape", "go_back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield YataHeader(id="scope-header")
        with Container(classes="main-container"):
            yield Static(id="scope-target-info", classes="panel-box")
            yield Static("[bold #00D2FF]SELECT SCOPE[/bold #00D2FF]\n[dim white]Define the operational boundary for this security mission[/dim white]\n", classes="panel-title")
            yield OptionList(
                Option("📁 Entire Repository", id="scope:entire"),
                Option("📂 Specific Directory", id="scope:directory"),
                Option("📄 Specific File", id="scope:file"),
                id="scope-options",
            )
            yield Static(id="scope-desc-box", classes="panel-box")
        yield YataFooter(id="scope-footer")

    def on_mount(self) -> None:
        target_name = self.app.mission_state.target_name or "Target"
        target_path = self.app.mission_state.target_path or Path(".")

        header = self.query_one("#scope-header", YataHeader)
        header.status = "READY"
        header.target_name = target_name
        header.breadcrumbs = f"Target › {target_name} › Scope Selection"

        footer = self.query_one("#scope-footer", YataFooter)
        footer.help_text = "↑↓ Select Scope   ENTER Confirm   ESC Back"

        info_box = self.query_one("#scope-target-info", Static)
        info_box.update(
            f"[dim white]SELECTED TARGET:[/]\n"
            f"[bold #00D2FF]{target_name}[/]\n"
            f"[white]{target_path}[/]"
        )

        self._update_description("scope:entire")
        self.query_one("#scope-options", OptionList).focus()

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option and event.option.id:
            self._update_description(event.option.id)

    def _update_description(self, option_id: str) -> None:
        desc_box = self.query_one("#scope-desc-box", Static)
        descriptions = {
            "scope:entire": (
                "[bold white]Entire Repository[/bold white]\n\n"
                "Assess all source code, routes, configurations, and assets within the target repository.\n"
                "Recommended for standard comprehensive security posture evaluations."
            ),
            "scope:directory": (
                "[bold white]Specific Directory[/bold white]\n\n"
                "Constrain HUNTER, HEALER, and VALIDATOR to a designated subdirectory.\n"
                "Useful for auditing specific microservices, modules, or API endpoints."
            ),
            "scope:file": (
                "[bold white]Specific File[/bold white]\n\n"
                "Target a single isolated file for rapid vulnerability hunting and remediation.\n"
                "Ideal for reviewing a single route handler or newly introduced script."
            ),
        }
        desc_box.update(descriptions.get(option_id, ""))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        opt_id = event.option.id
        if not opt_id:
            return

        if opt_id == "scope:entire":
            self.app.mission_state.scope_type = ScopeType.ENTIRE
            self.app.mission_state.scope_path = None
            from tui.screens.mode import ModeSelectScreen
            self.app.push_screen(ModeSelectScreen())
        elif opt_id == "scope:directory":
            self.app.mission_state.scope_type = ScopeType.DIRECTORY
            from tui.screens.browser import FileBrowserScreen
            self.app.push_screen(FileBrowserScreen(initial_path=self.app.mission_state.target_path, browse_mode="scope_dir"))
        elif opt_id == "scope:file":
            self.app.mission_state.scope_type = ScopeType.FILE
            from tui.screens.browser import FileBrowserScreen
            self.app.push_screen(FileBrowserScreen(initial_path=self.app.mission_state.target_path, browse_mode="scope_file"))

    def action_go_back(self) -> None:
        self.app.pop_screen()
