from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from llm_client import LLMClient
from tui.widgets.footer import YataFooter
from tui.widgets.header import YataHeader


class MissionPreviewScreen(Screen):
    """Mission confirmation and workflow preview before starting assessment."""

    BINDINGS = [
        Binding("c", "change_config", "Change Config"),
        Binding("escape", "go_back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield YataHeader(id="mission-header")
        with Container(classes="main-container"):
            yield Static("[bold #00D2FF]MISSION PREVIEW[/bold #00D2FF]\n[dim white]Verify configuration and authorization boundary before execution[/dim white]\n", classes="panel-title")
            with Horizontal(classes="split-horizontal"):
                with Vertical(classes="col-left"):
                    yield Static(id="mission-params-box", classes="panel-box")
                with Vertical(classes="col-right"):
                    yield Static(id="mission-workflow-box", classes="panel-box")
            yield OptionList(
                Option("🚀 START MISSION", id="mission:start"),
                Option("⚙  Change Configuration", id="mission:change"),
                Option("✖  Cancel", id="mission:cancel"),
                id="mission-action-list",
            )
        yield YataFooter(id="mission-footer")

    def on_mount(self) -> None:
        target_name = self.app.mission_state.target_name
        mode_str = self.app.mission_state.mode.value.upper()
        scope_str = self.app.mission_state.scope_type.value.capitalize()

        header = self.query_one("#mission-header", YataHeader)
        header.status = "READY"
        header.target_name = target_name
        header.mode_name = mode_str
        header.breadcrumbs = f"Target › {target_name} › Scope ({scope_str}) › Mode ({mode_str}) › Mission Preview"

        footer = self.query_one("#mission-footer", YataFooter)
        footer.help_text = "ENTER Start Mission   C Change Config   ESC Cancel"

        # Parameters box
        params_box = self.query_one("#mission-params-box", Static)
        scope_detail = "Entire Repository"
        if self.app.mission_state.scope_path:
            scope_detail = f"{self.app.mission_state.scope_type.value.capitalize()} ({self.app.mission_state.scope_path.name})"

        engine_mode = "Autonomous Fallback (Deterministic Offline)"
        if LLMClient.execution_mode not in ("autonomous_fallback", "demo"):
            engine_mode = "NVIDIA NIM (Assisted Reasoning)"

        failure_demo_flag = "\n[bold #FF3366]NOTE:[/] [yellow]Failure Simulation Mode Enabled[/yellow]" if self.app.mission_state.simulate_failure else ""

        params_text = (
            "[bold white]CONFIGURATION[/bold white]\n\n"
            f"[dim white]Target:[/dim white]\n  [bold #00D2FF]{target_name}[/bold #00D2FF]\n"
            f"  [dim]{self.app.mission_state.target_path}[/dim]\n\n"
            f"[dim white]Scope:[/dim white]\n  [bold white]{scope_detail}[/bold white]\n\n"
            f"[dim white]Mode:[/dim white]\n  [bold #00FF9D]{mode_str}[/bold #00FF9D]\n\n"
            f"[dim white]AI Engine:[/dim white]\n  [white]{engine_mode}[/white]\n\n"
            f"[dim white]Max Rounds:[/dim white]\n  [white]{self.app.mission_state.max_rounds}[/white]"
            f"{failure_demo_flag}"
        )
        params_box.update(params_text)

        # Workflow box
        workflow_box = self.query_one("#mission-workflow-box", Static)
        review_note = " (Mandatory Human Gate)" if mode_str == "INTERACTIVE" else " (Automated Approval)"
        apply_note = " (Patches Promoted Directly)" if mode_str == "APPLY" else " (Patched Copies Centralized in .yata)"

        workflow_text = (
            "[bold white]EXECUTION PIPELINE[/bold white]\n\n"
            "  [bold #00D2FF]01[/bold #00D2FF]  [white]Repository AST Discovery[/white]\n"
            "  [bold #00D2FF]02[/bold #00D2FF]  [white]HUNTER[/white]   [dim]Evaluate attack paths & prove exploitability[/dim]\n"
            f"  [bold #00D2FF]03[/bold #00D2FF]  [white]Human Review[/white] [dim]{review_note}[/dim]\n"
            "  [bold #00D2FF]04[/bold #00D2FF]  [white]HEALER[/white]   [dim]Generate minimal secure defensive patch[/dim]\n"
            "  [bold #00D2FF]05[/bold #00D2FF]  [white]VALIDATOR[/white][dim] Live re-exploitation against patched copy[/dim]\n"
            "  [bold #00D2FF]06[/bold #00D2FF]  [white]MUTATOR[/white]  [dim]Adversarial mutation bypass testing[/dim]\n"
            "  [bold #00D2FF]07[/bold #00D2FF]  [white]Recovery[/white] [dim]First-class failure handling & alternative patching[/dim]\n"
            f"  [bold #00D2FF]08[/bold #00D2FF]  [white]Promotion[/white][dim]{apply_note}[/dim]\n"
            "  [bold #00D2FF]09[/bold #00D2FF]  [white]SCHOLAR[/white]  [dim]Record persistent repository memory & metrics[/dim]\n"
            "  [bold #00D2FF]10[/bold #00D2FF]  [white]REPORTER[/white] [dim]Generate structured audit reports[/dim]"
        )
        workflow_box.update(workflow_text)

        self.query_one("#mission-action-list", OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        opt_id = event.option.id
        if opt_id == "mission:start":
            self.action_start_mission()
        elif opt_id == "mission:change":
            self.action_change_config()
        elif opt_id == "mission:cancel":
            self.action_go_back()

    def action_start_mission(self) -> None:
        from tui.screens.execution import ExecutionScreen
        self.app.push_screen(ExecutionScreen())

    def action_change_config(self) -> None:
        from tui.screens.scope import ScopeSelectScreen
        self.app.push_screen(ScopeSelectScreen())

    def action_go_back(self) -> None:
        self.app.pop_screen()
