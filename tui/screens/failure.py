from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from tui.widgets.footer import YataFooter
from tui.widgets.header import YataHeader


class FailureScreen(Screen):
    """First-class exception and failure workflow state when validation fails."""

    BINDINGS = [
        Binding("i", "inspect_failure", "Inspect Failure"),
        Binding("escape", "abort_action", "Abort"),
    ]

    def compose(self) -> ComposeResult:
        yield YataHeader(id="failure-header")
        with Container(classes="main-container"):
            yield Static(id="failure-alert-box", classes="decision-card")
            yield Static("[bold white]WHAT SHOULD HAPPEN NEXT?[/bold white]\n", classes="panel-subtitle")
            yield OptionList(
                Option("🔍 INSPECT FAILURE (View technical exploit response & bypass proof)", id="fail:inspect"),
                Option("🔄 RETRY REMEDIATION (Instruct HEALER to generate alternative patch)", id="fail:retry"),
                Option("⚡ RUN MUTATION (Evaluate additional mutated attack variations)", id="fail:mutate"),
                Option("✖ ABORT (Do not promote patch; mark vulnerability unresolved)", id="fail:abort"),
                id="failure-options",
            )
        yield YataFooter(id="failure-footer")

    def on_mount(self) -> None:
        target_name = self.app.mission_state.target_name
        fail_info = self.app.mission_state.failure_info or {}
        vuln_type = fail_info.get("vulnerability_type", "Security Weakness")

        header = self.query_one("#failure-header", YataHeader)
        header.status = "FAILED"
        header.target_name = target_name
        header.breadcrumbs = f"Mission › {target_name} › VALIDATOR › Adversarial Validation Failed"

        footer = self.query_one("#failure-footer", YataFooter)
        footer.help_text = "↑↓ Select Action   ENTER Confirm   I Inspect Failure   ESC Abort"

        alert_box = self.query_one("#failure-alert-box", Static)
        text = (
            "[bold #FF3366]VALIDATION FAILED[/bold #FF3366]\n\n"
            "[bold white]The remediation did not survive adversarial validation.[/bold white]\n"
            "[bold #FF3366]YATA will NOT mark this vulnerability as resolved.[/bold #FF3366]\n\n"
            f"[dim white]Vulnerability:[/] [bold #00D2FF]{vuln_type}[/bold #00D2FF]\n"
            f"[dim white]Target Location:[/] [cyan]{fail_info.get('file', 'app.py')}:{fail_info.get('line_number', 0)}[/cyan]\n"
            f"[dim white]Bypass Proof:[/]    [white]{fail_info.get('evidence', 'Exploit succeeded against patched sandbox.')}[/white]\n\n"
            "[dim]A patch is never accepted merely because it looks correct.\n"
            "Live attacks proved that this remediation remains vulnerable.[/dim]"
        )
        alert_box.update(text)

        self.query_one("#failure-options", OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        opt_id = event.option.id
        if opt_id == "fail:inspect":
            self.action_inspect_failure()
        elif opt_id == "fail:retry":
            self._send_decision("RETRY")
        elif opt_id == "fail:mutate":
            self._send_decision("RUN_MUTATION")
        elif opt_id == "fail:abort":
            self.action_abort_action()

    def _send_decision(self, decision: str) -> None:
        if hasattr(self.app, "current_engine") and self.app.current_engine:
            self.app.current_engine.failure_decision_queue.put(decision)
        self.app.pop_screen()

    def action_inspect_failure(self) -> None:
        from tui.screens.evidence import EvidenceScreen
        self.app.push_screen(EvidenceScreen())

    def action_abort_action(self) -> None:
        self._send_decision("ABORT")
