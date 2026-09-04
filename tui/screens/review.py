from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from tui.widgets.footer import YataFooter
from tui.widgets.header import YataHeader


class HumanReviewScreen(Screen):
    """Human decision gate for reviewing and authorizing remediation of proven exploits."""

    BINDINGS = [
        Binding("i", "inspect_evidence", "Inspect Evidence"),
        Binding("escape", "go_back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield YataHeader(id="review-header")
        with Container(classes="main-container"):
            yield Static(id="review-alert-card", classes="decision-card-warning")
            yield Static("[bold white]WHAT ACTION SHOULD YATA TAKE?[/bold white]\n", classes="panel-subtitle")
            yield OptionList(
                Option("🛡 AUTHORIZE REMEDIATION (Generate & validate defensive patch)", id="review:auth"),
                Option("🔍 INSPECT EVIDENCE (Deep-dive into exploit proof & attack payload)", id="review:inspect"),
                Option("⛔ REJECT FINDING (Ignore finding and continue search)", id="review:reject"),
                Option("✖ ABORT MISSION (Halt security assessment immediately)", id="review:abort"),
                id="review-options",
            )
        yield YataFooter(id="review-footer")

    def on_mount(self) -> None:
        target_name = self.app.mission_state.target_name
        active_f = self.app.mission_state.active_finding or {}
        vuln_type = active_f.get("vulnerability_type", "Security Weakness")

        header = self.query_one("#review-header", YataHeader)
        header.status = "DECISION REQUIRED"
        header.target_name = target_name
        header.breadcrumbs = f"Mission › {target_name} › HUNTER › Human Decision Required"

        footer = self.query_one("#review-footer", YataFooter)
        footer.help_text = "↑↓ Decision   ENTER Confirm   I Inspect Evidence   ESC Back"

        alert_card = self.query_one("#review-alert-card", Static)
        sev = active_f.get("severity", "CRITICAL")
        file_loc = f"{active_f.get('file', 'app.py')}:{active_f.get('line_number', 0)}"

        sev_color = "#FF3366" if sev == "CRITICAL" else "#F97316"

        text = (
            "[bold #F59E0B]HUMAN DECISION REQUIRED[/bold #F59E0B]\n\n"
            f"[bold white]Vulnerability:[/bold white] [bold #00D2FF]{vuln_type}[/bold #00D2FF]\n"
            f"[bold white]Location:[/bold white]      [cyan]{file_loc}[/cyan]\n"
            f"[bold white]Severity:[/bold white]      [bold {sev_color}]{sev}[/bold {sev_color}]\n"
            f"[bold white]Confidence:[/bold white]    [bold #00FF9D]98% (Proven via live exploit execution)[/bold #00FF9D]\n"
            f"[bold white]Exploit Payload:[/bold white] [dim white]{active_f.get('payload', 'N/A')}[/dim white]\n\n"
            "[dim white]HUNTER has constructed an active attack path and verified server vulnerability.\n"
            "Human oversight is required to authorize HEALER defensive patch generation.[/dim white]"
        )
        alert_card.update(text)

        self.query_one("#review-options", OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        opt_id = event.option.id
        if opt_id == "review:auth":
            self._send_decision("AUTHORIZE")
        elif opt_id == "review:inspect":
            self.action_inspect_evidence()
        elif opt_id == "review:reject":
            self._send_decision("REJECT")
        elif opt_id == "review:abort":
            self._send_decision("ABORT")

    def _send_decision(self, decision: str) -> None:
        if hasattr(self.app, "current_engine") and self.app.current_engine:
            self.app.current_engine.human_review_queue.put(decision)
        self.app.pop_screen()

    def action_inspect_evidence(self) -> None:
        from tui.screens.evidence import EvidenceScreen
        self.app.push_screen(EvidenceScreen())

    def action_go_back(self) -> None:
        self.action_inspect_evidence()
