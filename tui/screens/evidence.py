from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, Static

from tui.engine import VULNERABILITY_MAPPING
from tui.widgets.footer import YataFooter
from tui.widgets.header import YataHeader


class EvidenceScreen(Screen):
    """Deep-dive evidence and technical details screen for human inspection."""

    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("enter", "go_back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield YataHeader(id="evidence-header")
        with Container(classes="main-container"):
            yield Static("[bold #00D2FF]FINDING EVIDENCE & TECHNICAL DETAILS[/bold #00D2FF]\n", classes="panel-title")
            with ScrollableContainer(id="evidence-details-container", classes="panel-box"):
                yield Static(id="evidence-content-text")
            yield Button("← Return to Human Review (ESC)", id="btn-back", variant="primary")
        yield YataFooter(id="evidence-footer")

    def on_mount(self) -> None:
        target_name = self.app.mission_state.target_name
        active_f = self.app.mission_state.active_finding or {}
        vuln_type = active_f.get("vulnerability_type", "Vulnerability")

        header = self.query_one("#evidence-header", YataHeader)
        header.status = "DECISION REQUIRED"
        header.target_name = target_name
        header.breadcrumbs = f"Mission › {target_name} › Evidence › {vuln_type}"

        footer = self.query_one("#evidence-footer", YataFooter)
        footer.help_text = "ESC / ENTER Return to Decision"

        mapping = VULNERABILITY_MAPPING.get(vuln_type, {})
        owasp = mapping.get("owasp", "N/A")
        cwe = mapping.get("cwe", "N/A")
        impact = mapping.get("impact", "N/A")

        # Sanitize sensitive display if needed
        evidence_str = str(active_f.get("evidence", "No evidence payload recorded."))
        if vuln_type == "Hardcoded Secret":
            # Mask part of secret for safe display
            if len(evidence_str) > 8:
                evidence_str = evidence_str[:4] + "*" * (len(evidence_str) - 8) + evidence_str[-4:]

        remediation_strategies = {
            "SQL Injection": "Replace string concatenation/formatting with parameterized SQL statements (e.g. cursor.execute(query, (param,))).",
            "Hardcoded Secret": "Extract plaintext secret token to environment variable (e.g. os.environ.get(...)) and record in .env template.",
            "Command Injection": "Avoid shell=True in subprocess; use argument list array and sanitize inputs against strict allowlists.",
            "Path Traversal": "Validate relative paths using os.path.abspath, ensure target remains within intended base sandbox directory.",
        }
        proposed_rem = remediation_strategies.get(vuln_type, "Apply minimal contextual code patch to eliminate unsafe data flow.")

        content_widget = self.query_one("#evidence-content-text", Static)
        details_markup = (
            f"[bold white]Vulnerability:[/bold white]       [bold #00D2FF]{vuln_type}[/bold #00D2FF]\n"
            f"[bold white]File Location:[/bold white]       [cyan]{active_f.get('file', 'app.py')}:{active_f.get('line_number', 0)}[/cyan]\n"
            f"[bold white]Severity:[/bold white]            [bold #FF3366]{active_f.get('severity', 'CRITICAL')}[/bold #FF3366]\n"
            f"[bold white]OWASP Top 10:[/bold white]        [white]{owasp}[/white]\n"
            f"[bold white]CWE Identifier:[/bold white]      [white]{cwe}[/white]\n"
            f"[bold white]Potential Impact:[/bold white]    [yellow]{impact}[/yellow]\n\n"
            "[bold white]LIVE EXPLOITATION EVIDENCE:[/bold white]\n"
            f"  [dim white]{evidence_str}[/dim white]\n\n"
            "[bold white]PROVEN ATTACK PAYLOAD:[/bold white]\n"
            f"  [bold #00D2FF]{active_f.get('payload', 'N/A')}[/bold #00D2FF]\n\n"
            "[bold white]ATTACK VECTOR EXPLANATION:[/bold white]\n"
            f"  [white]{active_f.get('explanation', 'Constructed payload satisfied entry conditions and executed successfully.')}[/white]\n\n"
            "[bold white]PROPOSED REMEDIATION:[/bold white]\n"
            f"  [white]{proposed_rem}[/white]\n\n"
            "[bold white]ADVERSARIAL VALIDATION PLAN:[/bold white]\n"
            "  1. VALIDATOR will re-execute the confirmed winning payload against HEALER's sandbox.\n"
            "  2. MUTATOR will generate and execute mutated variations (URL encodings, alternate syntax).\n"
            "  3. Remediation is promoted only if 100% of attack variations are blocked."
        )
        content_widget.update(details_markup)

        self.query_one("#btn-back", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.action_go_back()

    def action_go_back(self) -> None:
        self.app.pop_screen()
