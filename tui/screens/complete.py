from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from tui.widgets.footer import YataFooter
from tui.widgets.header import YataHeader


def make_score_bar(score: int) -> str:
    filled = max(0, min(10, int(round(score / 10.0))))
    return "█" * filled + "░" * (10 - filled)


class CompleteScreen(Screen):
    """Mission completion summary showing validated score evolution and artifacts."""

    BINDINGS = [
        Binding("r", "return_target", "Return to Target"),
        Binding("q", "exit_console", "Exit"),
    ]

    def compose(self) -> ComposeResult:
        yield YataHeader(id="complete-header")
        with Container(classes="main-container"):
            yield Static(id="complete-summary-box", classes="panel-box")
            yield Static("[bold white]NEXT ACTIONS[/bold white]\n", classes="panel-subtitle")
            yield OptionList(
                Option("📄 VIEW AUDIT REPORT (Open generated report summary)", id="action:report"),
                Option("🔍 VIEW FINDINGS (Examine healed and remaining weaknesses)", id="action:findings"),
                Option("🔄 RETURN TO TARGET SELECTOR (Assess another repository)", id="action:return"),
                Option("✖ EXIT YATA CONSOLE", id="action:exit"),
                id="complete-options",
            )
            yield Static(id="report-display-box", classes="panel-box hidden")
        yield YataFooter(id="complete-footer")

    def on_mount(self) -> None:
        state = self.app.mission_state
        target_name = state.target_name
        is_passed = state.verification_outcome == "Passed"

        header = self.query_one("#complete-header", YataHeader)
        header.status = "COMPLETE" if is_passed else "FAILED"
        header.target_name = target_name
        header.breadcrumbs = f"Mission › {target_name} › Assessment Complete"

        footer = self.query_one("#complete-footer", YataFooter)
        footer.help_text = "ENTER Select Action   R Return to Target   Q Exit"

        summary_box = self.query_one("#complete-summary-box", Static)

        outcome_color = "#00FF9D" if is_passed else "#FF3366"
        outcome_label = "PASSED (All weak points verified & healed)" if is_passed else "FAILED / UNRESOLVED"

        score_diff = state.final_score - state.initial_score
        diff_str = f"+{score_diff}" if score_diff >= 0 else str(score_diff)

        reports_list = ", ".join(state.reports.keys()) if state.reports else "Saved in .yata/reports/"

        mem_assessments = state.memory_info.get("total_assessments", 1)

        text = (
            f"[bold {outcome_color}]MISSION COMPLETE — VALIDATION {outcome_label}[/bold {outcome_color}]\n\n"
            f"[bold white]Target Repository:[/bold white]       [bold #00D2FF]{target_name}[/bold #00D2FF]\n"
            f"[bold white]Execution Mode:[/bold white]          [white]{state.mode.value.upper()}[/white]\n"
            f"[bold white]Vulnerabilities Healed:[/bold white]  [bold #00FF9D]{state.healed_count} / {len(state.findings)}[/bold #00FF9D]\n"
            f"[bold white]Validation Status:[/bold white]       [bold {outcome_color}]{state.verification_outcome.upper()}[/bold {outcome_color}]\n\n"
            "[bold white]SECURITY SCORE EVOLUTION:[/bold white]\n"
            f"  Before Assessment:  [dim cyan]{make_score_bar(state.initial_score)}[/dim cyan] [bold]{state.initial_score:>3}[/bold] / 100\n"
            f"  After Validation:   [bold #00FF9D]{make_score_bar(state.final_score)}[/bold #00FF9D] [bold]{state.final_score:>3}[/bold] / 100  ([bold green]{diff_str}[/bold green])\n\n"
            "[bold white]REPOSITORY MEMORY (SCHOLAR):[/bold white]\n"
            f"  Updated persistent profile: [cyan].yata/memory/{target_name}/memory.json[/cyan]\n"
            f"  Total Lifetime Assessments: [white]{mem_assessments}[/white]\n\n"
            "[bold white]GENERATED AUDIT ARTIFACTS:[/bold white]\n"
            f"  Format(s): [white]{reports_list}[/white]\n"
            f"  Directory: [dim].yata/reports/{target_name}/[/dim]"
        )
        summary_box.update(text)

        self.query_one("#complete-options", OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        opt_id = event.option.id
        if opt_id == "action:report":
            self._toggle_report_view()
        elif opt_id == "action:findings":
            self._toggle_findings_view()
        elif opt_id == "action:return":
            self.action_return_target()
        elif opt_id == "action:exit":
            self.action_exit_console()

    def _toggle_report_view(self) -> None:
        disp = self.query_one("#report-display-box", Static)
        if not disp.has_class("hidden"):
            disp.add_class("hidden")
            return

        state = self.app.mission_state
        rep_path = state.reports.get("markdown") or state.reports.get("json")
        content = "No report file available on disk."
        if rep_path and Path(rep_path).exists():
            try:
                content = Path(rep_path).read_text(encoding="utf-8", errors="replace")
                if len(content) > 1500:
                    content = content[:1500] + "\n\n... [Report truncated for display. Full report saved to .yata/reports/]"
            except Exception as e:
                content = f"Error reading report: {e}"

        disp.update(f"[bold #00D2FF]REPORT PREVIEW[/bold #00D2FF]\n\n[dim white]{content}[/dim white]")
        disp.remove_class("hidden")

    def _toggle_findings_view(self) -> None:
        disp = self.query_one("#report-display-box", Static)
        if not disp.has_class("hidden"):
            disp.add_class("hidden")
            return

        lines = ["[bold #00D2FF]ASSESSMENT FINDINGS SUMMARY[/bold #00D2FF]\n"]
        for idx, f in enumerate(self.app.mission_state.findings, 1):
            status = "[bold green]HEALED ✓[/bold green]" if f.get("status") == "healed" else "[bold red]ACTIVE ✗[/bold red]"
            lines.append(
                f"  {idx}. [bold]{f.get('vulnerability_type')}[/bold] at [cyan]{f.get('file')}:{f.get('line_number')}[/cyan] "
                f"([bold red]{f.get('severity')}[/bold red]) -> {status}"
            )

        disp.update("\n".join(lines))
        disp.remove_class("hidden")

    def action_return_target(self) -> None:
        from tui.screens.target import TargetSelectScreen
        # Pop back to fresh target select screen
        self.app.pop_screen()  # pop complete
        self.app.pop_screen()  # pop execution
        # Navigate to target
        self.app.push_screen(TargetSelectScreen())

    def action_exit_console(self) -> None:
        self.app.exit(0)
