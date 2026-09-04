from __future__ import annotations

from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Input, OptionList, Static
from textual.widgets.option_list import Option

from tui.widgets.footer import YataFooter
from tui.widgets.header import YataHeader


def detect_repo_metadata(path: Path) -> tuple[str, int]:
    """Detect primary framework and file count for a directory."""
    if not path.is_dir():
        return "Unknown", 0

    framework = "Python"
    file_count = 0

    try:
        for p in path.rglob("*"):
            if p.is_file():
                if any(ignored in p.parts for ignored in (".git", ".venv", "__pycache__", ".yata")):
                    continue
                file_count += 1
                if file_count > 300:
                    break

        app_py = path / "app.py"
        req_txt = path / "requirements.txt"
        if app_py.exists():
            try:
                content = app_py.read_text(encoding="utf-8", errors="ignore")
                if "Flask" in content or "flask" in content:
                    framework = "Flask"
                elif "FastAPI" in content or "fastapi" in content:
                    framework = "FastAPI"
                elif "django" in content:
                    framework = "Django"
            except Exception:
                pass
        elif req_txt.exists():
            try:
                content = req_txt.read_text(encoding="utf-8", errors="ignore")
                if "flask" in content.lower():
                    framework = "Flask"
                elif "fastapi" in content.lower():
                    framework = "FastAPI"
                elif "django" in content.lower():
                    framework = "Django"
            except Exception:
                pass
    except Exception:
        pass

    return framework, file_count


YATA_ORANGE_BANNER = """[bold #FF8800]
██╗   ██╗ █████╗ ████████╗ █████╗ 
╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔══██╗
 ╚████╔╝ ███████║   ██║   ███████║
  ╚██╔╝  ██╔══██║   ██║   ██╔══██║
   ██║   ██║  ██║   ██║   ██║  ██║
   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝[/bold #FF8800]
[bold white]Yet Another Threat Antagonist[/bold white]
[dim #94A3B8]Autonomous Cyber Defense & Remediation Console[/dim #94A3B8]
"""


class TargetSelectScreen(Screen):
    """Initial target repository selection screen."""

    BINDINGS = [
        Binding("b", "browse", "Browse Filesystem"),
        Binding("/", "search", "Search Repos"),
        Binding("m", "manual_path", "Enter Path"),
        Binding("q", "quit_app", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.repos: list[dict[str, Any]] = []
        self._all_options: list[tuple[str, str, Path | None]] = []

    def compose(self) -> ComposeResult:
        yield YataHeader(id="target-header")
        with Container(classes="main-container"):
            yield Static(YATA_ORANGE_BANNER, id="target-logo-banner", classes="banner-box")
            yield Static("[bold #00D2FF]SELECT TARGET[/bold #00D2FF]  [dim white]Choose a target repository for autonomous security assessment & validation[/dim white]\n", classes="panel-title")
            yield Input(placeholder="Search repositories... (Press ESC to cancel search)", id="search-input", classes="hidden")
            yield OptionList(id="repo-list")
        yield YataFooter(id="target-footer")

    def on_mount(self) -> None:
        header = self.query_one("#target-header", YataHeader)
        header.status = "READY"
        header.breadcrumbs = "Target › Select Repository"

        footer = self.query_one("#target-footer", YataFooter)
        footer.help_text = "↑↓ Navigate   ENTER Select   / Search   B Browse   M Manual Path   Q Quit"

        self._discover_recent_repositories()
        self._populate_list()
        self.query_one("#repo-list", OptionList).focus()

    def _discover_recent_repositories(self) -> None:
        self.repos = []
        seen_paths = set()

        root = Path(__file__).resolve().parent.parent.parent

        # 1. From .yata/memory/
        mem_dir = root / ".yata" / "memory"
        if mem_dir.exists():
            for child in sorted(mem_dir.iterdir()):
                if child.is_dir():
                    candidate = root / "test_repositories" / child.name
                    if candidate.exists() and candidate.resolve() not in seen_paths:
                        fw, count = detect_repo_metadata(candidate)
                        self.repos.append({"name": child.name, "path": candidate, "framework": fw, "count": count, "source": "memory"})
                        seen_paths.add(candidate.resolve())

        # 2. From test_repositories/
        test_dir = root / "test_repositories"
        if test_dir.exists():
            for child in sorted(test_dir.iterdir()):
                if child.is_dir() and child.resolve() not in seen_paths:
                    fw, count = detect_repo_metadata(child)
                    self.repos.append({"name": child.name, "path": child, "framework": fw, "count": count, "source": "test_repos"})
                    seen_paths.add(child.resolve())

    def _populate_list(self, filter_query: str = "") -> None:
        option_list = self.query_one("#repo-list", OptionList)
        option_list.clear_options()

        self._all_options = []

        # Filter repositories
        for repo in self.repos:
            if filter_query and filter_query.lower() not in repo["name"].lower():
                continue
            display = f"📁 {repo['name']:<24} {repo['framework']:<12} {repo['count']} files"
            opt_id = f"repo:{repo['path']}"
            option_list.add_option(Option(prompt=display, id=opt_id))
            self._all_options.append((opt_id, display, repo["path"]))

        option_list.add_option(Option("────────────────────────────────────────────────────────────", disabled=True))

        # Action options
        action_items = [
            ("action:browse", "+ 📁 Browse Filesystem"),
            ("action:search", "+ 🔍 Search Repositories"),
            ("action:manual", "+ ⌨ Enter Path Manually"),
            ("action:failure_demo", "+ 🧪 Run Failure Scenario (Validation Fail Exception Demo)"),
        ]

        for act_id, act_label in action_items:
            option_list.add_option(Option(prompt=act_label, id=act_id))
            self._all_options.append((act_id, act_label, None))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        opt_id = event.option.id
        if not opt_id:
            return

        if opt_id == "action:browse":
            self.action_browse()
        elif opt_id == "action:search":
            self.action_search()
        elif opt_id == "action:manual":
            self.action_manual_path()
        elif opt_id == "action:failure_demo":
            self._launch_failure_demo()
        elif opt_id.startswith("repo:"):
            path_str = opt_id.split("repo:", 1)[1]
            self._select_repo(Path(path_str))

    def _select_repo(self, repo_path: Path) -> None:
        self.app.mission_state.reset_for_target(repo_path)
        from tui.screens.scope import ScopeSelectScreen
        self.app.push_screen(ScopeSelectScreen())

    def _launch_failure_demo(self) -> None:
        root = Path(__file__).resolve().parent.parent.parent
        demo_path = root / "test_repositories" / "repo1_login_sqli"
        self.app.mission_state.reset_for_target(demo_path)
        self.app.mission_state.simulate_failure = True
        from tui.screens.scope import ScopeSelectScreen
        self.app.push_screen(ScopeSelectScreen())

    def action_browse(self) -> None:
        from tui.screens.browser import FileBrowserScreen
        self.app.push_screen(FileBrowserScreen())

    def action_search(self) -> None:
        search_input = self.query_one("#search-input", Input)
        search_input.remove_class("hidden")
        search_input.focus()

    def action_manual_path(self) -> None:
        search_input = self.query_one("#search-input", Input)
        search_input.placeholder = "Enter absolute or relative repository path..."
        search_input.remove_class("hidden")
        search_input.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.placeholder.startswith("Search"):
            self._populate_list(filter_query=event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        val = event.value.strip()
        if not val:
            return

        if event.input.placeholder.startswith("Enter"):
            target_path = Path(val).resolve()
            if target_path.exists() and target_path.is_dir():
                self._select_repo(target_path)
            else:
                self.notify(f"Invalid directory path: {val}", severity="error")
        else:
            # Search selection: pick first matching
            if self._all_options and self._all_options[0][2]:
                self._select_repo(self._all_options[0][2])

    def action_quit_app(self) -> None:
        self.app.exit(0)
