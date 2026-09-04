from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Input, OptionList, Static
from textual.widgets.option_list import Option

from tui.widgets.footer import YataFooter
from tui.widgets.header import YataHeader


def looks_like_project(path: Path) -> bool:
    """Check if directory contains project or repository markers."""
    signals = (
        ".git",
        "app.py",
        "yata_profile.json",
        "pyproject.toml",
        "requirements.txt",
        "package.json",
        "Cargo.toml",
        "go.mod",
        "pom.xml",
    )
    try:
        return any((path / s).exists() for s in signals)
    except Exception:
        return False


def format_file_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


class FileBrowserScreen(Screen):
    """Real filesystem browser with keyboard-first navigation and robust error handling."""

    BINDINGS = [
        Binding("left", "go_parent", "Parent Dir"),
        Binding("backspace", "go_parent", "Parent Dir"),
        Binding("right", "select_highlighted", "Select"),
        Binding("s", "select_current", "Select Folder"),
        Binding("space", "select_current", "Select Folder"),
        Binding("/", "toggle_filter", "Filter / Search"),
        Binding("escape", "go_back", "Back"),
    ]

    def __init__(self, initial_path: Path | None = None, browse_mode: str = "target") -> None:
        super().__init__()
        self.browse_mode = browse_mode  # "target", "scope_dir", "scope_file"
        self.current_dir = (initial_path or Path.cwd()).resolve()
        self._entries: list[tuple[str, Path, bool]] = []  # (id, path, is_dir)

    def compose(self) -> ComposeResult:
        yield YataHeader(id="browser-header")
        with Container(classes="main-container"):
            yield Static(id="current-path-label", classes="panel-title")
            yield Input(placeholder="Type to filter directory contents... (Press ESC to cancel filter)", id="browser-filter-input", classes="hidden")
            yield OptionList(id="browser-list")
        yield YataFooter(id="browser-footer")

    def on_mount(self) -> None:
        header = self.query_one("#browser-header", YataHeader)
        header.status = "READY"
        header.breadcrumbs = f"Target › Browse Filesystem › {self.current_dir.name}"

        footer = self.query_one("#browser-footer", YataFooter)
        footer.help_text = "↑↓ Navigate   ENTER Open   →/S Select   ←/BACKSPACE Parent   ESC Back   / Filter"

        self._refresh_listing()
        self.query_one("#browser-list", OptionList).focus()

    def _refresh_listing(self, filter_query: str = "") -> None:
        if not self.is_mounted:
            return

        path_label = self.query_one("#current-path-label", Static)
        path_label.update(f"[bold #00D2FF]LOCATION:[/] [white]{self.current_dir}[/]\n")

        option_list = self.query_one("#browser-list", OptionList)
        option_list.clear_options()
        self._entries = []

        # Check if parent exists
        parent = self.current_dir.parent
        if parent != self.current_dir:
            option_list.add_option(Option(prompt="📁 .. (Parent Directory)", id="entry:parent"))
            self._entries.append(("entry:parent", parent, True))

        # Direct selection option for current directory
        if self.browse_mode in ("target", "scope_dir"):
            option_list.add_option(Option(prompt=f"[bold #00FF9D]✓ [SELECT THIS DIRECTORY][/]  {self.current_dir.name}", id="entry:select_current"))
            self._entries.append(("entry:select_current", self.current_dir, True))

        option_list.add_option(Option("────────────────────────────────────────────────────────────", disabled=True))

        # List directory entries
        dirs: list[Path] = []
        files: list[Path] = []

        try:
            for item in sorted(self.current_dir.iterdir(), key=lambda p: p.name.lower()):
                # Filter hidden or unwanted
                if item.name.startswith(".") and item.name not in (".git", ".yata"):
                    continue
                try:
                    if item.is_dir():
                        dirs.append(item)
                    elif item.is_file():
                        files.append(item)
                except (PermissionError, OSError):
                    continue
        except PermissionError:
            self.notify(f"Access Denied: Cannot read directory {self.current_dir}", severity="error")
            return
        except Exception as err:
            self.notify(f"Error accessing directory: {err}", severity="error")
            return

        # Add directories
        for d in dirs:
            if filter_query and filter_query.lower() not in d.name.lower():
                continue
            is_proj = looks_like_project(d)
            badge = " [#00D2FF][PROJECT][/]" if is_proj else ""
            opt_id = f"dir:{d}"
            display = f"📁 {d.name}{badge}"
            option_list.add_option(Option(prompt=display, id=opt_id))
            self._entries.append((opt_id, d, True))

        # Add files
        if self.browse_mode != "scope_dir":
            for f in files:
                if filter_query and filter_query.lower() not in f.name.lower():
                    continue
                try:
                    size_str = format_file_size(f.stat().st_size)
                except Exception:
                    size_str = ""
                opt_id = f"file:{f}"
                display = f"📄 {f.name:<32} {size_str}"
                option_list.add_option(Option(prompt=display, id=opt_id))
                self._entries.append((opt_id, f, False))

        if not dirs and not files:
            option_list.add_option(Option(prompt="  (Empty directory)", id="entry:empty", disabled=True))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        opt_id = event.option.id
        if not opt_id:
            return

        if opt_id == "entry:parent":
            self.action_go_parent()
        elif opt_id == "entry:select_current":
            self._confirm_selection(self.current_dir)
        elif opt_id.startswith("dir:"):
            target_dir = Path(opt_id.split("dir:", 1)[1])
            self._navigate_to(target_dir)
        elif opt_id.startswith("file:"):
            target_file = Path(opt_id.split("file:", 1)[1])
            if self.browse_mode == "scope_file":
                self._confirm_file_selection(target_file)
            else:
                self._confirm_selection(target_file.parent)

    def _navigate_to(self, new_dir: Path) -> None:
        try:
            resolved = new_dir.resolve()
            # Test access
            list(resolved.iterdir())
            self.current_dir = resolved
            if self.is_mounted:
                header = self.query_one("#browser-header", YataHeader)
                header.breadcrumbs = f"Target › Browse Filesystem › {self.current_dir.name}"
                self._refresh_listing()
        except PermissionError:
            if self.is_mounted:
                self.notify(f"Access Denied: {new_dir.name}", severity="error")
        except Exception as err:
            if self.is_mounted:
                self.notify(f"Cannot access {new_dir.name}: {err}", severity="error")

    def action_go_parent(self) -> None:
        parent = self.current_dir.parent
        if parent != self.current_dir:
            self._navigate_to(parent)

    def action_select_current(self) -> None:
        self._confirm_selection(self.current_dir)

    def action_select_highlighted(self) -> None:
        option_list = self.query_one("#browser-list", OptionList)
        if option_list.highlighted is not None and 0 <= option_list.highlighted < len(self._entries):
            entry_id, path, is_dir = self._entries[option_list.highlighted]
            if entry_id == "entry:parent":
                self.action_go_parent()
            elif entry_id == "entry:select_current":
                self._confirm_selection(self.current_dir)
            elif is_dir:
                if self.browse_mode == "scope_dir":
                    self._confirm_selection(path)
                else:
                    self._confirm_selection(path)
            else:
                if self.browse_mode == "scope_file":
                    self._confirm_file_selection(path)
                else:
                    self._confirm_selection(path.parent)

    def _confirm_selection(self, selected_path: Path) -> None:
        if self.browse_mode == "target":
            self.app.mission_state.reset_for_target(selected_path)
            from tui.screens.scope import ScopeSelectScreen
            self.app.push_screen(ScopeSelectScreen())
        elif self.browse_mode == "scope_dir":
            self.app.mission_state.scope_path = selected_path
            from tui.screens.mode import ModeSelectScreen
            self.app.push_screen(ModeSelectScreen())

    def _confirm_file_selection(self, selected_file: Path) -> None:
        self.app.mission_state.scope_path = selected_file
        from tui.screens.mode import ModeSelectScreen
        self.app.push_screen(ModeSelectScreen())

    def action_toggle_filter(self) -> None:
        inp = self.query_one("#browser-filter-input", Input)
        inp.remove_class("hidden")
        inp.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        self._refresh_listing(filter_query=event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        inp = self.query_one("#browser-filter-input", Input)
        inp.add_class("hidden")
        self.query_one("#browser-list", OptionList).focus()

    def action_go_back(self) -> None:
        inp = self.query_one("#browser-filter-input", Input)
        if not inp.has_class("hidden"):
            inp.add_class("hidden")
            self._refresh_listing()
            self.query_one("#browser-list", OptionList).focus()
            return
        self.app.pop_screen()
