from __future__ import annotations

import asyncio
import os
import queue
import sys
import unittest
from pathlib import Path

# Set UTF-8 encoding
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from tui.app import YataTuiApp
from tui.engine import AssessmentEngine
from tui.screens.browser import FileBrowserScreen, looks_like_project
from tui.screens.complete import CompleteScreen, make_score_bar
from tui.screens.evidence import EvidenceScreen
from tui.screens.execution import ExecutionScreen
from tui.screens.failure import FailureScreen
from tui.screens.mission import MissionPreviewScreen
from tui.screens.mode import ModeSelectScreen
from tui.screens.review import HumanReviewScreen
from tui.screens.scope import ScopeSelectScreen
from tui.screens.target import TargetSelectScreen, detect_repo_metadata
from tui.state import ExecutionMode, MissionState, ScopeType, Stage


class TestYataTui(unittest.TestCase):
    """Test suite for YATA Terminal User Interface & Mission Console."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent

    def test_01_repo_metadata_detection(self):
        """Test repository detection: framework and file counts."""
        repo1 = self.root / "test_repositories" / "repo1_login_sqli"
        framework, count = detect_repo_metadata(repo1)
        self.assertEqual(framework, "Flask")
        self.assertGreaterEqual(count, 1)

        # Test project marker detection
        self.assertTrue(looks_like_project(repo1))
        self.assertTrue(looks_like_project(self.root))

        # Test empty or non-existent path
        empty_path = self.root / "non_existent_folder_xyz"
        fw_unknown, count_zero = detect_repo_metadata(empty_path)
        self.assertEqual(fw_unknown, "Unknown")
        self.assertEqual(count_zero, 0)

    def test_02_filesystem_browser_logic(self):
        """Test real filesystem browsing and robust error handling."""
        browser = FileBrowserScreen(initial_path=self.root)
        self.assertEqual(browser.current_dir.resolve(), self.root.resolve())

        # Test parent navigation
        parent = browser.current_dir.parent
        browser.action_go_parent()
        self.assertEqual(browser.current_dir.resolve(), parent.resolve())

        # Test invalid path navigation safely without crashing
        invalid_path = Path("Z:\\non_existent_drive_or_path_12345")
        browser._navigate_to(invalid_path)
        # Verify it did not crash and stayed in valid directory
        self.assertTrue(browser.current_dir.exists())

    def test_03_mission_state_transitions(self):
        """Test explicit state model and transitions."""
        state = MissionState()
        repo1 = self.root / "test_repositories" / "repo1_login_sqli"
        state.reset_for_target(repo1)

        self.assertEqual(state.target_name, "repo1_login_sqli")
        self.assertEqual(state.scope_type, ScopeType.ENTIRE)
        self.assertEqual(state.mode, ExecutionMode.SAFE)
        self.assertEqual(state.current_stage, Stage.IDLE)

        # Scope changes
        state.scope_type = ScopeType.FILE
        state.scope_path = repo1 / "app.py"
        self.assertEqual(state.scope_path.name, "app.py")

        # Mode changes
        state.mode = ExecutionMode.INTERACTIVE
        self.assertEqual(state.mode, ExecutionMode.INTERACTIVE)

    def test_04_engine_successful_assessment(self):
        """Test full autonomous assessment pipeline with success outcome."""
        state = MissionState()
        repo1 = self.root / "test_repositories" / "repo1_login_sqli"
        state.reset_for_target(repo1)
        state.mode = ExecutionMode.SAFE

        logs = []
        engine = AssessmentEngine(state, on_log=lambda msg: logs.append(msg))
        success = engine.run_mission()

        self.assertTrue(success)
        self.assertEqual(state.current_stage, Stage.COMPLETE)
        self.assertEqual(state.verification_outcome, "Passed")
        self.assertGreaterEqual(state.healed_count, 1)
        self.assertEqual(state.final_score, 100)
        self.assertTrue(bool(state.reports))
        self.assertIn("markdown", state.reports)

    def test_05_engine_interactive_human_review(self):
        """Test human review gate in INTERACTIVE mode."""
        state = MissionState()
        repo1 = self.root / "test_repositories" / "repo1_login_sqli"
        state.reset_for_target(repo1)
        state.mode = ExecutionMode.INTERACTIVE

        engine = AssessmentEngine(state)
        # Pre-seed authorization decision into queue
        engine.human_review_queue.put("AUTHORIZE")

        success = engine.run_mission()
        self.assertTrue(success)
        self.assertEqual(state.verification_outcome, "Passed")
        self.assertEqual(state.healed_count, 1)

    def test_06_engine_failure_exception_workflow(self):
        """Test first-class failure workflow when validation fails."""
        state = MissionState()
        repo1 = self.root / "test_repositories" / "repo1_login_sqli"
        state.reset_for_target(repo1)
        state.mode = ExecutionMode.SAFE
        state.simulate_failure = True  # Trigger validation failure scenario

        engine = AssessmentEngine(state)
        # Pre-seed abort on failure decision queue
        engine.failure_decision_queue.put("ABORT")

        success = engine.run_mission()
        # Must NOT be marked passed when validation fails!
        self.assertFalse(success)
        self.assertEqual(state.verification_outcome, "Failed")
        self.assertIsNotNone(state.failure_info)
        self.assertIn("Simulated adversarial bypass", state.failure_info["evidence"])

    def test_07_textual_app_navigation_pilot(self):
        """Test Textual app screens and keyboard navigation via pilot harness."""
        async def run_pilot():
            app = YataTuiApp()
            async with app.run_test() as pilot:
                # 1. Initial screen is TargetSelectScreen
                self.assertIsInstance(app.screen, TargetSelectScreen)

                # 2. Navigate down in option list
                await pilot.press("down")
                await pilot.press("down")

                # 3. Test Manual Path keybinding
                await pilot.press("m")
                await pilot.press("escape")

                # 4. Push Scope screen with target
                repo1 = self.root / "test_repositories" / "repo1_login_sqli"
                app.mission_state.reset_for_target(repo1)
                app.push_screen(ScopeSelectScreen())
                await pilot.pause(0.1)
                self.assertIsInstance(app.screen, ScopeSelectScreen)

                # 5. Push Mode screen
                app.push_screen(ModeSelectScreen())
                await pilot.pause(0.1)
                self.assertIsInstance(app.screen, ModeSelectScreen)

                # 6. Push Mission Preview screen
                app.push_screen(MissionPreviewScreen())
                await pilot.pause(0.1)
                self.assertIsInstance(app.screen, MissionPreviewScreen)

                # 7. Test pop screen with ESC
                await pilot.press("escape")
                await pilot.pause(0.1)
                self.assertIsInstance(app.screen, ModeSelectScreen)

                # 8. Test Failure Screen
                app.mission_state.failure_info = {
                    "vulnerability_type": "SQL Injection",
                    "file": "app.py",
                    "line_number": 42,
                    "evidence": "Bypass exploit confirmed",
                }
                app.push_screen(FailureScreen())
                await pilot.pause(0.1)
                self.assertIsInstance(app.screen, FailureScreen)

                # 9. Test Evidence Screen
                app.push_screen(EvidenceScreen())
                await pilot.pause(0.1)
                self.assertIsInstance(app.screen, EvidenceScreen)

                # 10. Test Complete Screen
                app.push_screen(CompleteScreen())
                await pilot.pause(0.1)
                self.assertIsInstance(app.screen, CompleteScreen)

        asyncio.run(run_pilot())

    def test_08_browser_screen_pilot_navigation(self):
        """Test FileBrowserScreen keyboard interactions via pilot."""
        async def run_browser_pilot():
            app = YataTuiApp()
            async with app.run_test() as pilot:
                browser = FileBrowserScreen(initial_path=self.root)
                app.push_screen(browser)
                await pilot.pause(0.1)
                self.assertIsInstance(app.screen, FileBrowserScreen)

                # Test navigation down and up
                await pilot.press("down")
                await pilot.press("up")

                # Test filter toggle
                await pilot.press("/")
                await pilot.press("t", "e", "s", "t")
                await pilot.press("escape")

                # Test parent navigation
                await pilot.press("left")
                await pilot.pause(0.1)

                # Test pop screen
                await pilot.press("escape")
                await pilot.pause(0.1)

        asyncio.run(run_browser_pilot())

    def test_09_cli_dispatch_and_compatibility(self):
        """Verify CLI argument routing preserves 100% backward compatibility."""
        import yata

        # 1. Version command
        args_ver = yata._parse_args(["version"])
        self.assertEqual(args_ver.command, "version")

        # 2. Status command
        args_stat = yata._parse_args(["status"])
        self.assertEqual(args_stat.command, "status")

        # 3. Assess with --safe
        args_safe = yata._parse_args(["assess", "test_repositories/repo1_login_sqli", "--safe"])
        self.assertEqual(args_safe.command, "assess")
        self.assertEqual(args_safe.mode, "safe")
        self.assertEqual(args_safe.target, "test_repositories/repo1_login_sqli")

        # 4. Assess with --interactive
        args_int = yata._parse_args(["assess", "test_repositories/repo1_login_sqli", "--interactive"])
        self.assertEqual(args_int.mode, "interactive")

        # 5. Assess with --apply
        args_app = yata._parse_args(["assess", "test_repositories/repo1_login_sqli", "--apply"])
        self.assertEqual(args_app.mode, "apply")

        # 6. TUI command
        args_tui = yata._parse_args(["tui"])
        self.assertEqual(args_tui.command, "tui")


if __name__ == "__main__":
    unittest.main()
