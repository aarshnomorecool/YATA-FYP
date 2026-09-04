from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Stage(str, Enum):
    IDLE = "IDLE"
    DISCOVERY = "DISCOVERY"
    HUNTER = "HUNTER"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    HEALER = "HEALER"
    VALIDATOR = "VALIDATOR"
    MUTATOR = "MUTATOR"
    FAILURE = "FAILURE"
    RECOVERY = "RECOVERY"
    COMPLETE = "COMPLETE"


class ExecutionMode(str, Enum):
    SAFE = "safe"
    INTERACTIVE = "interactive"
    APPLY = "apply"


class ScopeType(str, Enum):
    ENTIRE = "entire"
    DIRECTORY = "directory"
    FILE = "file"


@dataclass
class MissionState:
    # Target Configuration
    target_path: Path | None = None
    target_name: str = ""
    scope_type: ScopeType = ScopeType.ENTIRE
    scope_path: Path | None = None
    mode: ExecutionMode = ExecutionMode.SAFE
    max_rounds: int = 5
    simulate_failure: bool = False

    # Dynamic Workflow Tracking
    current_stage: Stage = Stage.IDLE
    current_agent: str = "SYSTEM"
    current_operation: str = "Ready"
    current_file: str = ""
    current_round: int = 1

    # Security State & Metrics
    initial_score: int = 100
    final_score: int = 100
    healed_count: int = 0
    verification_outcome: str = "Pending"  # Passed / Failed
    
    # Findings & Details
    findings: list[dict[str, Any]] = field(default_factory=list)
    active_finding: dict[str, Any] | None = None
    active_attack_plan: Any = None
    active_vulnerable_check: Any = None
    active_patch_result: Any = None
    active_patched_check: Any = None
    mutation_attempts: list[dict[str, Any]] = field(default_factory=list)
    failure_info: dict[str, Any] | None = None

    # Persistent Artifacts
    reports: dict[str, str] = field(default_factory=dict)
    memory_info: dict[str, Any] = field(default_factory=dict)
    log_messages: list[str] = field(default_factory=list)

    # Runtime Flags
    is_paused: bool = False
    is_aborted: bool = False

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if str(f.get("severity", "")).upper() == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if str(f.get("severity", "")).upper() == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if str(f.get("severity", "")).upper() == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if str(f.get("severity", "")).upper() == "LOW")

    def add_log(self, message: str) -> None:
        self.log_messages.append(message)
        if len(self.log_messages) > 100:
            self.log_messages.pop(0)

    def reset_for_target(self, path: Path) -> None:
        self.target_path = path.resolve()
        self.target_name = path.name
        self.scope_type = ScopeType.ENTIRE
        self.scope_path = None
        self.current_stage = Stage.IDLE
        self.current_agent = "SYSTEM"
        self.current_operation = "Ready"
        self.current_file = ""
        self.current_round = 1
        self.findings = []
        self.active_finding = None
        self.active_attack_plan = None
        self.active_vulnerable_check = None
        self.active_patch_result = None
        self.active_patched_check = None
        self.mutation_attempts = []
        self.failure_info = None
        self.reports = {}
        self.log_messages = []
        self.healed_count = 0
        self.initial_score = 100
        self.final_score = 100
        self.verification_outcome = "Pending"
        self.is_paused = False
        self.is_aborted = False
