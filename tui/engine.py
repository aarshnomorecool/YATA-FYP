from __future__ import annotations

import json
import queue
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from blue_agent import BlueAgent, PatchResult
from learner_agent import LearnerAgent
from llm_client import LLMClient
from mutator_agent import MutatorAgent
from red_agent import AttackPlan, RedAgent, VulnerabilityFinding
from report_generator import ReportGenerator
from verifier import Referee, VerificationResult

from tui.state import ExecutionMode, MissionState, ScopeType, Stage


VULNERABILITY_MAPPING = {
    "SQL Injection": {
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
        "impact": "Authentication bypass, Data exfiltration",
        "severity": "CRITICAL",
    },
    "Hardcoded Secret": {
        "owasp": "A02:2021 – Cryptographic Failures",
        "cwe": "CWE-798",
        "impact": "Credential exposure, Access compromise",
        "severity": "HIGH",
    },
    "Cross-Site Scripting": {
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-79",
        "impact": "Session hijacking, Client-side code execution",
        "severity": "MEDIUM",
    },
    "Command Injection": {
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-78",
        "impact": "Remote Command Execution, Privilege Escalation, Data Exfiltration",
        "severity": "CRITICAL",
    },
    "Path Traversal": {
        "owasp": "A01:2021 Broken Access Control",
        "cwe": "CWE-22",
        "impact": "Unauthorized File Access, Source Code Disclosure, Sensitive Data Leakage",
        "severity": "HIGH",
    },
}


def _clean_rel_path(path: object, base_path: Path | None = None) -> str:
    path_str = str(path).replace("\\", "/")
    if base_path:
        base_str = str(base_path).replace("\\", "/")
        if path_str.startswith(base_str):
            return path_str[len(base_str):].lstrip("/")
    return Path(path_str).name


class AssessmentEngine:
    """Executes the existing YATA assessment pipeline with non-blocking event hooks."""

    def __init__(
        self,
        state: MissionState,
        on_state_change: Callable[[MissionState], None] | None = None,
        on_log: Callable[[str], None] | None = None,
    ) -> None:
        self.state = state
        self.on_state_change = on_state_change
        self.on_log = on_log

        # Queues for human-in-the-loop decisions
        self.human_review_queue: queue.Queue[str] = queue.Queue()
        self.failure_decision_queue: queue.Queue[str] = queue.Queue()

        # Agents
        self.red_agent = RedAgent()
        self.blue_agent = BlueAgent()
        self.mutator_agent = MutatorAgent()
        self.referee = Referee()
        self.learner = LearnerAgent()

        self.project_root = Path(__file__).resolve().parent.parent
        self.reports_root = self.project_root / ".yata" / "reports"
        self.report_generator = ReportGenerator(self.reports_root)

    def log(self, message: str) -> None:
        self.state.add_log(message)
        if self.on_log:
            self.on_log(message)
        if self.on_state_change:
            self.on_state_change(self.state)

    def notify(self) -> None:
        if self.on_state_change:
            self.on_state_change(self.state)

    def run_mission(self) -> bool:
        """Run the full security assessment mission."""
        if not self.state.target_path or not self.state.target_path.exists():
            self.log(f"Error: Target path does not exist: {self.state.target_path}")
            self.state.current_stage = Stage.COMPLETE
            self.state.verification_outcome = "Failed"
            self.notify()
            return False

        target_root = self.state.target_path.resolve()
        repo_name = target_root.name
        self.state.target_name = repo_name

        # Setup .yata directories
        yata_dir = self.project_root / ".yata"
        reports_dir = yata_dir / "reports" / repo_name
        patches_dir = yata_dir / "patches" / repo_name
        analysis_dir = yata_dir / "analysis" / repo_name
        logs_dir = yata_dir / "logs" / repo_name

        for d in (yata_dir, reports_dir, patches_dir, analysis_dir, logs_dir):
            d.mkdir(parents=True, exist_ok=True)

        self.report_generator.reports_root = reports_dir

        # Load repository memory
        pre_mem = self.learner.load_memory(repo_name)
        if pre_mem:
            self.state.memory_info = pre_mem
            self.log(f"[SCHOLAR] Loaded memory for {repo_name} (assessments: {pre_mem.get('total_assessments', 0)})")
        else:
            self.state.memory_info = {"total_assessments": 0, "status": "First Assessment"}
            self.log(f"[SCHOLAR] Initializing new memory profile for {repo_name}")

        current_root = target_root
        round_reports: list[dict] = []
        discovered_findings: list[dict[str, Any]] = []
        all_findings_keys: set[tuple] = set()
        battle_status = "complete"
        termination_reason = "All weaknesses resolved and validated."
        healed_count = 0
        patch_applied = False

        start_time = time.time()
        t_hunter_disc = 0.0
        t_hunter_att = 0.0
        t_healer_patch = 0.0
        t_validator_verif = 0.0
        t_mutator_verif = 0.0

        # STAGE 1: DISCOVERY
        self.state.current_stage = Stage.DISCOVERY
        self.state.current_agent = "HUNTER"
        self.state.current_operation = "Scanning repository AST for security weaknesses..."
        self.log("[HUNTER] Scanning codebase for vulnerabilities...")
        self.notify()

        t0 = time.time()
        raw_findings: list[VulnerabilityFinding] = self.red_agent.scan(current_root)
        t_hunter_disc += time.time() - t0

        # Apply Scope filter if requested
        if self.state.scope_type == ScopeType.FILE and self.state.scope_path:
            target_file_str = str(self.state.scope_path.resolve())
            raw_findings = [f for f in raw_findings if str(Path(f.affected_file).resolve()) == target_file_str]
        elif self.state.scope_type == ScopeType.DIRECTORY and self.state.scope_path:
            target_dir_str = str(self.state.scope_path.resolve())
            raw_findings = [f for f in raw_findings if str(Path(f.affected_file).resolve()).startswith(target_dir_str)]

        self.state.initial_score = self.referee.calculate_security_score(raw_findings)
        self.state.final_score = self.state.initial_score

        # Populate findings list in state
        for f in raw_findings:
            mapping = VULNERABILITY_MAPPING.get(f.vulnerability_type, {})
            f_dict = {
                "vulnerability_type": f.vulnerability_type,
                "file": _clean_rel_path(f.affected_file, current_root),
                "line_number": f.line_number,
                "severity": mapping.get("severity", f.severity).upper(),
                "owasp": mapping.get("owasp", "N/A"),
                "cwe": mapping.get("cwe", "N/A"),
                "impact": mapping.get("impact", "N/A"),
                "evidence": f.evidence,
                "status": "active",
                "finding_obj": f,
            }
            key = (f.vulnerability_type, f.affected_file, f.line_number)
            if key not in all_findings_keys:
                all_findings_keys.add(key)
                discovered_findings.append(f_dict)

        self.state.findings = discovered_findings
        self.log(f"[HUNTER] Discovered {len(discovered_findings)} vulnerability candidate(s). Initial Score: {self.state.initial_score}/100")
        self.notify()

        if not raw_findings:
            self.state.current_stage = Stage.COMPLETE
            self.state.current_operation = "Repository clean. No vulnerabilities found."
            self.state.verification_outcome = "Passed"
            self.notify()
            return True

        # ROUND LOOP
        max_rounds = min(self.state.max_rounds, len(raw_findings) + 2)
        remaining_findings = raw_findings

        for round_num in range(1, max_rounds + 1):
            if self.state.is_aborted:
                self.log("[SYSTEM] Mission aborted by user.")
                break

            self.state.current_round = round_num

            # STAGE 2: HUNTER - Attack Planning & Exploit Proof
            self.state.current_stage = Stage.HUNTER
            self.state.current_agent = "HUNTER"
            self.state.current_operation = f"Round {round_num}: Proving exploitability with live payloads..."
            self.log(f"[HUNTER] Evaluating prioritized attack paths for Round {round_num}...")
            self.notify()

            t0 = time.time()
            attack_selection = self._select_attack(current_root, remaining_findings)
            t_hunter_att += time.time() - t0

            if not attack_selection:
                self.log("[VALIDATOR] No remaining vulnerabilities could be exploited.")
                battle_status = "stalled"
                break

            finding, attack_plan, vulnerable_check = attack_selection
            self.state.active_finding = {
                "vulnerability_type": finding.vulnerability_type,
                "file": _clean_rel_path(finding.affected_file, current_root),
                "line_number": finding.line_number,
                "severity": finding.severity.upper(),
                "evidence": finding.evidence,
                "payload": attack_plan.payload,
                "attack_path": attack_plan.attack_path,
                "explanation": attack_plan.explanation,
                "finding_obj": finding,
            }
            self.state.active_attack_plan = attack_plan
            self.state.active_vulnerable_check = vulnerable_check
            self.state.current_file = _clean_rel_path(finding.affected_file, current_root)
            self.log(f"[HUNTER] Exploit CONFIRMED: {finding.vulnerability_type} at {self.state.current_file}:{finding.line_number}")
            self.notify()

            # STAGE 3: HUMAN REVIEW (INTERACTIVE MODE)
            if self.state.mode == ExecutionMode.INTERACTIVE:
                self.state.current_stage = Stage.HUMAN_REVIEW
                self.state.current_operation = "Paused: Awaiting Human Decision on confirmed weakness."
                self.log(f"[HUMAN OVERSIGHT] Human decision required for {finding.vulnerability_type}")
                self.notify()

                decision = self.human_review_queue.get()
                if decision == "ABORT":
                    self.state.is_aborted = True
                    self.log("[HUMAN OVERSIGHT] Mission aborted by human reviewer.")
                    break
                elif decision == "REJECT":
                    self.log("[HUMAN OVERSIGHT] Human reviewer rejected finding. Continuing search.")
                    remaining_findings = [f for f in remaining_findings if f != finding]
                    continue
                # If "AUTHORIZE", proceed to HEALER

            # STAGE 4: HEALER - Remediation Generation
            self.state.current_stage = Stage.HEALER
            self.state.current_agent = "HEALER"
            self.state.current_operation = f"Generating secure patch for {finding.vulnerability_type}..."
            self.log(f"[HEALER] Generating minimal secure patch for {self.state.current_file}:{finding.line_number}...")
            self.notify()

            t0 = time.time()
            patch_result = self.blue_agent.generate_patch(current_root, finding)
            t_healer_patch += time.time() - t0
            self.state.active_patch_result = patch_result
            self.log(f"[HEALER] Patch generated for {len(patch_result.changed_files)} file(s).")
            self.notify()

            # STAGE 5: VALIDATOR - Adversarial Attack on Patched Code
            self.state.current_stage = Stage.VALIDATOR
            self.state.current_agent = "VALIDATOR"
            self.state.current_operation = "Attacking patched code with original winning exploit payload..."
            self.log("[VALIDATOR] Launching live re-exploitation against patched copy...")
            self.notify()

            t0 = time.time()
            patched_check = self.referee.verify_exploit(patch_result.patched_root, finding, attack_plan.payload)
            t_validator_verif += time.time() - t0
            self.state.active_patched_check = patched_check

            patch_succeeded = not patched_check.attack_succeeded
            mutation_attempts: list[dict[str, Any]] = []

            # Simulated failure hook for testing/demoing failure workflow
            if self.state.simulate_failure:
                patch_succeeded = False
                patched_check.attack_succeeded = True
                patched_check.evidence = "Simulated adversarial bypass: Exploit executed on remediation."

            # STAGE 6: MUTATOR - Adversarial Variant Attacks (if original exploit blocked)
            if patch_succeeded:
                self.state.current_stage = Stage.MUTATOR
                self.state.current_agent = "MUTATOR"
                self.state.current_operation = "Re-attacking patch with mutated payload variants..."
                self.log("[MUTATOR] Generating mutated attack variations (encodings, alternate syntax)...")
                self.notify()

                t0 = time.time()
                mutated_payloads = self.mutator_agent.generate_mutations(
                    finding.vulnerability_type, attack_plan.payload
                )
                for mut_p in mutated_payloads:
                    mut_check = self.referee.verify_exploit(patch_result.patched_root, finding, mut_p)
                    mutation_attempts.append({
                        "payload": mut_p,
                        "bypassed": mut_check.attack_succeeded,
                        "evidence": mut_check.evidence,
                    })
                    if mut_check.attack_succeeded:
                        patch_succeeded = False
                        patched_check = mut_check
                        self.log(f"[MUTATOR] Mutated payload {mut_p!r} BYPASSED patch!")
                        break
                    else:
                        self.log(f"[MUTATOR] Mutated payload {mut_p!r} BLOCKED ✓")
                t_mutator_verif += time.time() - t0

            self.state.mutation_attempts = mutation_attempts

            # STAGE 7: EXCEPTION / FAILURE WORKFLOW
            if not patch_succeeded:
                self.state.current_stage = Stage.FAILURE
                self.state.current_operation = "VALIDATION FAILED: Remediation did not survive adversarial attack."
                self.state.failure_info = {
                    "vulnerability_type": finding.vulnerability_type,
                    "file": self.state.current_file,
                    "line_number": finding.line_number,
                    "payload": patched_check.evidence or attack_plan.payload,
                    "evidence": patched_check.evidence,
                    "status_code": getattr(patched_check, "status_code", 500),
                    "reason": "The patch did not prevent exploitation under adversarial verification.",
                    "mutation_attempts": mutation_attempts,
                }
                self.log("[VALIDATOR] Remediation FAILED verification. Patch rejected.")
                self.notify()

                # Wait for user decision on failure
                failure_decision = self.failure_decision_queue.get()
                if failure_decision == "ABORT":
                    battle_status = "failed"
                    termination_reason = "Remediation failed validation and assessment was aborted."
                    break
                elif failure_decision == "RETRY":
                    self.log("[RECOVERY] Retrying remediation with fallback strategy...")
                    self.state.current_stage = Stage.RECOVERY
                    self.state.current_operation = "Applying alternative defensive strategy..."
                    self.notify()
                    time.sleep(0.5)
                    # Retry HEALER
                    patch_result = self.blue_agent.generate_patch(current_root, finding)
                    patched_check = self.referee.verify_exploit(patch_result.patched_root, finding, attack_plan.payload)
                    if not patched_check.attack_succeeded:
                        patch_succeeded = True
                        self.log("[RECOVERY] Alternative patch survived validation!")
                    else:
                        self.log("[RECOVERY] Alternative patch also failed validation.")
                        battle_status = "failed"
                        break
                elif failure_decision == "RUN_MUTATION":
                    self.log("[RECOVERY] Re-evaluating with extended mutations...")
                    # Allow user to inspect or continue
                    pass

            if patch_succeeded:
                healed_count += 1
                self.state.healed_count = healed_count
                self.log(f"[VALIDATOR] Patch verified! Weakness {finding.vulnerability_type} HEALED.")

                # Copy to .yata/patches
                for rel_path in patch_result.changed_files:
                    src = patch_result.patched_root / rel_path
                    dst = patches_dir / rel_path
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)

                # APPLY mode handling
                if self.state.mode == ExecutionMode.APPLY:
                    self._apply_patch_to_target(target_root, patch_result)
                    current_root = target_root
                    patch_applied = True
                    self.log(f"[APPLY] Promoted verified patch to target repository: {repo_name}")
                else:
                    current_root = patch_result.patched_root

                # Update remaining findings
                raw_findings = self.red_agent.scan(current_root)
                if self.state.scope_type == ScopeType.FILE and self.state.scope_path:
                    raw_findings = [f for f in raw_findings if str(Path(f.affected_file).resolve()) == str(self.state.scope_path.resolve())]
                remaining_findings = raw_findings

                for f_item in self.state.findings:
                    if f_item["vulnerability_type"] == finding.vulnerability_type and f_item["line_number"] == finding.line_number:
                        f_item["status"] = "healed"

                self.state.final_score = self.referee.calculate_security_score(remaining_findings)
                self.notify()
            else:
                break

        # STAGE 8: SCHOLAR / LEARNER - Memory Update
        self.state.current_stage = Stage.COMPLETE
        self.state.current_agent = "SCHOLAR"
        self.state.current_operation = "Updating repository security memory profile..."
        self.log("[SCHOLAR] Recording assessment metrics in persistent repository memory...")
        self.notify()

        verification_result = "Passed" if healed_count > 0 and not remaining_findings else "Failed"
        if not discovered_findings:
            verification_result = "Passed"

        today = datetime.now().strftime("%Y-%m-%d")
        updated_mem = self.learner.update_memory(
            repository_name=repo_name,
            timestamp=today,
            findings_count=len(discovered_findings),
            vulnerability_types=[f["vulnerability_type"] for f in discovered_findings],
            successful_patches=[f["vulnerability_type"] for f in discovered_findings if f["status"] == "healed"],
            failed_patches=[f["vulnerability_type"] for f in discovered_findings if f["status"] != "healed"],
            initial_score=self.state.initial_score,
            final_score=self.state.final_score,
            validation_outcome=verification_result,
        )
        self.state.memory_info = updated_mem
        self.state.verification_outcome = verification_result

        # STAGE 9: REPORTER - Report Generation
        t_total = time.time() - start_time
        report = self.report_generator.build_report(
            repository_name=repo_name,
            mode=self.state.mode.value,
            patch_mode=self.state.mode.value.upper(),
            patch_applied_to_original="Yes" if patch_applied else "No",
            verification_result=verification_result,
            target_root=target_root,
            final_root=current_root,
            battle_status=battle_status,
            termination_reason=termination_reason,
            final_security_score=self.state.final_score,
            remaining_findings=remaining_findings,
            rounds=round_reports,
            capability_matrix={
                "HUNTER": self.red_agent.capability_matrix(),
                "HEALER": self.blue_agent.capability_matrix(),
                "VALIDATOR": self.referee.capability_matrix(),
                "MUTATOR": self.mutator_agent.capability_matrix(),
            },
            performance_telemetry={
                "hunter_discovery": t_hunter_disc,
                "hunter_attack": t_hunter_att,
                "healer_patch": t_healer_patch,
                "validator_verification": t_validator_verif,
                "mutator_verification": t_mutator_verif,
                "llm_requests": 0,
                "llm_time": 0.0,
                "avg_llm_response": 0.0,
                "report_generation": 0.0,
                "total_runtime": t_total,
            },
            execution_mode=LLMClient.execution_mode,
        )
        report_paths = self.report_generator.write_reports(report)
        self.state.reports = report_paths
        self.log(f"[REPORTER] Reports generated: {', '.join(report_paths.keys())}")
        self.state.current_operation = "Mission Complete."
        self.notify()
        return verification_result == "Passed"

    def _select_attack(
        self, current_root: Path, findings: list[VulnerabilityFinding]
    ) -> tuple[VulnerabilityFinding, AttackPlan, VerificationResult] | None:
        for finding in self.red_agent.prioritize(findings):
            payloads = self.red_agent.get_payloads_for_finding(finding)
            for payload in payloads:
                if finding.vulnerability_type == "Hardcoded Secret" and payload != finding.exploit_payload:
                    continue
                check = self.referee.verify_exploit(current_root, finding, payload)
                if check.attack_succeeded:
                    attack_plan = self.red_agent.plan_attack(finding, payload)
                    return finding, attack_plan, check
        return None

    def _apply_patch_to_target(self, target_root: Path, patch_result: PatchResult) -> None:
        for rel_path in patch_result.changed_files:
            rel = Path(rel_path)
            src = patch_result.patched_root / rel
            dst = target_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
