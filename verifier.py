from __future__ import annotations

import importlib.util
import json
import re
from dataclasses import dataclass
from pathlib import Path

from red_agent import VulnerabilityFinding


@dataclass(slots=True)
class VerificationResult:
    attack_succeeded: bool
    status_code: int
    response_text: str
    evidence: str


@dataclass(slots=True)
class RoundScore:
    round_number: int
    vulnerability_type: str
    attack_succeeded: bool
    patch_succeeded: bool
    score_before: int
    score_after: int
    score_delta: int


class Referee:
    RISK_WEIGHTS = {
        "SQL Injection": 60,
        "Hardcoded Secret": 35,
        "Cross-Site Scripting": 30,
        "Command Injection": 45,
        "Path Traversal": 30,
    }

    def __init__(self) -> None:
        self.scorecard: list[RoundScore] = []

    def verify_exploit(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        verifier = getattr(self, f"_verify_{finding.vulnerability_type.lower().replace(' ', '_')}", None)
        if verifier is None:
            raise ValueError(f"No validator strategy registered for {finding.vulnerability_type}")
        return verifier(app_root.resolve(), finding, payload)

    def calculate_security_score(self, findings: list[VulnerabilityFinding]) -> int:
        total_risk = sum(self.RISK_WEIGHTS.get(finding.vulnerability_type, 20) for finding in findings)
        return max(0, 100 - min(total_risk, 100))

    def record_round(
        self,
        *,
        round_number: int,
        finding: VulnerabilityFinding,
        attack_verification: VerificationResult,
        patch_verification: VerificationResult,
        score_before: int,
        score_after: int,
    ) -> RoundScore:
        result = RoundScore(
            round_number=round_number,
            vulnerability_type=finding.vulnerability_type,
            attack_succeeded=attack_verification.attack_succeeded,
            patch_succeeded=not patch_verification.attack_succeeded,
            score_before=score_before,
            score_after=score_after,
            score_delta=score_after - score_before,
        )
        self.scorecard.append(result)
        return result

    def capability_matrix(self) -> dict[str, str]:
        return {
            "SQL Injection": "implemented",
            "Hardcoded Secrets": "implemented",
            "Cross-Site Scripting": "framework-ready, verification strategy pending",
            "Command Injection": "framework-ready, verification strategy pending",
            "Path Traversal": "framework-ready, verification strategy pending",
        }

    def _verify_sql_injection(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        app_module = self._load_app_module(app_root / "app.py")
        app = app_module.create_app(str(app_root / "database.db"))
        profile = self._load_profile(app_root).get("sql_injection", {})
        method = str(profile.get("method", "POST")).upper()
        path = str(profile.get("path", "/login"))
        params = dict(profile.get("params", {"username": "__PAYLOAD__", "password": "anything"}))
        success_contains = str(profile.get("success_contains", "Welcome"))
        success_status_code = int(profile.get("success_status_code", 200))

        request_values = {
            key: payload if value == "__PAYLOAD__" else value
            for key, value in params.items()
        }

        with app.test_client() as client:
            if method == "GET":
                response = client.get(path, query_string=request_values, follow_redirects=True)
            else:
                response = client.post(path, data=request_values, follow_redirects=True)

        body = response.get_data(as_text=True)
        attack_succeeded = success_contains in body and response.status_code == success_status_code
        evidence = (
            f"Runtime exploit reproduced against {path}; the payload triggered the success marker {success_contains!r}."
            if attack_succeeded
            else f"Runtime exploit no longer reached the expected success marker {success_contains!r}."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=response.status_code,
            response_text=body,
            evidence=evidence,
        )

    def _verify_hardcoded_secret(self, app_root: Path, finding: VulnerabilityFinding, payload: str) -> VerificationResult:
        relative_file = Path(str(finding.metadata.get("relative_file", Path(finding.affected_file).name)))
        target_file = app_root / relative_file
        if not target_file.exists():
            return VerificationResult(
                attack_succeeded=False,
                status_code=204,
                response_text="",
                evidence="The original source file is no longer present in the target tree.",
            )

        source = target_file.read_text(encoding="utf-8")
        variable_name = str(finding.metadata.get("variable_name", "SECRET_VALUE"))
        env_var_name = str(finding.metadata.get("env_var_name", payload))
        literal_pattern = re.compile(rf"\b{re.escape(variable_name)}\b\s*=\s*['\"]")
        moved_to_env = (
            f'os.getenv("{env_var_name}", "")' in source
            or f"os.getenv('{env_var_name}', '')" in source
        )

        env_example_path = app_root / ".env.example"
        env_documented = False
        if env_example_path.exists():
            env_documented = any(
                line.strip().startswith(f"{env_var_name}=")
                for line in env_example_path.read_text(encoding="utf-8").splitlines()
            )

        attack_succeeded = bool(literal_pattern.search(source)) or not moved_to_env or not env_documented
        evidence = (
            "Credential literal is still recoverable from source or has not been fully externalized."
            if attack_succeeded
            else "Credential literal was removed from source and documented as an environment variable."
        )
        return VerificationResult(
            attack_succeeded=attack_succeeded,
            status_code=200 if attack_succeeded else 204,
            response_text=source,
            evidence=evidence,
        )

    def _load_profile(self, app_root: Path) -> dict[str, object]:
        profile_path = app_root / "yata_profile.json"
        if not profile_path.exists():
            return {}
        return json.loads(profile_path.read_text(encoding="utf-8"))

    def _load_app_module(self, app_path: Path):
        unique_name = f"yata_target_{abs(hash(str(app_path.resolve())))}"
        spec = importlib.util.spec_from_file_location(unique_name, app_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to load app module from {app_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


Verifier = Referee
