from __future__ import annotations

import time
from dataclasses import dataclass, field

from llm_client import LLMClient
from red_agent import VulnerabilityFinding

from .exploiter import ReconExploiter
from .profile import ReconProfile
from .scanner import ReconScanner


@dataclass(slots=True)
class ReconRunResult:
    base_url: str
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    endpoints_checked: int = 0
    scan_seconds: float = 0.0
    exploit_seconds: float = 0.0


class ReconAgent:
    """RECON: deployment-side counterpart to HUNTER, attacking a live HTTP
    target instead of reading source. Scans and exploits only -- never
    patches, so the four-part detector/patch/verify cycle Golden Rule 2
    requires for YATA-Dev vulnerability classes does not apply here.
    """

    def __init__(
        self,
        *,
        scanner: ReconScanner | None = None,
        exploiter: ReconExploiter | None = None,
        llm_client: LLMClient | None = None,
    ) -> None:
        self.scanner = scanner or ReconScanner()
        self.exploiter = exploiter or ReconExploiter()
        self.llm = llm_client or LLMClient(provider="recon")

    def run(self, base_url: str, *, profile: ReconProfile | None = None) -> ReconRunResult:
        t0 = time.time()
        endpoints = self.scanner.discover(profile=profile)
        scan_seconds = time.time() - t0

        t1 = time.time()
        findings: list[VulnerabilityFinding] = []
        for endpoint in endpoints:
            finding = self.exploiter.exploit(base_url, endpoint)
            if finding is not None:
                findings.append(finding)
        exploit_seconds = time.time() - t1

        return ReconRunResult(
            base_url=base_url,
            findings=findings,
            endpoints_checked=len(endpoints),
            scan_seconds=scan_seconds,
            exploit_seconds=exploit_seconds,
        )

    def explain_finding(self, finding: VulnerabilityFinding) -> str:
        fallback_text = (
            f"Rule-based assessment: a live HTTP request to {finding.affected_file} using payload "
            f"{finding.exploit_payload!r} produced the {finding.vulnerability_type} success signal, "
            "confirming the weakness is exploitable on the running deployment."
        )
        if LLMClient.execution_mode in ("autonomous_fallback", "demo"):
            return fallback_text
        response = self.llm.generate(
            system_prompt=(
                "You are RECON in YATA, the deployment-side reconnaissance module. Explain a concrete "
                "live HTTP attack path using only the provided evidence. Do not invent extra vulnerabilities."
            ),
            user_prompt=(
                f"Vulnerability Type: {finding.vulnerability_type}\n"
                f"Endpoint: {finding.affected_file}\n"
                f"Payload: {finding.exploit_payload}\n"
                f"Evidence: {finding.evidence}\n\n"
                "Write a concise explanation of how the exploit works against the live deployment."
            ),
            fallback_text=fallback_text,
            temperature=0.9,
            max_tokens=220,
            request_type="recon",
        )
        return response.content

    def capability_matrix(self) -> dict[str, str]:
        return {
            "SQL Injection": "implemented (recon)",
            "Command Injection": "implemented (recon)",
            "Path Traversal": "implemented (recon)",
            "Hardcoded Secret": "not applicable (no live-HTTP signal)",
            "Cross-Site Scripting": "framework-ready, recon check pending",
        }
