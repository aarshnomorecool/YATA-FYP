from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

# Maps the yata_profile.json slug (same slugs verifier.py's _verify_* dispatch
# already keys off of) to the display-string vulnerability_type used by
# AttackLibrary / VULNERABILITY_MAPPING. Only vulnerability classes whose
# success signal is observable over plain HTTP are included here -- Hardcoded
# Secret has no live-HTTP signal and is intentionally out of RECON's scope.
SLUG_TO_VULNERABILITY_TYPE: dict[str, str] = {
    "sql_injection": "SQL Injection",
    "command_injection": "Command Injection",
    "path_traversal": "Path Traversal",
}


@dataclass(slots=True)
class EndpointProfile:
    vulnerability_type: str
    slug: str
    method: str
    path: str
    params: dict[str, str]
    success_contains: str | None = None
    success_status_code: int | None = None
    expected_status: int | None = None


class ReconProfile:
    def __init__(self, endpoints: list[EndpointProfile]) -> None:
        self.endpoints = endpoints

    @classmethod
    def load(cls, profile_path: Path) -> "ReconProfile":
        raw = json.loads(profile_path.read_text(encoding="utf-8"))
        endpoints: list[EndpointProfile] = []
        for slug, entry in raw.items():
            vulnerability_type = SLUG_TO_VULNERABILITY_TYPE.get(slug)
            if vulnerability_type is None:
                continue
            endpoints.append(
                EndpointProfile(
                    vulnerability_type=vulnerability_type,
                    slug=slug,
                    method=str(entry.get("method", "GET")).upper(),
                    path=str(entry.get("path", "/")),
                    params=dict(entry.get("params", {})),
                    success_contains=entry.get("success_contains"),
                    success_status_code=entry.get("success_status_code"),
                    expected_status=entry.get("expected_status"),
                )
            )
        return cls(endpoints)

    def endpoints_for(self, vulnerability_type: str) -> list[EndpointProfile]:
        return [e for e in self.endpoints if e.vulnerability_type == vulnerability_type]
