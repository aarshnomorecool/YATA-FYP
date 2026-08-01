from __future__ import annotations

from .profile import EndpointProfile, ReconProfile

# Deliberately small, explicit candidate list -- NOT a generic web crawler
# (that's out of scope). Used only when no ReconProfile is supplied, i.e.
# blind mode against a real target with no known route map.
BUILTIN_CANDIDATES: list[EndpointProfile] = [
    EndpointProfile("SQL Injection", "sql_injection", "POST", "/login", {"username": "__PAYLOAD__", "password": "anything"}),
    EndpointProfile("SQL Injection", "sql_injection", "GET", "/search", {"q": "__PAYLOAD__"}),
    EndpointProfile("Command Injection", "command_injection", "POST", "/ping", {"host": "__PAYLOAD__"}),
    EndpointProfile("Path Traversal", "path_traversal", "GET", "/download", {"file": "__PAYLOAD__"}),
]


class ReconScanner:
    def discover(self, *, profile: ReconProfile | None) -> list[EndpointProfile]:
        if profile is not None and profile.endpoints:
            return list(profile.endpoints)
        return list(BUILTIN_CANDIDATES)
