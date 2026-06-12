from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


class LearnerAgent:
    def __init__(self, memory_root: Path | None = None) -> None:
        project_root = Path(__file__).resolve().parent
        self.memory_root = memory_root or project_root / ".yata" / "memory"

    def get_memory_file(self, repository_name: str) -> Path:
        repo_mem_dir = self.memory_root / repository_name
        repo_mem_dir.mkdir(parents=True, exist_ok=True)
        return repo_mem_dir / "memory.json"

    def load_memory(self, repository_name: str) -> dict | None:
        mem_file = self.get_memory_file(repository_name)
        if mem_file.exists():
            try:
                return json.loads(mem_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        return None

    def initialize_memory(self, repository_name: str) -> dict:
        today = datetime.now().strftime("%Y-%m-%d")
        return {
            "repository": repository_name,
            "first_assessed": today,
            "last_assessed": today,
            "total_assessments": 0,
            "last_score": 0,
            "best_score": 0,
            "vulnerabilities_seen": {},
            "successful_patches": {},
            "failed_patches": {},
            "assessment_history": []
        }

    def update_memory(
        self,
        repository_name: str,
        timestamp: str,
        findings_count: int,
        vulnerability_types: list[str],
        successful_patches: list[str],
        failed_patches: list[str],
        initial_score: int,
        final_score: int,
        validation_outcome: str
    ) -> dict:
        mem = self.load_memory(repository_name)
        if not mem:
            mem = self.initialize_memory(repository_name)

        mem["total_assessments"] += 1
        mem["last_assessed"] = timestamp
        mem["last_score"] = final_score
        if final_score > mem["best_score"]:
            mem["best_score"] = final_score

        for vtype in vulnerability_types:
            mem["vulnerabilities_seen"][vtype] = mem["vulnerabilities_seen"].get(vtype, 0) + 1
        for vtype in successful_patches:
            mem["successful_patches"][vtype] = mem["successful_patches"].get(vtype, 0) + 1
        for vtype in failed_patches:
            mem["failed_patches"][vtype] = mem["failed_patches"].get(vtype, 0) + 1

        mem["assessment_history"].append({
            "date": timestamp,
            "score_before": initial_score,
            "score_after": final_score,
            "findings": findings_count
        })

        mem_file = self.get_memory_file(repository_name)
        mem_file.write_text(json.dumps(mem, indent=2), encoding="utf-8")
        return mem
