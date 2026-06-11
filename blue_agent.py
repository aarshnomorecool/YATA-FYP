from __future__ import annotations

import ast
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from llm_client import LLMClient
from red_agent import VulnerabilityFinding


@dataclass(slots=True)
class PatchResult:
    patched_root: Path
    patched_file: Path
    changed_files: list[str]
    patch_text: str
    used_llm: bool
    mitigation_explanation: str
    defense_strategy: str


class PatchStrategy:
    vulnerability_type = "Generic"

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        raise NotImplementedError

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        raise NotImplementedError

    def apply_auxiliary_updates(self, patched_root: Path, finding: VulnerabilityFinding) -> list[str]:
        return []

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No source changes were required because the file already matched the expected safe pattern."
        return "Applied a safe patch."

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Apply a targeted defensive change that neutralizes the exploit path while preserving behavior.",
            "Defense Strategy: Standardize secure coding patterns for this vulnerability class and re-verify them continuously.",
        )


class SQLInjectionPatchStrategy(PatchStrategy):
    vulnerability_type = "SQL Injection"

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        parameterized_query = str(metadata.get("parameterized_query", "")).strip()
        parameter_names = [str(name) for name in metadata.get("parameter_names", [])]
        query_var_name = str(metadata.get("query_var_name", "query"))
        execute_receiver = str(metadata.get("execute_receiver", "cursor"))
        query_line = int(metadata.get("query_line", finding.line_number))
        execute_line = int(metadata.get("execute_line", finding.line_number))

        lines = source.splitlines()
        query_indent = str(metadata.get("query_indent", self._line_indent(lines, query_line)))
        execute_indent = str(metadata.get("execute_indent", self._line_indent(lines, execute_line)))
        escaped_query = parameterized_query.replace("\\", "\\\\").replace('"', '\\"')
        query_replacement = f'{query_indent}{query_var_name} = "{escaped_query}"'
        execute_replacement = f"{execute_indent}{execute_receiver}.execute({query_var_name}, {self._tuple_literal(parameter_names)})"

        if 0 <= query_line - 1 < len(lines):
            lines[query_line - 1] = query_replacement

        if 0 <= execute_line - 1 < len(lines):
            if execute_line == query_line:
                lines[execute_line - 1] = f"{query_replacement}\n{execute_replacement}"
            else:
                lines[execute_line - 1] = execute_replacement

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return patched

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        parameterized_query = str(finding.metadata.get("parameterized_query", "")).strip()
        query_var_name = str(finding.metadata.get("query_var_name", "query"))
        normalized = source.replace("\t", "    ")
        return parameterized_query in normalized and f".execute({query_var_name}," in normalized

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the SQL statement already appeared parameterized."
        return (
            "Replaced string-built SQL with a parameterized query and passed user input as bound parameters "
            "to block SQL injection payloads."
        )

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Replace dynamic SQL string construction with a parameterized query so user input cannot alter SQL syntax.",
            "Defense Strategy: Route every database access path through bound parameters and continuously retest exploitable request flows.",
        )

    def _tuple_literal(self, parameter_names: list[str]) -> str:
        if not parameter_names:
            return "()"
        if len(parameter_names) == 1:
            return f"({parameter_names[0]},)"
        return f"({', '.join(parameter_names)})"

    def _line_indent(self, lines: list[str], line_number: int) -> str:
        if not (0 <= line_number - 1 < len(lines)):
            return ""
        line = lines[line_number - 1]
        return line[: len(line) - len(line.lstrip())]


class HardcodedSecretPatchStrategy(PatchStrategy):
    vulnerability_type = "Hardcoded Secret"

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        variable_name = str(finding.metadata.get("variable_name", "SECRET_VALUE"))
        env_var_name = str(finding.metadata.get("env_var_name", variable_name.upper()))
        line_number = finding.line_number
        lines = source.splitlines()
        indent = self._line_indent(lines, line_number)

        if 0 <= line_number - 1 < len(lines):
            lines[line_number - 1] = f'{indent}{variable_name} = os.getenv("{env_var_name}", "")'

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return self._ensure_os_import(patched)

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        variable_name = str(finding.metadata.get("variable_name", "SECRET_VALUE"))
        env_var_name = str(finding.metadata.get("env_var_name", variable_name.upper()))
        literal_pattern = re.compile(rf"\b{re.escape(variable_name)}\b\s*=\s*['\"]")
        env_usage = f'os.getenv("{env_var_name}", "")' in source or f"os.getenv('{env_var_name}', '')" in source
        return env_usage and literal_pattern.search(source) is None

    def apply_auxiliary_updates(self, patched_root: Path, finding: VulnerabilityFinding) -> list[str]:
        env_var_name = str(finding.metadata.get("env_var_name", "SECRET_VALUE"))
        env_example_path = patched_root / ".env.example"
        existing_lines: list[str] = []
        if env_example_path.exists():
            existing_lines = env_example_path.read_text(encoding="utf-8").splitlines()

        if not any(line.strip().startswith(f"{env_var_name}=") for line in existing_lines):
            existing_lines.append(f"{env_var_name}=change_me")
            env_example_path.write_text("\n".join(existing_lines).rstrip() + "\n", encoding="utf-8")
            return [".env.example"]
        return []

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the secret already appeared to be sourced from the environment."
        return "Moved a hardcoded credential out of source code and replaced it with an environment-variable lookup."

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Remove the credential literal from source code and load it from an environment variable instead.",
            "Defense Strategy: Keep secrets out of repositories, document required variables in .env.example, and continuously re-verify for literals.",
        )

    def _ensure_os_import(self, source: str) -> str:
        if re.search(r"^\s*import os\b", source, re.MULTILINE) or re.search(r"^\s*from os import\b", source, re.MULTILINE):
            return source

        lines = source.splitlines()
        insert_at = 0
        try:
            tree = ast.parse(source)
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                break
        except Exception:
            insert_at = 0

        lines.insert(insert_at, "import os")
        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return patched

    def _line_indent(self, lines: list[str], line_number: int) -> str:
        if not (0 <= line_number - 1 < len(lines)):
            return ""
        line = lines[line_number - 1]
        return line[: len(line) - len(line.lstrip())]


class CommandInjectionPatchStrategy(PatchStrategy):
    vulnerability_type = "Command Injection"

    def apply_source(self, source: str, finding: VulnerabilityFinding) -> str:
        metadata = finding.metadata
        safe_args = metadata.get("safe_args")
        execute_line = int(metadata.get("execute_line", finding.line_number))
        end_execute_line = int(metadata.get("end_execute_line", execute_line))
        func_name = str(metadata.get("func_name", "os.system"))
        call_src = str(metadata.get("call_src", ""))
        first_arg_src = str(metadata.get("first_arg_src", ""))

        lines = source.splitlines()
        indent = self._line_indent(lines, execute_line)

        # Build replacement call
        if safe_args:
            args_str = ", ".join(safe_args)
        else:
            param = metadata.get("parameter_names", ["cmd"])
            param_name = param[0] if param else "cmd"
            args_str = param_name

        if func_name.startswith("subprocess.") or func_name in ("run", "Popen", "check_output", "call"):
            # Subprocess call. We replace the call source in the line.
            if call_src and first_arg_src:
                new_call_src = call_src.replace(first_arg_src, f"[{args_str}]", 1)
                new_call_src = re.sub(r"\bshell\s*=\s*True\b", "shell=False", new_call_src)
                
                segment = "\n".join(lines[execute_line - 1 : end_execute_line])
                if call_src in segment:
                    new_segment = segment.replace(call_src, new_call_src, 1)
                else:
                    new_segment = f"{indent}{new_call_src}"
                lines[execute_line - 1 : end_execute_line] = new_segment.splitlines()
            else:
                lines[execute_line - 1 : end_execute_line] = [f"{indent}subprocess.run([{args_str}], shell=False)"]
        elif func_name in ("os.popen", "popen"):
            # stream = subprocess.Popen(["ping", host], shell=False, stdout=subprocess.PIPE, text=True)
            lines[execute_line - 1 : end_execute_line] = [f"{indent}import subprocess; stream = subprocess.Popen([{args_str}], shell=False, stdout=subprocess.PIPE, text=True)"]
        else:
            # os.system(cmd) -> subprocess.run(["ping", host], shell=False)
            lines[execute_line - 1 : end_execute_line] = [f"{indent}subprocess.run([{args_str}], shell=False)"]

        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"

        return self._ensure_subprocess_import(patched)

    def is_safe(self, source: str, finding: VulnerabilityFinding) -> bool:
        normalized = source.replace("\t", "    ")
        return "shell=False" in normalized or "subprocess.run" in normalized or "subprocess.Popen" in normalized

    def build_summary(self, original: str, patched: str) -> str:
        if original == patched:
            return "No changes were required; the execution path already appeared safe."
        return "Replaced unsafe shell execution with secure subprocess.run/Popen call (shell=False)."

    def fallback_guidance(self) -> tuple[str, str]:
        return (
            "Mitigation: Replace unsafe shell execution (shell=True, os.system, os.popen) with secure subprocess.run calls using shell=False and argument lists.",
            "Defense Strategy: Standardize on subprocess.run with shell=False, passing command and arguments as a list to prevent shell command injection.",
        )

    def _ensure_subprocess_import(self, source: str) -> str:
        if re.search(r"^\s*import subprocess\b", source, re.MULTILINE) or re.search(r"^\s*from subprocess import\b", source, re.MULTILINE):
            return source

        lines = source.splitlines()
        insert_at = 0
        try:
            tree = ast.parse(source)
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                    insert_at = max(insert_at, getattr(node, "end_lineno", node.lineno))
                    continue
                break
        except Exception:
            insert_at = 0

        lines.insert(insert_at, "import subprocess")
        patched = "\n".join(lines)
        if source.endswith("\n"):
            patched += "\n"
        return patched

    def _line_indent(self, lines: list[str], line_number: int) -> str:
        if not (0 <= line_number - 1 < len(lines)):
            return ""
        line = lines[line_number - 1]
        return line[: len(line) - len(line.lstrip())]


class BlueAgent:
    def __init__(
        self,
        *,
        llm_client: LLMClient | None = None,
        strategies: dict[str, PatchStrategy] | None = None,
    ) -> None:
        self.llm = llm_client or LLMClient()
        self.strategies = strategies or {
            SQLInjectionPatchStrategy.vulnerability_type: SQLInjectionPatchStrategy(),
            HardcodedSecretPatchStrategy.vulnerability_type: HardcodedSecretPatchStrategy(),
            CommandInjectionPatchStrategy.vulnerability_type: CommandInjectionPatchStrategy(),
        }
        self.verbose = False

    def generate_patch(self, target_root: Path, finding: VulnerabilityFinding) -> PatchResult:
        if LLMClient.execution_mode in ("autonomous_fallback", "demo"):
            if self.verbose:
                print("[HEALER]")
                print("Using deterministic remediation strategy.")
            import fallback_patches
            return fallback_patches.generate_patch(target_root, finding)

        strategy = self.strategies.get(finding.vulnerability_type)
        if strategy is None:
            raise ValueError(f"No patch strategy registered for {finding.vulnerability_type}")

        target_root = target_root.resolve()
        temp_root = Path(tempfile.mkdtemp(prefix="yata_patched_"))
        patched_root = temp_root / target_root.name
        shutil.copytree(
            target_root,
            patched_root,
            ignore=shutil.ignore_patterns(".yata", ".git", ".venv", "__pycache__")
        )

        relative_file = Path(str(finding.metadata.get("relative_file", Path(finding.affected_file).name)))
        patched_copy_file = patched_root / relative_file
        original_source = patched_copy_file.read_text(encoding="utf-8")
        patched_source = strategy.apply_source(original_source, finding)

        patch_llm_response = self.llm.generate(
            system_prompt=(
                "You are the BLUE agent in YATA. Patch the provided file without changing unrelated behavior. "
                "Return only the full patched file contents."
            ),
            user_prompt=self._build_patch_prompt(original_source, finding),
            fallback_text="LLM patch suggestion unavailable; using deterministic local patch strategy.",
            max_tokens=1600,
            request_type="healer",
        )

        llm_source = self._extract_code_candidate(patch_llm_response.content)
        if llm_source and strategy.is_safe(llm_source, finding):
            patched_source = llm_source

        patched_copy_file.write_text(patched_source, encoding="utf-8")
        changed_files = [str(relative_file)]
        changed_files.extend(strategy.apply_auxiliary_updates(patched_root, finding))

        mitigation_response = self.llm.generate(
            system_prompt=(
                "You are the BLUE agent in YATA. Explain how a patch reduces exploitability and how defenders "
                "should harden the affected workflow."
            ),
            user_prompt=(
                f"Vulnerability Type: {finding.vulnerability_type}\n"
                f"Affected File: {finding.affected_file}\n"
                f"Evidence: {finding.evidence}\n\n"
                "Return exactly two lines:\n"
                "Mitigation: <one concise sentence>\n"
                "Defense Strategy: <one concise sentence>"
            ),
            fallback_text=self._fallback_guidance_text(strategy),
            max_tokens=220,
        )
        mitigation_explanation, defense_strategy = self._parse_mitigation_details(
            mitigation_response.content,
            strategy,
        )
        patch_text = strategy.build_summary(original_source, patched_source)

        return PatchResult(
            patched_root=patched_root,
            patched_file=patched_copy_file,
            changed_files=changed_files,
            patch_text=patch_text,
            used_llm=bool(llm_source and strategy.is_safe(llm_source, finding)),
            mitigation_explanation=mitigation_explanation,
            defense_strategy=defense_strategy,
        )

    def capability_matrix(self) -> dict[str, str]:
        return {
            "SQL Injection": "implemented",
            "Hardcoded Secrets": "implemented",
            "Cross-Site Scripting": "framework-ready, patch strategy pending",
            "Command Injection": "implemented",
            "Path Traversal": "framework-ready, patch strategy pending",
        }

    def _build_patch_prompt(self, source: str, finding: VulnerabilityFinding) -> str:
        return (
            f"File: {finding.affected_file}\n"
            f"Line: {finding.line_number}\n"
            f"Vulnerability: {finding.vulnerability_type}\n"
            f"Evidence: {finding.evidence}\n\n"
            f"Source:\n{source}"
        )

    def _extract_code_candidate(self, content: str) -> str | None:
        stripped = content.strip()
        if not stripped:
            return None
        if stripped.startswith("```") and "```" in stripped[3:]:
            parts = stripped.split("```")
            if len(parts) >= 3:
                code = parts[1]
                if code.startswith("python\n"):
                    code = code[len("python\n") :]
                return code.strip()
        if "def " in stripped and "import " in stripped:
            return stripped
        return None

    def _fallback_guidance_text(self, strategy: PatchStrategy) -> str:
        mitigation, defense_strategy = strategy.fallback_guidance()
        return f"Mitigation: {mitigation}\nDefense Strategy: {defense_strategy}"

    def _parse_mitigation_details(self, content: str, strategy: PatchStrategy) -> tuple[str, str]:
        default_mitigation, default_defense_strategy = strategy.fallback_guidance()
        mitigation = default_mitigation
        defense_strategy = default_defense_strategy
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if line.lower().startswith("mitigation:"):
                mitigation = line.split(":", 1)[1].strip() or mitigation
            elif line.lower().startswith("defense strategy:"):
                defense_strategy = line.split(":", 1)[1].strip() or defense_strategy
        return mitigation, defense_strategy
