# YATA (Yata no Kagami)

YATA is a terminal-first autonomous cyber immune system for educational and defensive security hardening in Python applications.

## What it does

- Runs an adversarial `HUNTER -> HEALER -> VALIDATOR` loop in rounds.
- Analyzes Python source for SQL injection and hardcoded-secret patterns using local rules.
- Generates a proof-of-concept payload and attack-path explanation.
- Verifies runtime exploits and source-level credential exposure before any patch is accepted.
- Uses NVIDIA-hosted `qwen/qwen3-next-80b-a3b-instruct` when available for reasoning and patch suggestions.
- Supports safe-copy validation mode and apply mode for verified self-healing.
- Repeats the cycle until no verified vulnerabilities remain or a round limit is reached.
- Can assess one repository or an entire directory of repositories and prints a summary table for the whole suite.
- Generates JSON + Markdown security assessment reports with round history and score changes.

## Project Structure

- `yata.py` orchestrates the multi-round cyber defense battle.
- `red_agent.py` (HUNTER) evaluates attack paths, prioritizes, and prepares attack plans.
- `blue_agent.py` (HEALER) generates secure patches on temporary copies.
- `verifier.py` (VALIDATOR) replays exploits and owns the security score.
- `llm_client.py` centralizes NVIDIA-backed LLM access with fallback behavior.
- `llm.py` remains as a thin compatibility shim.
- `report_generator.py` writes JSON and Markdown security assessment reports.
- `vulnerable_app/` contains the intentionally vulnerable Flask + SQLite demo app.
- `test_repositories/` contains the multi-repository validation suite.

## Requirements

- Python 3.12
- Optional NVIDIA API key for LLM reasoning
- Model: `qwen/qwen3-next-80b-a3b-instruct`

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file from `.env.example` if you want NVIDIA-backed reasoning:

```bash
copy .env.example .env
```

If the API key is missing or the NVIDIA call fails, YATA falls back to deterministic local behavior so the remediation loop still works.

If you still have `qwen/qwen2.5-coder-32b-instruct` or `qwen/qwen3-coder-480b-a35b-instruct` in your local `.env`, YATA will automatically retry with `qwen/qwen3-next-80b-a3b-instruct`.

## Run

To run on a target repository, you can specify one of the mode flags, or run without flags to launch the interactive arrow-key mode selector:

Single repository, safe mode:

```bash
python yata.py assess vulnerable_app --safe
```

Single repository, apply mode:

```bash
python yata.py assess vulnerable_app --apply
```

Assess the full validation suite:

```bash
python yata.py assess test_repositories --safe
```

Demo mode (zero setup, self-contained, resets automatically):

```bash
python yata.py --demo
```

Backward-compatible invocation also still works:

```bash
python yata.py vulnerable_app
```

Expected terminal flow:

```text
[HUNTER] Evaluating attack paths for SQL Injection...
 └─ Payloads loaded: 3
 └─ Payload 1/3 FAIL
 └─ Payload 2/3 FAIL
 └─ Payload 3/3 SUCCESS ✓
[HUNTER] Prioritized weakness: SQL Injection
 └─ Severity:  CRITICAL
 └─ Location:  app.py:38
 └─ OWASP:     A03:2021 – Injection
 └─ CWE:       CWE-89
 └─ Impact:    Authentication bypass, Data exfiltration
 └─ Payload:   ' OR '1'='1' -- 
[VALIDATOR] Vulnerability verified: Runtime exploit reproduced against /login...
[HEALER] Generating secure patch...
 └─ Patch written → .yata/patches/app.py
[VALIDATOR] Attacking patched code...
 └─ Exploit blocked ✓
[HEALER] Patch verified.
```

## Output

Reports are written to `.yata/reports/` as both JSON and Markdown, including:

- Round-by-round attack, patch, and verifier verdicts
- Security score changes owned by the verifier
- Remaining findings at the end of the run
- Capability matrices showing the current SQL injection and hardcoded-secret implementation plus extension points for XSS, command injection, and path traversal

When assessing a directory of repositories, YATA also prints a security assessment summary table with:

- Repository Name
- Vulnerabilities Found
- Patches Generated
- Verification Result
- Security Score

In `--safe` mode, patched repositories stay in temporary directories (`.yata/sandbox/`) and the original source tree is never overwritten.

In `--apply` mode, YATA verifies the patch on a safe copy first and then applies only the verified file changes back to the original repository.
