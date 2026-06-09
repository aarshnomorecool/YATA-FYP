# YATA (Yata no Kagami)

YATA is a terminal-first autonomous cyber immune system for educational and defensive security hardening in Python applications.

## What it does

- Runs an adversarial `RED -> BLUE -> REFEREE` loop in rounds.
- Scans Python source for SQL injection and hardcoded-secret patterns using local rules.
- Generates a proof-of-concept payload and attack-path explanation.
- Verifies runtime exploits and source-level credential exposure before any patch is accepted.
- Uses NVIDIA-hosted `qwen/qwen3-next-80b-a3b-instruct` when available for reasoning and patch suggestions.
- Supports safe-copy validation mode and apply mode for verified self-healing.
- Repeats the cycle until no verified vulnerabilities remain or a round limit is reached.
- Can scan one repository or an entire directory of repositories and prints a summary table for the whole suite.
- Generates JSON + Markdown battle reports with round history and score changes.

## Project Structure

- `yata.py` orchestrates the multi-round cyber battle.
- `red_agent.py` scans, prioritizes, and prepares attack plans.
- `blue_agent.py` generates secure patches on temporary copies.
- `verifier.py` contains the `Referee`, which replays exploits and owns the security score.
- `llm_client.py` centralizes NVIDIA-backed LLM access with fallback behavior.
- `llm.py` remains as a thin compatibility shim.
- `report_generator.py` writes JSON and Markdown battle reports.
- `vulnerable_app/` contains the intentionally vulnerable Flask + SQLite demo app.
- `test_repositories/` contains the v0.3 multi-repository validation suite.
- `reports/` stores generated findings and summaries.

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

Single repository, safe mode:

```bash
python yata.py scan vulnerable_app --safe
```

Single repository, apply mode:

```bash
python yata.py scan vulnerable_app --apply
```

Scan the full validation suite:

```bash
python yata.py scan test_repositories --safe
```

Backward-compatible invocation also still works:

```bash
python yata.py vulnerable_app
```

Expected terminal flow:

```text
[YATA] Autonomous Scan Started
Repository: repo1_login_sqli
Round 1
[RED] Searching for additional weaknesses...
[RED] SQL Injection prioritized
[REFEREE] Attack succeeded
[BLUE] Generating patch on a safe copy...
[REFEREE] Exploit blocked
[REFEREE] Security score: 40 -> 100 (+60)
Round 2
[RED] Searching for additional weaknesses...
[REFEREE] No verified weaknesses remain
[YATA] Repository cycle finished
```

## Output

Reports are written to `reports/` as both JSON and Markdown, including:

- Round-by-round attack, patch, and referee verdicts
- Security score changes owned by the referee
- Remaining findings at the end of the run
- Capability matrices showing the current SQL injection and hardcoded-secret implementation plus extension points for XSS, command injection, and path traversal

When scanning a directory of repositories, YATA also prints a repository summary table with:

- Repository Name
- Vulnerabilities Found
- Patches Generated
- Verification Result
- Security Score

In `--safe` mode, patched repositories stay in temporary directories and the original source tree is never overwritten.

In `--apply` mode, YATA verifies the patch on a safe copy first and then applies only the verified file changes back to the original repository.
