# CLAUDE.md

This file is read by Claude Code at the start of every session in this repo. It exists so you do not have to re-derive the architecture, re-guess naming conventions, or accidentally rebuild something that already works. Read this fully before touching any file.

---

## 1. What This Project Is

YATA (Yet Another Threat Antagonist) is an autonomous security agent split into two halves:

- **YATA** (development side) — scans source code, proves vulnerabilities are exploitable via live attacks, generates patches, and attacks its own patches before accepting them.
- **RECON** (deployment side) — does the same job against a live, deployed application instead of source code. Not built yet. See Section 4.

The single non-negotiable design principle: **a patch is never accepted because it looks correct. It is accepted only when the system's own offensive logic, attacking with real payloads, fails to break it.** Every feature you build must respect this. If you are ever asked to add a shortcut that accepts a patch without VALIDATOR (or MUTATOR) attacking it first, push back and flag it instead of just doing it.

---

## 2. Current State — What Already Exists

Do not rewrite these files from scratch. Read them first, understand the existing patterns, and extend them. The codebase is at roughly v0.8.2 equivalent functionality described below.

```
yata.py              Main entry point. CLI orchestration, mode handling
                      (SAFE / APPLY / INTERACTIVE / DEMO), the round loop
                      that runs HUNTER -> HEALER -> VALIDATOR, Rich terminal
                      output, workspace initialization.

red_agent.py          HUNTER. Contains:
                        - VulnerabilityDetector base class
                        - SQLInjectionDetector, HardcodedSecretDetector
                          (AST-based, walk the tree, do not regex)
                        - RedAgent class: scan(), prioritize(), plan_attack(),
                          get_payloads_for_finding()
                        - VulnerabilityFinding and AttackPlan dataclasses

blue_agent.py          HEALER. Contains:
                        - PatchStrategy base class with apply_source(),
                          is_safe(), apply_auxiliary_updates(), build_summary(),
                          fallback_guidance()
                        - SQLInjectionPatchStrategy, HardcodedSecretPatchStrategy
                        - BlueAgent class: generate_patch() (always works on a
                          sandboxed copy, never touches the original repo)
                        - PatchResult dataclass

verifier.py            VALIDATOR (class is literally named Referee, with
                        Verifier = Referee as an alias, keep that alias).
                        Contains:
                        - RISK_WEIGHTS dict per vulnerability type
                        - verify_exploit() dispatches to _verify_sql_injection,
                          _verify_hardcoded_secret etc. by naming convention
                          _verify_<snake_case_vuln_type>
                        - Loads the target app via importlib and actually runs
                          it with Flask's test_client(). This is REAL runtime
                          verification, not a static check. Never replace this
                          with a static "does the pattern look fixed" check.
                        - calculate_security_score(), record_round()

attack_library.py      AttackLibrary class. get_payloads(vulnerability_type,
                        winning_payload) returns an ordered payload list.
                        Currently a flat dict. LEARNER will need to reorder
                        this per repository (see Module 2 below), so keep
                        the payload source and the ordering logic separable.

llm_client.py          LLMClient class. Wraps NVIDIA NIM via the OpenAI SDK
                        compatibility layer. DEFAULT_MODEL is currently
                        qwen/qwen3-next-80b-a3b-instruct. Has a
                        MODEL_FALLBACKS dict for deprecated models. generate()
                        always needs a fallback_text argument and degrades
                        gracefully to that text if no API key is present or
                        the call fails. This fallback path must always keep
                        working with zero configuration.

report_generator.py    ReportGenerator class (will become REPORTER, see
                        Module 4). VULNERABILITY_MAPPING dict maps vuln type
                        to OWASP id, CWE id, impact, severity. Currently
                        outputs JSON and Markdown. HTML output and merging
                        in RECON findings are not built yet.

test_repositories/      repo1_login_sqli, repo2_search_sqli, repo3_admin_sqli,
                        repo4_hardcoded_secret, repo5_mixed,
                        repo6_command_injection, repo7_path_traversal.
                        Each has app.py (a small Flask app with one seeded
                        vulnerability) and yata_profile.json (tells VALIDATOR
                        how to route the payload: method, path, params dict
                        with a __PAYLOAD__ placeholder, success_contains,
                        success_status_code).

.env.example            NVIDIA_API_KEY, YATA_LLM_MODEL, NVIDIA_API_BASE_URL
```

Workspace layout (already implemented, keep it centralized, never write inside the target repo unless the user explicitly picked APPLY mode):

```
.yata/
  patches/<repo_name>/<file>
  reports/<repo_name>/...
  analysis/<repo_name>/security_assessment.json
  logs/<repo_name>/run_<date>.log
  memory/<repo_name>/memory.json      (LEARNER, see Module 2)
```

Agent temperature configuration already decided and load-bearing for the whole design story, do not change without a strong reason:

```
HUNTER      temperature 0.9   (aggressive, creative payload selection)
HEALER      temperature 0.2   (conservative, precise patch generation)
VALIDATOR   temperature 0.9   (identical config to HUNTER, this is the point)
```

---

## 3. Build Order — Work Through These In Sequence

Do not jump ahead to a later module because it sounds more interesting. Each module assumes the previous one is solid. If you are asked to add something from Module 4 while Module 2 still has gaps, finish Module 2 first or explicitly flag the ordering conflict.

### Module 1 — Core Foundation (mostly done, finish these gaps)
- [ ] Repository discovery: `yata discover <path>` should recursively find every folder under `<path>` that looks like a repo (has `app.py` or `yata_profile.json`) and assess all of them. Multi-repo summary table already exists in `yata.py`, reuse it.
- [ ] Fix the LLM system prompts in `red_agent.py` and `blue_agent.py` that may still literally say "You are the RED agent" / "You are the BLUE agent" instead of HUNTER / HEALER. Grep for this before doing anything else, it is an embarrassing inconsistency if left in.
- [ ] Confirm `red_agent.py`'s LLM calls actually pass `temperature=0.9` explicitly. Do not rely on the client default.
- [ ] Add `python-dotenv` to `requirements.txt` if `test_nvidia.py` or anything else imports it and it is missing.

### Module 2 — Adversarial Patch Generation and MUTATOR
- [ ] Add MUTATOR as a genuinely new agent, not a rename of anything existing. New file: `mutator_agent.py`.
  - MUTATOR's job, scoped tightly: after VALIDATOR confirms a patch blocks the *original* winning payload, MUTATOR generates a small number of mutated variants of that payload (encoding tricks, case changes, alternate syntax that achieves the same attack class) and re-runs VALIDATOR against each variant. If any variant gets through, the patch is rejected and sent back to HEALER, same as a normal VALIDATOR failure.
  - MUTATOR temperature: high, around 0.9 to 1.0, since the entire point is creative variation.
  - MUTATOR does **not** generate patch variants in this module. That is a separate, much larger idea (see YATA-X in Section 5, explicitly out of scope right now). Keep MUTATOR's v1 scope to payload mutation only.
  - Cap the number of mutation attempts per finding (start with 3 to 5) so a single vulnerability cannot loop forever.
- [ ] Extend `verifier.py`'s round loop (currently in `yata.py`) so that after VALIDATOR passes, MUTATOR runs automatically before the round is marked complete. Update the round report structure to include a `mutation_attempts` list.
- [ ] Command Injection and Path Traversal already have full detect-exploit-patch-verify cycles per the file list above; if they do not yet exist when you start, build them following the exact same four-part pattern as SQL Injection (detector class, attack payloads in `attack_library.py`, patch strategy class, `_verify_command_injection` / `_verify_path_traversal` methods). Do not build a partial version of a vulnerability class. Detection without exploitation and patching without validation are both explicitly forbidden, see Section 6.

### Module 3 — Multi-Language Support and RECON
- [ ] Multi-language detection is a real architectural change, not a small patch. `VulnerabilityDetector` currently assumes Python AST. Before writing any JS/Java/PHP/Go detector, first refactor `red_agent.py` so detectors are pluggable per language (a `language` attribute on each detector, and a file-extension-to-language dispatch in `RedAgent.scan()`). Do this refactor as its own step, do not bolt a second language onto the existing Python-only assumptions.
- [ ] RECON is a new top-level module, not a modification of `red_agent.py`. Suggested structure:
  ```
  recon/
    __init__.py
    scanner.py       endpoint discovery, reconnaissance
    exploiter.py      live exploitation against a running target
    profile.py        equivalent of yata_profile.json but for a live URL
                       instead of a local Flask app
  ```
  RECON talks to a live HTTP target directly with `requests`, it does not use `importlib` to load a Flask app the way `verifier.py` does, because in RECON's case there usually is no local source to import.
- [ ] Dual LLM / AI Router: add a `provider` argument to `LLMClient` (or a thin router class in front of it) so YATA-Dev agents (HUNTER, HEALER, VALIDATOR, MUTATOR) use one configured model and RECON uses a separate one. Keep this a simple routing decision (which client instance to call), do not over-engineer a generic multi-model abstraction layer before there is a second real use case.
- [ ] RECON findings must flow into the same REPORTER output as YATA-Dev findings (see Module 4). Do not build a separate report format for RECON.

### Module 4 — Learning, Memory, and Reporting
- [ ] LEARNER: new file `learner_agent.py`. Reads and writes `.yata/memory/<repo>/memory.json`. Minimum schema: `total_assessments`, `winning_payloads` (per vuln type), `patch_history` (per vuln type, success/fail), `vulnerabilities_seen`, `score_history`, `best_score`.
  - Before HUNTER sequences payloads from `attack_library.py`, LEARNER should get a chance to reorder that list, putting previously-winning payloads first. Wire this in as an explicit step, do not silently mutate `AttackLibrary`'s internal state.
  - LEARNER makes no LLM calls. It is pure file I/O and simple logic. Keep it that way, it needs to be fast and deterministic.
- [ ] REPORTER: promote `report_generator.py` into the actual REPORTER agent. Add an HTML output alongside the existing JSON and Markdown. The HTML report needs to be able to show findings from both YATA-Dev and RECON in one place once Module 3 exists, so design the report data model now with a `source: "yata" | "recon"` field on each finding even before RECON produces any real data.
- [ ] GitHub integration and OWASP expansion (XSS, SSRF, Insecure Deserialization, Weak Crypto) belong in this module. Each new vulnerability class must ship with the full four-part cycle, same rule as Module 2.

### Module 5 — Long-Term Vision, Do Not Start
See Section 5. Nothing in this module should be touched until Modules 1 through 4 are solid and demonstrated working end to end.

---

## 4. Explicitly Out of Scope Right Now

These are real ideas that have been discussed and are part of the long-term roadmap, but building them now would be premature and would come at the expense of finishing the fundamentals. If a request comes in that sounds like one of these, flag it rather than quietly building a half version.

- **YATA-X Mutation Engine.** This is a much bigger idea than MUTATOR (Module 2). YATA-X would search across *many* candidate patches, not just re-attack one patch with mutated payloads, evolving toward the "most hardened" version of a fix over multiple generations. Do not confuse this with MUTATOR. MUTATOR mutates the attack. YATA-X (not built) would mutate the patch itself, repeatedly, as a search process.
- **Autonomous Red Team** (full attack chains: find a foothold, escalate privileges, move laterally, reach an objective across multiple files or services).
- **Digital Immune System** (one repository's learned attack knowledge automatically protecting a different, unrelated repository).
- **Security Knowledge Graph** (files, functions, endpoints, secrets, and dependencies modeled as a connected graph for structural reasoning).
- **Security Copilot Mode** (conversational "why was this patched" queries against LEARNER's memory).
- **Predictive Security** (forecasting future vulnerabilities from repository structure before they are written).
- **Global Memory Network** (cross-organization, anonymized attack pattern sharing).

None of these have a file structure decided yet on purpose. Do not scaffold empty folders for them.

---

## 5. Golden Rules

These are constraints that have already caused real confusion once and are written down so they do not happen again.

1. **VALIDATOR (and once built, MUTATOR) is the source of truth.** A patch is never marked accepted based on HEALER's own confidence, an LLM saying "this looks correct," or a static pattern check. It is accepted only after a live re-exploitation attempt fails.
2. **Every vulnerability class needs the full four-part cycle before it counts as done:** detector, exploit payloads plus live verification, patch strategy, and a `_verify_<type>` method that actually runs the attack again against the patched code. A detector with no patch strategy, or a patch strategy with no verification, is not a shippable feature, it is half of one.
3. **Test repositories stay vulnerable in version control.** Never commit a patch into `test_repositories/`. YATA always works on a sandboxed copy unless the user explicitly runs APPLY mode against their own repository, not the test fixtures.
4. **Autonomous Fallback Mode must always work with zero API key.** Every LLM-touching code path needs a deterministic, rule-based fallback that produces a usable (if less nuanced) result. Do not add a feature that hard-requires the NVIDIA API to function at all, even in a degraded form.
5. **Workspace artifacts are centralized under `.yata/`, never written inside the scanned repository**, except the one specific case of APPLY mode intentionally modifying the user's own source files.
6. **Naming stays consistent with the six-agent model:** HUNTER, HEALER, VALIDATOR, MUTATOR, LEARNER, REPORTER. Do not introduce a seventh top-level agent without updating this file. If a new capability seems to need its own agent, first check whether it actually belongs inside one of the six.

---

## 6. Tech Stack

```
Python 3.11
Flask >=3.0,<4.0            test target apps, verifier.py's Flask test_client
rich >=13.7,<14.0             terminal UI
InquirerPy >=0.3.4            interactive CLI mode selection
requests >=2.31,<3.0          HTTP fallback, RECON's HTTP layer
openai >=2.41,<3.0            NVIDIA NIM API compatibility
python-dotenv                 .env loading (add if missing, see Module 1)
```

LLM: NVIDIA NIM, default model `qwen/qwen3-next-80b-a3b-instruct`, configured through `.env` (`NVIDIA_API_KEY`, `YATA_LLM_MODEL`, `NVIDIA_API_BASE_URL`). Offline deterministic fallback is mandatory, see Golden Rule 4.

---

## 7. CLI Reference

```
yata assess <repo> --safe            patched copy only, original untouched (default, recommended)
yata assess <repo> --apply           verified patch applied directly to the original repo
yata assess <repo> --interactive     user approves or rejects each patch
yata --demo                          runs against a bundled vulnerable repo, zero config needed
yata discover <path>                 find and list all assessable repos under a directory (Module 1)
yata memory <repo>                   show LEARNER state for a repo (Module 4)
yata history <repo>                  show security score evolution across runs (Module 4)
yata report <repo>                   open the latest report
yata status                          show provider status, workspace summary
```

---

## 8. Before You Write Any Code

1. Read the existing file for the area you are touching, in full, before editing. This codebase has established patterns (dataclasses for findings/results, strategy classes for detectors and patchers, naming convention `_verify_<snake_case_type>` for verifier dispatch). Match them, do not introduce a parallel style.
2. If you are adding a new vulnerability class, copy the shape of the SQL Injection implementation across all four files (`red_agent.py`, `blue_agent.py`, `verifier.py`, `attack_library.py`) rather than inventing a new pattern.
3. If a task spans more than one module from Section 3, say so before starting, and confirm which module takes priority.
4. When in doubt about whether something belongs in Module 2, Module 5, or is out of scope entirely, re-read Section 4 before writing code.
