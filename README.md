# YATA — Yet Another Threat Antagonist

> An autonomous agent that attacks your codebase, patches every vulnerability it finds, then tries to break its own fixes. No human required.

```
git clone <repository-url> && cd yata
pip install -r requirements.txt
python yata.py --demo
```

---

## What YATA Does

Most security tools find problems. YATA fixes them.

YATA runs three agents in an adversarial loop against your Python repository. HUNTER breaks in. HEALER patches the breach. VALIDATOR — running the same offensive configuration as HUNTER — tries to break the patch. The loop repeats until YATA cannot defeat itself.

```
HUNTER   →  finds and exploits weaknesses
HEALER   →  generates and applies secure patches
VALIDATOR  →  attacks the patched code
              ↓ if breakthrough → back to HEALER
              ↓ if blocked      → repository secured
```

When the run ends, your repository is either secure or YATA tells you exactly why it isn't.

---

## The Adversarial Loop

YATA does not scan and report. It attacks.

```
[HUNTER]    Evaluating attack paths...
              └─ SQL payloads loaded: 7
              └─ Trying payload 1/7 ... FAIL
              └─ Trying payload 2/7 ... FAIL
              └─ Trying payload 3/7 ... SUCCESS ✓
              └─ Payload: ' OR '1'='1

[HEALER]    Generating secure patch...
              └─ Vulnerability confirmed by HUNTER
              └─ Patch written → .yata/patches/login.py

[VALIDATOR] Attacking patched code...
              └─ Re-attempting SQL injection ... BLOCKED ✓
              └─ Security score: 23 → 91

YATA complete. Repository secured.
Human interventions: 0
```

Every finding is proven exploitable before a patch is generated. Every patch is attacked before it is accepted.

---

## Agents

| Agent | Role | Behaviour |
|---|---|---|
| HUNTER | Offensive | Aggressive. Tries every payload. Confirms exploitability before reporting. |
| HEALER | Defensive | Conservative. Writes minimal patches. Critiques its own output before committing. |
| VALIDATOR | Adversarial | Identical configuration to HUNTER. Attacks the patched code with fresh reasoning. |

HUNTER and VALIDATOR share the same offensive configuration. A patch does not pass until VALIDATOR — thinking exactly like HUNTER — cannot break it.

---

## Quick Start

**Clone and install:**
```bash
git clone <repository-url>
cd yata
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

**Run the demo (no API key required):**
```bash
python yata.py --demo
```

**Run against your own repository:**
```bash
python yata.py
```

Select a mode, provide a path, and YATA handles the rest.

---

## Modes

```
> SAFE          patched copy created, original untouched
  APPLY         verified patch applied directly to original
  INTERACTIVE   approve or reject each patch individually
```

All three modes run the full adversarial loop. The only difference is what happens to your files after a patch passes VALIDATOR.

---

## Workspace

Every scanned repository gets a `.yata/` directory:

```
your-repo/
└── .yata/
    ├── patches/        verified patch files
    ├── reports/        run reports (terminal + HTML)
    ├── scans/          findings.json with full attack history
    └── logs/           execution logs per run
```

`findings.json` stores every payload attempted, the winning payload, and the patch that blocked it. Nothing is discarded.

---

## Coverage

| Vulnerability | Detect | Exploit | Patch | Verify | OWASP |
|---|:---:|:---:|:---:|:---:|---|
| SQL Injection | ✅ | ✅ | ✅ | ✅ | A03:2021 · CWE-89 |
| Hardcoded Secrets | ✅ | ✅ | ✅ | ✅ | A02:2021 · CWE-798 |
| Command Injection | 🔜 | 🔜 | 🔜 | 🔜 | A03:2021 · CWE-78 |
| Path Traversal | 🔜 | 🔜 | 🔜 | 🔜 | A01:2021 · CWE-22 |

YATA covers full detect–exploit–patch–verify cycles. Detection without exploitation is not a finding.

---

## LLM Configuration

YATA uses `qwen/qwen3-next-80b-a3b-instruct` via NVIDIA NIM by default.

To enable it:
```bash
cp .env.example .env
# add your NVIDIA API key
```

If no key is present, YATA falls back to deterministic local behaviour automatically. Demo mode requires no configuration.

---

## Roadmap

- [x] SQL Injection
- [x] Hardcoded Secrets
- [x] Multi-payload attack library
- [x] Adversarial validation loop
- [x] Workspace architecture
- [x] Demo mode
- [ ] Command Injection
- [ ] Path Traversal
- [ ] Cross-Site Scripting
- [ ] Repository memory and learning
- [ ] GitHub PR automation

---

## FAR AWAY 2026

YATA is submitted under the **Agentic & Autonomous Systems** theme.

The core claim: a security agent that is only as trustworthy as its ability to defeat itself. YATA does not accept a patch until its own offensive reasoning cannot break it.

---

*Built by Team Seasaw.*
