# YATA

### Yet Another Threat Antagonist

> The Cybersecurity Ouroboros

An autonomous security agent that attacks a codebase, heals the vulnerabilities it proves, attacks its own remediations, and learns from every assessment.

Most security tools stop at detection.

YATA refuses to trust detection alone.

***A vulnerability is not accepted until YATA successfully exploits it.***

A patch is not accepted until YATA fails to break it.

**Attack. Heal. Attack Again. Learn.**

---

# Why YATA?

Traditional security workflows are fragmented.

```text
Scanner
   ↓
Find Vulnerability
   ↓
Developer Investigates
   ↓
Developer Creates Patch
   ↓
Developer Tests Patch
   ↓
Developer Validates Security
```

The remediation process remains largely manual.




YATA automates the complete offensive-to-defensive cycle.

```text
Repository
    ↓
HUNTER attacks
    ↓
Exploit succeeds
    ↓
HEALER repairs
    ↓
VALIDATOR attacks again
    ↓
Patch survives
    ↓
LEARNER remembers
```




Every remediation must survive an attack from YATA's own offensive engine before it is accepted.

---

# Core Agents

## HUNTER

Offensive security agent.

Responsibilities:

* Build attack paths
* Execute payloads
* Prove exploitability
* Confirm vulnerabilities

---

## HEALER

Defensive remediation agent.

Responsibilities:

* Generate secure patches
* Preserve functionality
* Apply minimal changes
* Produce validated fixes

---

## VALIDATOR

Adversarial validation agent.

Responsibilities:

* Re-run exploit chains
* Attack generated patches
* Verify exploit prevention
* Confirm remediation success

---

## LEARNER

Repository memory agent.

Responsibilities:

* Track assessment history
* Record vulnerability trends
* Track patch success rates
* Maintain repository knowledge

---

# Supported Vulnerabilities

| Vulnerability             | Exploit | Patch | Validate |
| ------------------------- | ------- | ----- | -------- |
| SQL Injection             | ✓       | ✓     | ✓        |
| Hardcoded Secret Exposure | ✓       | ✓     | ✓        |
| Command Injection         | ✓       | ✓     | ✓        |
| Path Traversal            | ✓       | ✓     | ✓        |

---

# Quick Start

## Clone Repository

```bash
git clone https://github.com/aarshnomorecool/yata.git
cd yata
```

## Create Virtual Environment

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Linux / macOS

```bash
python -m venv .venv
source .venv/bin/activate
```

## Install YATA

```bash
pip install -e .
```

## Verify Installation

```bash
yata version
```

Expected:

```text
YATA v0.8.1
```

---

# First Assessment

Run the demo:

```bash
yata --demo
```

Run against a repository:

```bash
yata assess test_repositories/repo5_mixed --safe
```

---

# Execution Modes

## SAFE

```bash
yata assess <repository> --safe
```

Creates validated patches without modifying original files.

Recommended mode.

---

## APPLY

```bash
yata assess <repository> --apply
```

Automatically applies validated remediations directly to the target repository.

---

## INTERACTIVE

```bash
yata assess <repository> --interactive
```

Requests user approval before patch application.

---

# Native CLI Commands

```bash
yata help
```

Show available commands.

```bash
yata assess <repository> --safe
```

Assess repository.

```bash
yata discover <path>
```

Discover repositories.

```bash
yata memory <repository>
```

View repository memory.

```bash
yata history <repository>
```

View assessment history.

```bash
yata report <repository>
```

Open latest report.

```bash
yata status
```

View platform statistics.

```bash
yata version
```

Display version information.

---

# Repository Memory

Every repository develops persistent security knowledge.

Stored under:

```text
.yata/memory/<repository>/memory.json
```

Tracked information:

* Assessment history
* Security scores
* Vulnerability trends
* Patch success rates
* Repository statistics

YATA does not simply assess repositories.

It remembers them.

---

# Reports

YATA generates:

### Terminal Reports

Rich CLI summaries.

### HTML Reports

Containing:

* Executive Summary
* Security Score Evolution
* Proven Exploits
* Generated Patches
* Validation Results
* Repository History
* Agent Metrics

---

# NVIDIA Assisted Mode

Default model:

```text
qwen/qwen3.5-122b-a10b
```

Configure:

```bash
cp .env.example .env
```

Add:

```text
NVIDIA_API_KEY=<your-key>
```

---

# Autonomous Fallback Mode

If no API key is available:

```text
LLM Requests = 0
```

YATA automatically switches to deterministic local engines.

No functionality is lost.

---

# Roadmap

### Completed

* SQL Injection
* Hardcoded Secret Exposure
* Command Injection
* Path Traversal
* Adversarial Validation
* Repository Memory
* Native CLI Installation
* HTML Reporting
* Multi Repository Assessment

### Planned

* Cross Site Scripting (XSS)
* SSRF
* Repository Discovery v2
* GitHub Pull Request Automation
* CI/CD Integration
* Watch Mode

---

# FAR AWAY 2026

Submitted under:

```text
Agentic & Autonomous Systems
```

YATA's core principle:

> A security agent is only as trustworthy as its ability to defeat itself.

Inspired by the Ouroboros, YATA attacks repositories, heals proven weaknesses, attacks its own remediations, and learns from every assessment.

**Attack. Heal. Attack Again. Learn.**

---

Built by Team Seasaw.
