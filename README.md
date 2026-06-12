# YATA — Yet Another Threat Antagonist

> An autonomous cybersecurity agent that discovers vulnerabilities, proves exploitability, generates patches, attacks its own fixes, and learns from every assessment.

```bash
git clone aarshnomorecool/yata.git
cd yata

python -m venv .venv

# Windows
.venv\Scripts\activate

pip install -e .

yata --demo
```

---

## What is YATA?

YATA (Yet Another Threat Antagonist) is an autonomous security assessment and remediation platform.

Unlike traditional scanners that stop at detection, YATA executes a complete offensive-to-defensive security workflow:

```text
Discover Vulnerability
        ↓
Prove Exploitability
        ↓
Generate Patch
        ↓
Apply Patch
        ↓
Attack Patch
        ↓
Validate Security
        ↓
Learn & Remember
```

A vulnerability is not considered real until YATA proves it can exploit it.

A patch is not considered secure until YATA fails to break it.

---

## Core Agents

### HUNTER

Offensive security agent.

Responsibilities:

- Discover vulnerabilities
- Build attack paths
- Execute payloads
- Prove exploitability

---

### HEALER

Defensive remediation agent.

Responsibilities:

- Generate secure patches
- Apply minimal code changes
- Preserve functionality
- Produce validated fixes

---

### VALIDATOR

Adversarial validation agent.

Responsibilities:

- Re-run exploit chains
- Attack generated patches
- Verify exploit prevention
- Confirm remediation success

---

### LEARNER

Repository memory agent.

Responsibilities:

- Track assessment history
- Record vulnerability trends
- Track patch success rates
- Maintain repository knowledge

Repository memory is stored locally:

```text
.yata/memory/
```

---

## Assessment Workflow

```text
HUNTER
  ↓
HEALER
  ↓
VALIDATOR
  ↓
LEARNER
```

Security Score:

```text
Before Assessment
      ↓
Vulnerabilities Found
      ↓
Patches Generated
      ↓
Validation Passed
      ↓
Score Updated
```

---

## Supported Vulnerabilities

| Vulnerability             | Detect | Exploit | Patch | Validate |
| ------------------------- | ------ | ------- | ----- | -------- |
| SQL Injection             | ✓      | ✓       | ✓     | ✓        |
| Hardcoded Secret Exposure | ✓      | ✓       | ✓     | ✓        |
| Command Injection         | ✓      | ✓       | ✓     | ✓        |
| Path Traversal            | ✓      | ✓       | ✓     | ✓        |

---

## Execution Modes

### SAFE

```bash
yata assess <repository> --safe
```

- Creates patched copies
- Original files untouched
- Recommended mode

---

### APPLY

```bash
yata assess <repository> --apply
```

- Applies validated patches directly
- Updates repository files

---

### INTERACTIVE

```bash
yata assess <repository> --interactive
```

- Requests approval before patching
- Human-in-the-loop workflow

---

## Native CLI Commands

### Assess Repository

```bash
yata assess <repository> --safe
```

---

### Discover Repositories

```bash
yata discover <path>
```

---

### Repository Memory

```bash
yata memory <repository>
```

---

### Assessment History

```bash
yata history <repository>
```

---

### Latest Report

```bash
yata report <repository>
```

---

### Platform Status

```bash
yata status
```

---

### Version

```bash
yata version
```

---

### Help

```bash
yata help
```

---

## Repository Discovery

YATA can automatically discover repositories within a workspace.

Example:

```bash
yata discover test_repositories
```

Output:

```text
repo1_login_sqli
repo2_search_sqli
repo3_admin_sqli
repo4_hardcoded_secret
repo5_mixed
repo6_command_injection
repo7_path_traversal
```

---

## Repository Memory

Each repository develops a persistent security history.

Stored under:

```text
.yata/memory/<repository>/memory.json
```

Tracked metrics:

- Total Assessments
- Best Security Score
- Last Security Score
- Vulnerabilities Seen
- Successful Patches
- Failed Patches
- Assessment Timeline

---

## Reports

YATA generates:

### Terminal Reports

Rich CLI summaries.

### HTML Reports

Containing:

- Executive Summary
- Security Score Evolution
- Vulnerabilities Found
- Exploits Proven
- Patches Applied
- Validation Results
- Timeline
- Agent Status
- Metrics
- Repository History

---

## Demo Mode

No API key required.

```bash
yata --demo
```

Demonstrates:

- SQL Injection
- Hardcoded Secret Exposure
- Autonomous Patch Generation
- Validation Loop
- Repository Memory

---

## NVIDIA Assisted Mode

Default model:

```text
qwen/qwen3-next-80b-a3b-instruct
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

## Autonomous Fallback Mode

If no API key is available:

```text
LLM Requests = 0
```

YATA automatically switches to deterministic local engines.

No functionality is lost.

---

## Current Roadmap

### Completed

- ✓ SQL Injection
- ✓ Hardcoded Secret Detection
- ✓ Command Injection
- ✓ Path Traversal
- ✓ Adversarial Validation
- ✓ Repository Memory
- ✓ Git-Style Commands
- ✓ Native CLI Installation
- ✓ HTML Reporting
- ✓ Multi-Repository Assessment

### Planned

- Repository Discovery v2
- Assess-All Workspaces
- Cross-Site Scripting (XSS)
- SSRF
- Watch Mode
- GitHub Pull Request Automation

---

## FAR AWAY 2026

Submitted under:

```text
Agentic & Autonomous Systems
```

YATA's core principle:

> A security agent is only as trustworthy as its ability to defeat itself.

Every patch must survive an attack from YATA's own offensive engine before it is accepted.

---

Built by Team Seasaw.
<img width="1119" height="627" alt="image" src="https://github.com/user-attachments/assets/915f5152-1ee8-4068-95ea-77d3b8da3bf3" />
