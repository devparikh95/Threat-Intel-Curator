# Autonomous Threat Intel Curator

A multi-agent SOC briefing system that turns the daily flood of threat intelligence into a ranked, stack-relevant **Threat Hunt Briefing** — safely.

Built with **ADK 2.0** (scaffolded via `agents-cli`), an **MCP server** for external tools, and **Gemini** models, with a security-first design that treats all ingested intel as untrusted.

> Kaggle × Google — AI Agents Intensive Vibe Coding Capstone · Track: Agents for Business

---

## Problem

An in-house SOC at a large company can't keep up with the volume of new threat intel — new CVEs, vendor advisories, research write-ups, and campaign reports appear faster than anyone can find and read them, and most of it is irrelevant to the organization's actual technology. The real question ("is this something *our* stack is exposed to, and could we even detect it?") is slow and error-prone to answer by hand, and getting it wrong causes both missed threats and wasted hours.

## Solution & what it does

The Curator runs once a day, ingests intel from NVD, RSS feeds, and GitHub, reasons about relevance against a configured tech stack, verifies its facts against authoritative records, and produces a single ranked briefing. Each actionable threat comes with why it matters to *this* environment, 2–3 KQL + 2–3 Sigma hunt queries, and hit/miss interpretation guidance. Anything that looks like a prompt-injection attempt is quarantined to a human-review lane before any LLM sees it. Nothing is auto-deployed — every query is a hunting lead for a human analyst.

**Sample briefing output** (`briefings/YYYY-MM-DD.md`):

```markdown
# Threat Hunt Briefing — 2026-07-06
> Monitored Threat Advisories: 3   |   Actionable Threats Identified: 2

## 🎯 ACTIONABLE THREAT HUNTS
### 1. Palo Alto Networks PAN-OS Remote Code Execution (CVE-2099-90001)
- Relevance Reason: Deterministic match: Product 'pan-os' matched CPE prefix 'cpe:2.3:o:paloaltonetworks:pan-os'
- Grounding: Could not independently verify against NVD (404). Severity/CPE shown are UNVERIFIED source claims.
- Query Validation: Passed
  #### Hunt Queries
  **KQL:** DeviceNetworkEvents | where RemoteIP == '<FIREWALL_IP>' | where RemotePort in (22,3389,...)
  **Sigma:** title: PAN-OS Outbound Anomalous Firewall Traffic ...

## 🛡️ SECURITY REVIEW & QUARANTINE LANE
### ⚠️ QUARANTINED: Benign Threat Advisory with Hidden Injection Payload (RED-TEAM-001)
- Quarantine Reason: Matched suspicious pattern: '(?i)ignore\s+...previous...instructions?'
```

## Architecture

A dynamic, code-orchestrated ADK workflow. One coordinator ingests the day's items, then routes each one per-item: a **plain code check** (does it carry a CPE/CVE?) decides between a deterministic filter and an LLM judgment call. LLM nodes are used **only** where genuine reasoning is required.

```
                    ┌──────────────────────────────┐
                    │  CONFIG (read at startup)     │
                    │  config/stack_profile.yaml    │
                    │  config/sources.yaml          │
                    └──────────────────────────────┘
                                   │
   ┌──────────────┐               ▼
   │  MCP SERVER  │        ┌──────────────────┐
   │  - nvd_query │◄───────┤ 1. INGESTION     │  code
   │  - fetch_rss │        │    (snapshot/live)│
   │  - fetch_url │        └──────────────────┘
   │  - github…   │               │
   └──────────────┘               ▼
                          ┌──────────────────┐
                          │ 2. SECURITY      │  PRE-LLM SCREEN
                          │    SCREEN        │  quarantine injected items
                          └──────────────────┘
                                   │
                         ┌─────────┴─────────┐
                         ▼ (CPE match?)      ▼ (no CPE / TTP-only)
                ┌──────────────────┐  ┌──────────────────┐
                │ 3. STACK-MATCH   │  │ 4. RELEVANCE     │  LLM
                │    FILTER (code) │  │    ANALYZER      │
                └──────────────────┘  └──────────────────┘
                         └─────────┬─────────┘
                                   ▼
                          ┌──────────────────┐
                          │ 5. NVD GROUNDING │  code + API (anti-hallucination)
                          └──────────────────┘
                                   ▼
                          ┌──────────────────┐
                          │ 6. HUNT-GUIDE    │  LLM (KQL + Sigma + why-it-matters)
                          │    GENERATOR      │
                          └──────────────────┘
                                   ▼
                          ┌──────────────────┐
                          │ 7. CRITIC        │  LLM (validate + self-correct queries)
                          └──────────────────┘
                                   ▼
                          ┌──────────────────┐
                          │ 8. BRIEFING      │  code (rank + render)
                          │    ASSEMBLER      │
                          └──────────────────┘
                                   ▼
                          briefings/YYYY-MM-DD.md
```

| # | Node | LLM? | Responsibility |
|---|------|------|----------------|
| 1 | Ingestion | No | Pull + normalize items (frozen snapshot or live NVD/RSS/GitHub via MCP tools) |
| 2 | Security screen | No | Trust boundary — quarantine prompt-injection attempts before any LLM |
| 3 | Stack-match filter | No | Deterministic CPE/product match against the stack profile |
| 4 | Relevance analyzer | **Yes** | For non-CPE items: reason about TTP relevance + detectability |
| 5 | NVD grounding | No | Independently verify CVE facts against the authoritative NVD record |
| 6 | Hunt-guide generator | **Yes** | Produce threat context, why-it-matters, KQL + Sigma queries, hit/miss guidance |
| 7 | Critic | **Yes** | Validate query syntax; self-correct malformed queries; degrade gracefully |
| 8 | Briefing assembler | No | Rank (stack-match > severity) and render the dated markdown briefing |

---

## Setup

**Prerequisites:** [Python 3.11+](https://www.python.org/) and [uv](https://docs.astral.sh/uv/getting-started/installation/) (Python package manager).

```bash
# 1. Clone
git clone <YOUR_REPO_URL>
cd threat-intel-curator

# 2. Install dependencies into a local virtual environment
uv sync

# 3. Configure secrets
cp .env.example .env
#   then edit .env and set your key(s):
#     GEMINI_API_KEY   (required — get one at https://aistudio.google.com/apikey)
#     NVD_API_KEY      (optional — raises NVD rate limits)
#     GITHUB_TOKEN     (optional — raises GitHub rate limits, live mode only)
```

`.env` is gitignored and never committed; only `.env.example` (placeholders) is in the repo.

## How to run the demo

One command runs the full pipeline over the frozen snapshot (`data/snapshot/items.json`) and writes a dated briefing:

```bash
uv run python run.py
```

Output lands in **`briefings/YYYY-MM-DD.md`**. The snapshot contains a CPE-matched CVE, a TTP-only phishing item, and a seeded **red-team injection item** — so a single run demonstrates deterministic matching, LLM relevance reasoning, grounding, hunt-guide generation, and the security quarantine all at once.

To run against live feeds instead of the snapshot (needs network + keys):

```bash
uv run python run.py live
```

**Run the tests:**

```bash
uv run pytest tests/unit -q      # 25 unit tests covering every node
```

> Note: `tests/integration` and `tests/load_test` are scaffold-generated and require GCP credentials / `locust`; they are not part of the core project and can be skipped.

## Security note

The system ingests attacker-influenceable content (blogs, CVE text, GitHub READMEs), so it is designed to resist **detection-as-code poisoning via prompt injection**. Four layered controls:

1. **Pre-LLM injection screen** — all fetched text is scanned before any model sees it; suspicious items are quarantined to a human-review lane ([`src/security/injection_guard.py`](src/security/injection_guard.py)).
2. **Trust boundary** — untrusted text is always wrapped in a delimited data envelope inside prompts, never placed in instruction position ([`config/prompts.yaml`](config/prompts.yaml)).
3. **Independent NVD grounding** — CVE facts are verified against the authoritative record; unverifiable claims are flagged, never fabricated ([`src/agent/nodes/grounding.py`](src/agent/nodes/grounding.py)).
4. **No auto-deploy** — every generated query is a human-reviewed hunting lead, not a live rule.

The guard is proven by [`tests/unit/test_injection_guard.py`](tests/unit/test_injection_guard.py), and the seeded `RED-TEAM-001` snapshot item shows it catching a real injection payload end-to-end.

## Roadmap & limitations

**Limitations (honest scope):**
- The demo runs over a **frozen snapshot** for reproducibility; live mode is implemented but lightly exercised.
- The injection screen is regex-based — a strong first line, but layered with the architectural controls above rather than relied on alone.
- Snapshot CVE IDs are intentionally fictional (`CVE-2099-…`) so they can't collide with real NVD records; grounding correctly reports them as *Unverified*.
- Both LLM nodes run on `gemini-2.5-flash` (configurable per node in `stack_profile.yaml`); LLM nodes require a valid API key and will error rather than silently degrade.

**Roadmap:**
- Deliver briefings where analysts work (email / Slack / ticketing) and schedule a daily 6 AM run (cron / Agent Runtime).
- Add deduplication + a persistence layer and cache NVD/LLM calls for cost and idempotency.
- Integrate as a module in a larger multi-agent AI-SOC platform, where an agent turns each surfaced vulnerability into tested detection-as-code (Sigma → Splunk SPL / Sentinel), closing the loop from intel to automated hunt.

---

## Repository layout

```
threat-intel-curator/
├── run.py                      # ← single-command demo entrypoint
├── config/                     # stack_profile.yaml, sources.yaml, prompts.yaml
├── data/snapshot/items.json    # frozen demo intel (incl. red-team item)
├── src/
│   ├── agent/
│   │   ├── graph.py            # ADK workflow: routing + orchestration
│   │   ├── state.py            # IntelItem / HuntGuide schemas
│   │   ├── nodes/              # the 8 pipeline nodes
│   │   └── utils/              # llm client, prompt loader, logging
│   ├── mcp/server.py           # MCP server: nvd_query, fetch_rss, fetch_url, github_search
│   └── security/injection_guard.py
├── tests/unit/                 # 25 unit tests
├── scratch/demo_critic.py      # standalone critic self-correction demo
└── briefings/                  # output: YYYY-MM-DD.md
```
