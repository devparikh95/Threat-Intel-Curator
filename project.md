# project.md — Autonomous Threat Intel Curator

> **Capstone:** Kaggle × Google — AI Agents: Intensive Vibe Coding Capstone Project
> **Track:** Agents for Business
> **Author:** Dev
> **Status:** Build spec + deliverable drafts

---

## HOW TO USE THIS FILE

This is the master document for the whole capstone.

- **Sections 1–7 are the build spec.** This is what you point Antigravity at. Build phase by phase (Section 7). Don't ask Antigravity to build everything at once — feed it one phase at a time and review each before moving on.
- **Sections 8–9 are your deliverables** (video outline, writeup skeleton). These are for you, not for Antigravity to execute. They're in this file so the build stays aligned to how the project will be *communicated and graded*.
- **Section 10 is the grading map** — keep referring back to it so you don't over- or under-build.

**Two rules to keep repeating to Antigravity:**
1. Use `agents-cli` to scaffold the ADK 2.0 project structure. Do NOT hand-roll the project layout — generate idiomatic ADK 2.0 graph-workflow code from the scaffold.
2. Never hardcode API keys. Everything sensitive goes through environment variables and `.env` (which is gitignored). `.env.example` is committed with placeholder names only.

> Note on ADK specifics: this spec describes *intent and node responsibilities*. The exact ADK 2.0 graph API, state object, and node signatures should come from the `agents-cli` scaffold and the course codelabs — let Antigravity generate idiomatic code against those, and verify against the Day 3 (multi-agent) and Day 2 (MCP) codelabs rather than inventing API shapes.

---

## 1. PROBLEM

SOC analysts are drowning in threat intelligence. New CVEs, vendor advisories, research blogs, and malware/phishing campaign writeups appear faster than any human can read them — and the overwhelming majority are irrelevant to any given organization's actual technology stack. The work of "is this new threat something *we* could even be hit by, and could we even *see* it in our logs?" is slow, manual, repetitive, and easy to get wrong under volume.

The cost of getting it wrong runs both ways: miss a relevant threat and you have a coverage gap; chase an irrelevant one and you burn analyst hours that should go to real investigations.

**The job to be done:** every morning, an analyst should walk in to a short, trustworthy briefing of *only the threats that matter to our stack*, each one accompanied by ready-to-run hunt queries so they can immediately go look for it — not a deploy-ready rule (which an LLM can't responsibly produce without the live environment), but a **hunt guide** that gives them a lead and tells them what a hit or miss means.

## 2. SOLUTION

**Autonomous Threat Intel Curator** — a multi-agent system that runs once daily (target: 6:00 AM, before shift), ingests threat intel from authoritative and community sources, reasons about relevance against a defined org tech stack, verifies its facts against authoritative sources, and produces a daily **Threat Hunt Briefing**: a ranked set of hunt guides, each containing the threat/TTP context, *why it matters to this specific stack*, 2–3 KQL and Sigma hunt queries, and hit/miss interpretation guidance.

**What it is NOT (scope discipline — keep telling Antigravity this):**
- It does **not** auto-deploy detection rules. Analyst-in-the-loop by design.
- It does **not** scrape X/Twitter. (No reliable free API, low signal, high noise.)
- It does **not** need a live public deployment for grading (see Section 10). Build a reproducible local run.
- It does **not** try to cover every feed. One feed-type done well (NVD) + a small set of RSS sources + GitHub PoC lookup. Depth over breadth.

## 3. WHY AGENTS (this is central — judged under "use of agents must be clear, meaningful, and central")

A naive version of this is a glorified RSS reader: fetch feeds, summarize, print. That is not agentic and would score poorly.

The agentic value is in **judgment**, expressed as two distinct relevance funnels plus grounded fact-checking:

1. **Asset-driven relevance (deterministic):** does the advisory's affected product (CPE / vendor / product string) match the org's stack? This is *code*, not an LLM — fast, exact, cheap.
2. **Technique-driven relevance (judgment → LLM):** a new phishing kit or malware loader has no CPE. The only way to assess it is to read the report, extract the TTPs (map to MITRE ATT&CK where possible), and *reason about detectability*: given our log sources (EDR, firewall, cloud), could we plausibly see this? That is genuine judgment — the core reason this is an agent.
3. **Grounded generation:** for each relevant item, generate hunt queries and explain *why this threat matters to this stack* — synthesis that requires reasoning over the threat + the environment together.

The design principle (straight from the course's own pattern): **code-based routing where the decision is deterministic, LLM nodes only where judgment is genuinely needed.** This keeps it cheap, fast, and defensible.

## 4. ARCHITECTURE

ADK 2.0 graph workflow. State flows through the graph as a list of intel items, each accumulating annotations (relevance verdict, grounding status, generated hunt guide) as it passes through nodes.

```
                    ┌─────────────────────────────────────────────┐
                    │         CONFIG (read at startup)             │
                    │  config/stack_profile.yaml                   │
                    │  config/sources.yaml                         │
                    └─────────────────────────────────────────────┘
                                      │
        ┌─────────────────┐          ▼
        │  MCP SERVER     │   ┌──────────────────┐
        │  (tools)        │◄──┤ 1. INGESTION     │  code, no LLM
        │  - nvd_query    │   │   (Fetcher)      │  pulls raw items via MCP tools
        │  - fetch_rss    │   └──────────────────┘
        │  - fetch_url    │          │
        │  - github_search│          ▼
        └─────────────────┘   ┌──────────────────┐
                              │ 2. SECURITY      │  PRE-LLM SCREEN (the security pillar)
                              │    SCREEN        │  isolate + scan untrusted text BEFORE
                              │    (guard)       │  any LLM sees it; quarantine injected items
                              └──────────────────┘
                                      │
                            ┌─────────┴─────────┐
                            ▼ (CPE match?)      ▼ (no CPE / TTP-only)
                   ┌──────────────────┐  ┌──────────────────┐
                   │ 3. STACK-MATCH   │  │ 4. RELEVANCE     │  LLM node
                   │    FILTER        │  │    ANALYZER      │  detectability reasoning
                   │  code, no LLM    │  │  + ATT&CK map    │
                   └──────────────────┘  └──────────────────┘
                            └─────────┬─────────┘
                                      ▼
                              ┌──────────────────┐
                              │ 5. NVD GROUNDING │  code + API
                              │  verify any CVE  │  anti-hallucination
                              │  vs authoritative│
                              └──────────────────┘
                                      │
                                      ▼
                              ┌──────────────────┐
                              │ 6. HUNT-GUIDE    │  LLM node
                              │    GENERATOR     │  KQL + Sigma + why-it-matters
                              └──────────────────┘
                                      │
                                      ▼ (stretch goal)
                              ┌──────────────────┐
                              │ 7. CRITIC /      │  LLM node (optional)
                              │    VALIDATOR     │  weak query → send back
                              └──────────────────┘
                                      │
                                      ▼
                              ┌──────────────────┐
                              │ 8. BRIEFING      │  code
                              │    ASSEMBLER     │  ranked markdown briefing
                              └──────────────────┘
                                      │
                                      ▼
                              briefings/YYYY-MM-DD.md
```

**Node responsibilities:**

| # | Node | LLM? | Responsibility |
|---|------|------|----------------|
| 1 | Ingestion / Fetcher | No | Pull raw items from NVD, RSS, GitHub via MCP tools. Normalize to a common item schema. |
| 2 | Security Screen | No | Trust boundary. Isolate fetched text as data; scan for injection patterns; quarantine suspicious items to a human-review lane instead of processing. |
| 3 | Stack-Match Filter | No | Deterministic CPE/vendor/product match against `stack_profile.yaml`. Funnel 1. |
| 4 | Relevance Analyzer | **Yes** | For non-CPE items: extract TTPs, map to ATT&CK, reason about detectability vs configured log sources. Output verdict + reasoning. Funnel 2. |
| 5 | NVD Grounding | No | Verify every CVE ID referenced against the authoritative NVD record. Hunt guide may only assert CVE facts from NVD, never from fetched blog text. |
| 6 | Hunt-Guide Generator | **Yes** | Produce hunt guide: threat context, why-it-matters-to-this-stack, 2–3 KQL + 2–3 Sigma queries, hit/miss interpretation. |
| 7 | Critic / Validator | **Yes** | (Stretch) Validate query quality & syntax; loop back weak guides once. |
| 8 | Briefing Assembler | No | Rank by (stack-match > TTP-relevant) then severity; render daily markdown briefing. |

**Models:** Gemini (course default). Use a faster Gemini variant for the Relevance Analyzer (high-volume triage) and a stronger variant for the Hunt-Guide Generator (quality-sensitive synthesis). Keep model choice in config so it's a one-line change.

## 5. SECURITY DESIGN (this is your differentiator — invest here)

The system **ingests attacker-influenceable content** — blogs, CVE descriptions, GitHub READMEs. This is a real, under-discussed threat: **detection-as-code poisoning via CTI injection.** An adversary who can publish content could try to manipulate the agent into producing an over-broad hunt query (alert fatigue) or one that conveniently excludes their own technique. The security design exists to make that fail.

**Controls (all in `src/security/`):**

1. **Trust boundary + input isolation.** All fetched external text is untrusted. When passed to an LLM node, it goes inside a clearly delimited data envelope (tagged block), never concatenated into instruction position. The system/instruction portion of every prompt is fixed; fetched content is always data.
2. **Pre-LLM injection screen.** Before any LLM node, scan fetched text for instruction-like patterns (role markers, "ignore previous", "system:", tool-call mimicry, etc.). Suspicious items are **quarantined to a human-review lane** rather than processed — mirroring the course pattern of short-circuiting prompt injection to human escalation.
3. **NVD grounding (anti-hallucination).** Any CVE ID is independently verified against the NVD API. The hunt guide only states CVE facts from the authoritative record — a malicious blog cannot "redefine" what a CVE means.
4. **Output constraints.** Generated queries are validated for structure (valid Sigma YAML, plausible KQL) and never auto-deployed. Analyst-in-the-loop is a security control, not just a UX choice.
5. **No secrets in code.** Env vars only; `.env` gitignored; `.env.example` committed with placeholders.

**Demonstrable security moment (build this for the video + grading):** include a **red-team item** in the frozen snapshot — a benign-looking advisory with an embedded injection payload — and show the screen catching and quarantining it while legitimate items flow through. This is your single most memorable demo beat.

## 6. REPOSITORY STRUCTURE

```
threat-intel-curator/
├── run.py                     # ← single-command demo entrypoint (python run.py → briefings/)
├── README.md                  # separately graded (20 pts) — see Section 9b
├── project.md                 # this file
├── WRITEUP.md                 # Kaggle writeup (final, ≤2,500 words)
├── CODEBASE_GUIDE.md          # study companion — deep walkthrough of the code
├── .env.example               # placeholder names only, committed
├── .gitignore                 # MUST include .env
├── pyproject.toml
├── config/
│   ├── stack_profile.yaml      # vendors, products, log sources, per-node model choice
│   ├── sources.yaml            # RSS URLs, GitHub queries
│   └── prompts.yaml            # externalized prompts (incl. untrusted-data envelope)
├── src/
│   ├── agent/                  # ADK 2.0 graph workflow (from agents-cli scaffold)
│   │   ├── graph.py            # graph definition + per-item routing
│   │   ├── state.py            # IntelItem / HuntGuide schemas
│   │   ├── nodes/
│   │   │   ├── ingestion.py
│   │   │   ├── security_screen.py
│   │   │   ├── stack_filter.py
│   │   │   ├── relevance_analyzer.py
│   │   │   ├── grounding.py
│   │   │   ├── hunt_guide_generator.py
│   │   │   ├── critic.py
│   │   │   └── briefing_assembler.py
│   │   └── utils/              # llm client, prompt loader, logging
│   ├── mcp/
│   │   └── server.py            # MCP server: nvd_query, fetch_rss, fetch_url, github_search
│   └── security/
│       └── injection_guard.py
├── data/
│   └── snapshot/               # FROZEN feed snapshot for reproducible demo (incl. red-team item)
├── scratch/
│   └── demo_critic.py          # standalone critic self-correction demo (for the video)
├── briefings/                  # output: YYYY-MM-DD.md
└── tests/
    └── unit/                   # 25 unit tests (injection guard, stack filter, grounding, critic, …)
```

> Note: nodes expose a plain `*_impl` function (callable directly) plus a `@node` ADK wrapper.
> `run.py` drives the `_impl` functions in the same order as `graph.py` so the full pipeline runs
> as one command without the ADK web runtime. The ADK graph (`graph.py` / `root_agent`) remains
> the deployable artifact.

**Config examples to generate:**

`config/stack_profile.yaml`
```yaml
products:
  - vendor: microsoft
    product: defender_for_endpoint
    cpe_prefix: "cpe:2.3:a:microsoft:defender"
  - vendor: paloaltonetworks
    product: pan-os
    cpe_prefix: "cpe:2.3:o:paloaltonetworks:pan-os"
  - vendor: amazon
    product: guardduty
log_sources:        # used by the Relevance Analyzer for detectability reasoning
  - edr_process_events
  - firewall_traffic_logs
  - cloudtrail
  - email_gateway
generic_threat_interests:   # TTP-driven funnel, no CPE
  - phishing
  - malware_loaders
  - credential_theft
```

`config/sources.yaml`
```yaml
nvd:
  lookback_hours: 24
  min_cvss: 7.0          # ranking tiebreaker, NOT the primary filter
rss:
  - https://msrc.microsoft.com/blog/feed
  - https://unit42.paloaltonetworks.com/feed/
  - <add 2-3 reputable research feeds>
github:
  poc_lookback_days: 7
```

## 7. BUILD PLAN (feed Antigravity ONE phase at a time)

Timeline: now → capstone deadline (early July). Phases 0–7 are the core; 8 is the stretch; 9 is deliverables. Review and commit after each phase.

- **Phase 0 — Scaffold & skeleton.** `agents-cli scaffold` the ADK 2.0 graph project. Create repo, `.gitignore` (with `.env`), `.env.example`, `config/*.yaml`, empty node stubs. Verify the local playground runs.
- **Phase 1 — MCP server.** Implement `nvd_query` first (clean JSON REST API), then `fetch_rss`, `fetch_url`, `github_search`. Test each tool in isolation.
- **Phase 2 — Ingestion node + snapshot.** Wire ingestion to the MCP tools; normalize items to a common schema. **Capture a frozen snapshot** into `data/snapshot/` for reproducible demos and grading. Add the red-team injection item to the snapshot now.
- **Phase 3 — Security screen.** Build `injection_guard.py` + the security_screen node (pre-LLM). Write `test_injection_guard.py` proving it quarantines the red-team item. *Do this before the LLM nodes so nothing untrusted ever reaches an LLM unguarded.*
- **Phase 4 — Relevance funnels.** Stack-match filter (deterministic, with tests) + Relevance Analyzer (LLM, ATT&CK mapping + detectability reasoning).
- **Phase 5 — NVD grounding.** Verify CVE claims against authoritative NVD records; test.
- **Phase 6 — Hunt-guide generator.** Produce KQL + Sigma + why-it-matters + hit/miss. Validate query structure.
- **Phase 7 — Briefing assembler + end-to-end.** Rank and render `briefings/YYYY-MM-DD.md`. Full run over the snapshot.
- **Phase 8 — (stretch) Critic loop.** Add the validator node only if time allows.
- **Phase 9 — Deliverables.** README + architecture diagram, record demo, write the writeup, record the 5-min video.

**Definition of done for the build:** one command runs the full graph over the frozen snapshot and produces a dated briefing containing at least one CPE-matched hunt guide, one TTP-driven hunt guide, and a quarantined red-team item shown in a review lane.

---

## 8. VIDEO OUTLINE (5:00 hard cap — script before you film)

Five required beats in ~300 seconds. Storyboard it; don't wing it. Antigravity and deployability are *only* demonstrated here, so make sure both appear.

| Time | Beat | Content |
|------|------|---------|
| 0:00–0:30 | **Hook + Problem** | SOC analysts drown in CTI; most is irrelevant to their stack; manual triage is slow and error-prone. One concrete line: "X advisories published today — how many matter to *us*?" |
| 0:30–1:00 | **Why agents** | Relevance is a judgment call, not a keyword match. Show the two-funnel idea: deterministic stack-match vs. LLM detectability reasoning. Emphasize: not a feed reader. |
| 1:00–2:00 | **Architecture** | Show the graph diagram (Section 4). Call out: code-routing vs. LLM-only-where-needed, MCP tools, and the pre-LLM security screen. |
| 2:00–3:30 | **Demo** | Run over the snapshot → open the daily briefing. Walk one hunt guide (TTP, why-it-matters, KQL+Sigma, hit/miss). **Then show the red-team injection item getting quarantined.** This is the money shot. |
| 3:30–4:30 | **The Build** | Antigravity vibe-coding the nodes; `agents-cli` scaffold; ADK 2.0 graph; Gemini models; MCP server. Show the IDE briefly. |
| 4:30–5:00 | **Value + roadmap** | Daily morning briefing for analysts; deployability story (6 AM cron / Agent Runtime); roadmap: feeds into a larger AI-SOC detection engine. Close on impact. |

**Production notes:** publish to YouTube (required); attach to Media Gallery; a cover image is required to submit. Record the demo at least twice so you have clean footage. Keep narration tight — 5 beats in 5 minutes means ~1 minute each, so every sentence earns its place.

---

## 9. WRITEUP SKELETON (2,500-word HARD cap — over = penalty)

This is your project report, worth real pitch points (Core Concept 10 + Writeup 10) and it supports the implementation score too. Budget below totals ~2,250 to leave buffer. Write in your own voice for the "journey" parts — judges reward an authentic story. Sections marked **[FILL]** need your specifics.

**Title:** Autonomous Threat Intel Curator
**Subtitle:** A multi-agent SOC briefing system that turns the daily flood of threat intel into a ranked, stack-relevant hunt guide — safely.
**Track:** Agents for Business

| Section | Budget | What to cover |
|---------|--------|---------------|
| Problem | ~350w | The CTI deluge; relevance is the bottleneck; cost of both misses and false chases. Draft below. |
| Solution overview | ~300w | Daily briefing of stack-relevant hunt guides (not auto-rules); analyst-in-the-loop. |
| Why agents | ~250w | The two relevance funnels + grounded generation; code-routing vs LLM judgment. |
| Architecture | ~550w | Walk the graph (embed the diagram). Node responsibilities; MCP tools; state flow. |
| Security design | ~350w | Detection-as-code poisoning threat model; the five controls; the red-team demonstration. |
| The build & journey | ~300w | **[FILL]** Antigravity + agents-cli + ADK 2.0 + Gemini; what was hard, what you'd do next. Your voice here. |
| Results & value + roadmap | ~200w | What the demo produces; who it helps; **[FILL]** how it extends toward your larger AI-SOC work. |

**Draft — Problem (keep/trim to budget):**
> Security operations teams face a structural mismatch: threat intelligence is produced far faster than it can be triaged. Every day brings new CVEs, vendor advisories, research writeups, and campaign reports — and for any single organization, the overwhelming majority are irrelevant. The real question an analyst must answer is narrow and repetitive: *is this threat something our specific stack is exposed to, and could we even detect it with the telemetry we collect?* Answering it by hand, at volume, is slow and error-prone. The failure modes cut both ways — a missed-but-relevant threat becomes a coverage gap, while time spent on irrelevant intel is time stolen from live investigations. What teams actually need is a short, trustworthy morning briefing of only the threats that matter to them, each paired with ready-to-run hunt queries.

**Draft — Why agents (keep/trim):**
> A summarizer of feeds is not an agent — it is a newsletter. The agentic value here is judgment. Relevance splits into two funnels. The first is deterministic: does an advisory's affected product match our stack? That is best handled in code. The second cannot be: a new phishing kit or malware loader has no version identifier, so the only way to assess it is to read the report, extract its techniques, map them to MITRE ATT&CK, and reason about whether our log sources could plausibly observe them. That reasoning — plus grounded generation of hunt queries explaining why each threat matters to *this* environment — is the core of the system, and the reason it is built as a multi-agent workflow rather than a script.

**Draft — Security design opening (keep/trim):**
> Because the system ingests attacker-influenceable content — blogs, CVE descriptions, public repositories — it is itself an attack surface. We treat this as a concrete threat: detection-as-code poisoning via CTI injection, where an adversary attempts to manipulate the agent into producing an over-broad hunt query that buries real alerts, or one that omits their own technique. Five controls exist to make that fail: a strict trust boundary that isolates all fetched text as data, a pre-LLM injection screen that quarantines suspicious items to human review, independent NVD grounding so no fetched text can redefine a CVE, structural validation of all generated queries, and an analyst-in-the-loop design that never auto-deploys.

> **Word-count discipline:** the architecture and security sections will want to sprawl. Resist it. Use the diagram to carry detail visually so the prose can stay lean. Run a word count before submitting.

---

## 9b. README.md REQUIREMENTS (separately graded — 20 pts)

The repo README is worth a fifth of the implementation score. It must contain:
1. **Problem** — 2–3 sentences.
2. **Solution & what it does** — including a sample briefing snippet.
3. **Architecture** — embed the diagram from Section 4.
4. **Setup instructions** — exact, reproducible: clone, `uv`/deps, copy `.env.example` → `.env`, set keys, run command. Judges will follow these literally.
5. **How to run the demo** — the single command that runs over `data/snapshot/` and where the output lands.
6. **Security note** — short paragraph on the injection-resistance design (links to the test).
7. **Roadmap / limitations** — honest scope notes.

> Setup instructions are graded on whether a stranger can reproduce your run. Test them on a clean checkout.

---

## 10. GRADING MAP (re-check before every work session)

**Concept coverage — target 6/6 (minimum required: 3):**

| Concept | Where graded | Satisfied by |
|---------|-------------|--------------|
| Multi-agent (ADK) | Code | The graph workflow, Section 4 |
| MCP Server | Code | `src/mcp/server.py` |
| Security features | Code/Video | `src/security/` + red-team demo |
| Antigravity | Video | Build the project in Antigravity; screen-record it |
| Agent skills (Agents CLI) | Code/Video | `agents-cli scaffold` workflow |
| Deployability | Video | *Discuss* 6 AM cron / Agent Runtime — deployment NOT required to actually run |

**Points (100 total):**
- Pitch — 30: Core Concept & Value (10), YouTube Video (10), Writeup (10)
- Implementation — 70: Technical Implementation (50), Documentation/README (20)

**Hard constraints:**
- Writeup ≤ 2,500 words (penalty over).
- Video ≤ 5:00, on YouTube, attached to Media Gallery; cover image required.
- Public project link required: since not deploying, a public GitHub repo with detailed setup instructions.
- **No API keys or passwords in code.**
- Track selection required at submission (Agents for Business).
- Submit before the deadline — drafts are not judged.

**Submission checklist:**
- [ ] Public GitHub repo, runs over snapshot in one command
- [ ] README with setup tested on a clean checkout
- [ ] `.env` gitignored; no secrets committed (scan history before pushing)
- [ ] 5-min YouTube video (problem, why-agents, architecture, demo, build)
- [ ] Cover image in Media Gallery
- [ ] Writeup ≤ 2,500 words, track selected
- [ ] Antigravity + deployability both appear in the video
- [ ] Red-team injection demo is in the video
- [ ] **Clicked Submit** (not left as draft)
