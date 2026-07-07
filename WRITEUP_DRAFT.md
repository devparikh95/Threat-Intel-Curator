# Autonomous Threat Intel Curator

**Subtitle:** A multi-agent SOC briefing system that turns the daily flood of threat intel into a ranked, stack-relevant hunt guide — safely.
**Track:** Agents for Business

---

## Problem

New attack methods come out every single day. For an in-house SOC at a large company, keeping up with them is a real, grinding problem: vulnerabilities, vendor advisories, research write-ups, and campaign reports appear faster than anyone can realistically go find them and read them all. Someone has to skim the noise, decide what's worth a second look, and throw away the rest — and the overwhelming majority of what comes out on any given day has nothing to do with the technology our organization actually runs.

The question an analyst has to answer, over and over, is narrow and repetitive: is this new technique or vulnerability something our specific stack is even exposed to, and if it is, could we detect it with the telemetry we already collect? Answering that by hand, at volume, under time pressure, is slow and easy to get wrong — and the cost cuts both ways. A relevant threat that gets lost in the noise becomes a silent coverage gap nobody notices until it's exploited. An irrelevant one that gets chased anyway burns hours that should have gone to a live investigation.

Compounding it, most of this content can't be filtered mechanically. A vulnerability ships with a product identifier you can match against an inventory. A brand-new phishing kit or malware loader does not — it's described in prose, as a set of behaviors, and deciding whether it applies to your environment means actually reading and reasoning about it, not keyword-matching a feed.

What a SOC actually needs isn't more feeds or another dashboard. It's a short, trustworthy morning briefing containing only the threats that matter to *this* environment, each one paired with a concrete, ready-to-run hunt query — so the analyst has an immediate next action instead of another reading assignment.

## Solution

The Autonomous Threat Intel Curator is a system that delivers fresh cybersecurity news, new attack methods, and new vulnerabilities — summarized, filtered down to what's relevant to us, and packaged with actionable queries ready to use for threat hunting. It runs once daily, ingests intel from a defined set of sources (NVD, vendor and research RSS feeds, GitHub proof-of-concept repositories), reasons about relevance against a configured organizational tech stack, independently verifies its own factual claims against authoritative records, and produces a single ranked Threat Hunt Briefing.

The core design decision was to filter aggressively against the tool suite we actually run, and only surface vulnerability and threat information relevant to that — cutting the noise down to the handful of items worth an analyst's attention. Each entry pairs a specific threat with what's needed to act on it: why it's relevant to this environment specifically, 2–3 KQL queries and 2–3 Sigma rules the analyst can run right now, and plain-language guidance on what a hit or miss actually means.

Deliberately, the system does not auto-deploy detection rules. Every query is a hunting lead for a human to run and interpret — never a rule pushed live automatically. An LLM reasoning from a blog post and a stack profile, without live access to the environment, cannot responsibly guarantee a rule won't misfire; a human in the loop can.

It also doesn't try to cover every feed type. It goes deep on one structured, authoritative source (NVD) plus a small set of reputable feeds and a GitHub search, rather than shallow across dozens of noisy integrations — depth over breadth, to keep judgment quality high. For grading and demos, the whole pipeline runs over a frozen snapshot of intel — including a seeded red-team item — producing a fully reproducible, dated briefing with one command and no live network dependency.

## Why agents

A system that fetches feeds and asks an LLM to summarize them isn't an agent — it's a newsletter generator. Because of the non-deterministic nature of LLMs, I deliberately did not want to rely on AI for everything; I wanted to use it only where its strength actually lies, and keep everything else in plain, predictable code. That principle splits the relevance problem into two funnels.

The first is deterministic: does an advisory's affected product match something in our stack? A vulnerability ships with a CPE — an exact product identifier — so this can be answered in code with a string comparison. There's no ambiguity, so there's no reason to spend an LLM call on it; a plain routing check handles every item carrying a CPE.

The second genuinely cannot be answered in code. A new phishing kit or credential-harvesting campaign has no version string to match. The only way to assess it is to read the report, understand the technique, and reason about whether our actual log sources — EDR, firewall, cloud audit trails — could plausibly observe it. That is real judgment, and it's exactly the kind of task an LLM is strong at, so those items route to an LLM node instead of a keyword filter.

A third layer of judgment sits on top: once an item is relevant, producing a useful hunt guide means synthesizing the threat's specifics together with the environment's specifics — not summarizing either alone. That synthesis, plus a self-correcting validation pass over the generated queries, is what makes this a multi-agent system rather than a single prompt wrapped in a script.

## Architecture

The system is built as a dynamic, code-orchestrated workflow using ADK 2.0, generated from the `agents-cli` scaffold. Rather than a static graph of fixed edges, a single coordinator ingests the day's items, then loops over each one and routes it based on a plain code check — the routing decision itself is where the "code vs. judgment" principle lives, not an abstraction hidden inside a framework.

The pipeline runs in eight stages. **Ingestion** pulls raw items — from a frozen snapshot for reproducible demos, or live from RSS, NVD, and GitHub in production mode — through an MCP server exposing four tools (`nvd_query`, `fetch_rss`, `fetch_url`, `github_search`) as a clean boundary between reaching the outside world and reasoning about what came back. Every item is normalized into a common schema.

Before any item reaches an LLM, it passes through a **security screen** that scans its raw text for prompt-injection patterns. Anything suspicious is quarantined to a human-review lane and excluded from further processing — the system never lets a model reason over untrusted text that hasn't been screened first.

Clean items are then routed per-item. Those carrying a CPE or CVE go to a deterministic **stack-match filter** that checks the affected product against the organization's configured stack profile — pure code, no model call. Items with no product identifier — the phishing kits and campaigns described only by behavior — go to an LLM **relevance analyzer**, which reasons about the described techniques against our configured log sources and returns a structured relevance verdict.

Relevant items continue to **grounding**, where any referenced CVE is independently re-verified against the live NVD API. If NVD confirms it, its authoritative severity and product data overwrite whatever the source text claimed. If NVD cannot confirm it, the item is explicitly marked unverified rather than trusting the source blindly or fabricating a result — an anti-hallucination guarantee that matters precisely because the source is attacker-influenceable.

Grounded items reach the **hunt-guide generator**, an LLM node that produces the full deliverable: a technical threat summary, why it matters given our specific stack and log sources, 2–3 KQL queries, 2–3 Sigma rules, and hit/miss guidance — all as validated structured output, not free text.

A **critic** node then checks every generated query in code first (valid Sigma YAML with the required sections, KQL containing pipe operators), and if one fails, calls the LLM once to repair it. The outcome — passed, fixed, or failed — is recorded and surfaces in the briefing, and the node degrades gracefully rather than failing the whole run if the correction call is unavailable.

Finally, a code-only **briefing assembler** ranks all relevant items — confirmed stack matches first, then by severity — and renders them plus the quarantine lane into a single dated markdown briefing. All organization-specific behavior — the stack profile, feed list, model choice per node, and the prompt text itself — lives in version-controlled YAML config, not in the pipeline code, so adapting to a different environment is a configuration change, not a rewrite.

## Security design

Because the system ingests attacker-influenceable content — public blog posts, CVE descriptions, GitHub repository text — it is itself part of the attack surface. This isn't hypothetical: in practice we increasingly see attackers poisoning public content, from SEO poisoning that surfaces malicious pages to planted write-ups, specifically to get their material in front of both people and automated systems. An agent that ingests public threat intel is exposed to exactly that manipulation, and building the defense for it felt like the right thing to practice now rather than after it bites. The concrete threat is detection-as-code poisoning: an adversary who can publish content trying to steer the agent into producing an over-broad hunt query that buries real alerts, or a narrow one that conveniently excludes their own technique.

Four controls work together as layered defense, not a single checkpoint. First, a strict trust boundary: every piece of fetched text is treated as untrusted data, never instructions, and is wrapped in an explicit delimited data envelope inside every prompt — the system instruction is fixed and kept separate from untrusted content. Second, a pre-LLM injection screen scans all fetched text for instruction-like patterns — role markers, "ignore previous instructions," system-prompt mimicry — before anything reaches a model; matches are quarantined to a human-review lane, never silently dropped. Third, independent grounding: any referenced CVE is re-verified against the authoritative NVD record, and if NVD cannot confirm it, the item is marked unverified rather than trusted or fabricated — a blog post cannot redefine what a CVE means. Fourth, generated queries are structurally validated, and regardless of outcome, none is ever auto-deployed; every output is a hunting lead for a human to review and run, which is a security control here, not just a UX choice.

No secrets are hardcoded: credentials come from environment variables, `.env` is gitignored, and a placeholder-only `.env.example` is committed. The demonstrable version of all this is a red-team item seeded into the snapshot — a benign-looking advisory with an embedded injection payload — which the screen catches and quarantines while legitimate items flow through untouched.

## The build & journey

This started with a conversation with our director: we thought we should use AI to gather relevant cybersecurity articles and deliver them to our team every day. Right off the bat I knew this was the capstone I wanted to build — it serves a real purpose, and I'd end up with a working system I can translate for my own team. What began as "curate the articles" grew, as I worked, into the harder and more interesting problem underneath it: deciding which threats actually matter to *us*, and handing analysts something they can act on immediately.

I built it end-to-end in Antigravity, using `agents-cli` and ADK 2.0. Honestly, it was a breeze to work with — and for the first time in my life, the thing I had to decide was *what* to build, the design choices, and my use case, rather than being limited by my own ability to code, the time it takes, and the brutal testing phase to get a working prototype. That shift alone made me feel like a creator, and gave me real confidence to build more highly tuned, specific projects for my own needs.

It wasn't one-shot, though, and learning that was half the value. I quickly realized I had to be very specific with Antigravity and do my own research and thinking rather than expecting it to produce the whole project in one go. So I split the work into phases and only moved forward one phase at a time, making sure everything was sound and that I actually understood what it was doing before continuing. That discipline paid off — the clearest example was a grounding bug that made it all the way to a "working" demo. The snapshot used a fabricated CVE ID that, by coincidence, collided with a real, unrelated Google Chrome CVE in NVD; the grounding step dutifully looked it up and overwrote a PAN-OS advisory with Chrome's data, producing a briefing that contradicted itself. I also found a hardcoded band-aid that had been added to paper over it. Fixing it properly — fictional CVE IDs that can't collide, and an honest "unverified" state instead of a faked result — made the anti-hallucination guarantee genuinely honest instead of accidentally correct. It was also a lesson in not trusting the agent's own status reports at face value: more than once it claimed work was finished that wasn't, and reviewing each phase myself is what caught it.

Along the way I learned ADK's principles and fundamentals, and how to work effectively inside an agentic IDE — managing context deliberately and finding more efficient ways to interact with it to get exactly what I wanted.

## Results & value + roadmap

The demo run over the frozen snapshot produces a single ranked briefing with two fully worked hunt guides — one confirmed by a deterministic stack match (Palo Alto PAN-OS), one surfaced entirely through TTP-based LLM reasoning (a credential-phishing campaign) — plus a quarantined red-team item proving the injection screen holds under a staged attack. The real gain is simple: analysts no longer have to read through every article to find the few essential to us, and they get hunting guides ready to go, so they can hunt for threats right away.

Beyond the capstone, this fits directly into a larger AI-SOC project I recently started building — a multi-agent setup with MCP servers and, effectively, a "SOC brain," where multiple connected and separate agents perform red-team testing, triage incidents, and use detection-as-code to push for new and better detection rules. The Curator slots in cleanly as an add-on: an agent can take each new vulnerability it surfaces each day and work on testing and creating detection rules from it. The KQL and Sigma queries it already generates are the natural interface for that — Sigma's vendor-neutral format converts directly to Splunk SPL and other backends, so the same hunt guide can target Sentinel, Splunk, or another SIEM without regeneration, and the next step is closing the loop so hunts are triggered automatically against the environment. Crucially, that stays a hunt, not an auto-deployed rule — read-only, reviewed, reversible. The human-in-the-loop boundary this project treats as a security control stays intact even as the manual step it replaces gets automated away.
