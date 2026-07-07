<!--
============================================================
KAGGLE SUBMISSION — HOW TO USE THIS FILE
============================================================
• TITLE field on Kaggle:     Autonomous Threat Intel Curator
• SUBTITLE field on Kaggle:  A multi-agent SOC briefing system that turns the daily
                             flood of threat intel into a ranked, stack-relevant
                             hunt guide — safely.
• TRACK to select:           Agents for Business
• Paste everything BELOW this comment block into the Writeup body (markdown).
• Word count: ~2,410 (limit 2,500).

REQUIRED ATTACHMENTS (add in Media Gallery / Writeup before submitting):
  [ ] Cover image (required to submit)
  [ ] YouTube video, 5 min or less
  [ ] Public project link (your GitHub repo, with setup instructions)
  [ ] Track selected
  [ ] Click Submit (drafts are not judged)
============================================================
-->

## Problem

New attack methods come out every day, and for an in-house SOC at a large company, keeping up with them is a real problem. Vulnerabilities, vendor advisories, research write-ups, and campaign reports show up faster than anyone can go find them and read them. Someone still has to skim the noise, decide what deserves a second look, and drop the rest. And most of what lands on a given day has nothing to do with the technology we actually run.

The question an analyst keeps answering is a narrow one: is this new technique or vulnerability something our stack is exposed to, and if it is, could we even detect it with the telemetry we already collect? Doing that by hand, at volume and under time pressure, is slow and easy to get wrong. The cost runs both ways. Miss something relevant and it becomes a coverage gap nobody notices until it is used against us. Chase something irrelevant and those are hours a live investigation needed.

Most of this content also resists mechanical filtering. A vulnerability comes with a product identifier you can match against an inventory. A new phishing kit or malware loader does not. It is prose describing behavior, and working out whether it applies to you means reading and reasoning about it, not matching a keyword.

A SOC does not need more feeds or another dashboard. It needs a short, trustworthy morning briefing containing only the threats that matter to this environment, each one carrying a hunt query the analyst can run straight away. A next action, not another reading assignment.

## Solution

The Autonomous Threat Intel Curator delivers fresh cybersecurity news, new attack methods, and new vulnerabilities, summarized, filtered down to what is relevant to us, and packaged with actionable queries ready to use for threat hunting. It runs once a day, pulls intel from a defined set of sources (NVD, vendor and research RSS feeds, GitHub proof-of-concept repositories), reasons about relevance against a configured organizational tech stack, verifies its own factual claims against authoritative records, and produces one ranked Threat Hunt Briefing.

The core decision was to filter hard against the tool suite we actually run, and only surface vulnerability and threat information relevant to that. This cuts the noise down to the handful of items worth an analyst's attention. Each entry pairs a threat with what is needed to act on it: why it matters to this environment, two to three KQL queries and two to three Sigma rules the analyst can run now, and plain-language guidance on what a hit or a miss means.

The system does not auto-deploy detection rules. Every query is a hunting lead for a human to run and interpret, never a rule pushed live automatically. An LLM reasoning from a blog post and a stack profile, with no live access to the environment, cannot responsibly promise a rule will not misfire. A human in the loop can.

It also does not try to cover every feed type. It goes deep on one structured, authoritative source (NVD) plus a small set of reputable feeds and a GitHub search, instead of spreading thin across dozens of noisy integrations. For grading and demos, the whole pipeline runs over a frozen snapshot of intel, including a seeded red-team item, and produces a reproducible, dated briefing with one command and no live network dependency.

## Why agents

A system that fetches feeds and asks an LLM to summarize them is a newsletter generator, not an agent. Because of the non-deterministic nature of LLMs, I did not want to lean on AI for everything. I wanted to use it only where its strength lies and keep the rest in plain, predictable code. That principle splits the relevance problem into two funnels.

The first is deterministic. Does an advisory's affected product match something in our stack? A vulnerability ships with a CPE, an exact product identifier, so this can be answered in code with a string comparison. There is no ambiguity, so there is no reason to spend an LLM call on it. A plain routing check handles every item that carries a CPE.

The second cannot be answered in code. A new phishing kit or credential-harvesting campaign has no version string to match. The only way to assess it is to read the report, understand the technique, and reason about whether our log sources (EDR, firewall, cloud audit trails) could plausibly observe it. That is a judgment call, and it is the kind of task an LLM is good at, so those items route to an LLM node instead of a keyword filter.

A third layer sits on top. Once an item is relevant, writing a useful hunt guide means synthesizing the threat's specifics together with the environment's specifics, not summarizing either one alone. That synthesis, plus a self-correcting pass over the generated queries, is what makes this a multi-agent system rather than a single prompt wrapped in a script.

## Architecture

The system is a dynamic, code-orchestrated workflow built on ADK 2.0 and generated from the `agents-cli` scaffold. Instead of a static graph of fixed edges, one coordinator ingests the day's items, then loops over each and routes it based on a plain code check. That routing decision is where the "code versus judgment" principle actually lives, not buried inside a framework abstraction.

The pipeline runs in eight stages. **Ingestion** pulls raw items, either from a frozen snapshot for reproducible demos or live from RSS, NVD, and GitHub in production mode, through an MCP server exposing four tools (`nvd_query`, `fetch_rss`, `fetch_url`, `github_search`). Every item is normalized into a common schema.

Before any item reaches an LLM, it passes through a **security screen** that scans its raw text for prompt-injection patterns. Anything suspicious is quarantined to a human-review lane and left out of further processing. The system never lets a model reason over untrusted text that has not been screened first.

Clean items are routed per item. Those carrying a CPE or CVE go to a deterministic **stack-match filter** that checks the affected product against the configured stack profile, in pure code with no model call. Items with no product identifier, the phishing kits and campaigns described only by behavior, go to an LLM **relevance analyzer**, which reasons about the described techniques against our configured log sources and returns a structured verdict.

Relevant items continue to **grounding**, where any referenced CVE is re-verified against the live NVD API. If NVD confirms it, its authoritative severity and product data replace whatever the source text claimed. If NVD cannot confirm it, the item is marked unverified rather than trusted blindly or filled in with a guess. This anti-hallucination step matters because the source text is attacker-influenceable.

Grounded items reach the **hunt-guide generator**, an LLM node that produces the deliverable: a technical threat summary, why it matters given our stack and log sources, two to three KQL queries, two to three Sigma rules, and hit/miss guidance, all returned as validated structured output.

A **critic** node then checks every generated query in code first (valid Sigma YAML with the required sections, KQL containing pipe operators). If one fails, it calls the LLM once to repair it. The outcome (passed, fixed, or failed) is recorded and shown in the briefing, and the node degrades gracefully rather than failing the whole run if the repair call is unavailable.

A code-only **briefing assembler** then ranks all relevant items, confirmed stack matches first and then by severity, and writes them plus the quarantine lane into one dated markdown briefing. All organization-specific behavior (the stack profile, the feed list, the model per node, and the prompt text) lives in version-controlled YAML config rather than in the pipeline code, so adapting the system to a different environment is a configuration change, not a rewrite.

## Security design

Because the system ingests attacker-influenceable content (public blog posts, CVE descriptions, GitHub repository text), it is part of the attack surface itself. This is not hypothetical. We increasingly see attackers poisoning public content, from SEO poisoning that pushes malicious pages up the results to planted write-ups, to get their material in front of both people and automated systems. An agent that ingests public threat intel is exposed to the same manipulation, and I would rather build the defense for it now than after it bites. The concrete threat is detection-as-code poisoning: an adversary who can publish content trying to steer the agent into an over-broad hunt query that buries real alerts, or a narrow one that conveniently skips their own technique.

Four controls work together as layered defense rather than a single checkpoint. First, a strict trust boundary. Every piece of fetched text is treated as untrusted data, never as instructions, and is wrapped in an explicit delimited envelope inside every prompt, with the system instruction kept fixed and separate. Second, a pre-LLM injection screen scans all fetched text for instruction-like patterns such as role markers, "ignore previous instructions," and system-prompt mimicry, before anything reaches a model. Matches go to a human-review lane and are never silently dropped. Third, independent grounding. Any referenced CVE is re-verified against the authoritative NVD record, and if NVD cannot confirm it, the item is marked unverified instead of trusted or fabricated, so a blog post cannot redefine what a CVE means. Fourth, generated queries are structurally validated, and whatever the outcome, none is ever auto-deployed. Every output is a hunting lead for a human to review and run, which is a security control here and not just a UX choice.

No secrets are hardcoded. Credentials come from environment variables, `.env` is gitignored, and a placeholder-only `.env.example` is committed. The demonstrable version of all this is a red-team item seeded into the snapshot, a benign-looking advisory with an embedded injection payload, which the screen catches and quarantines while legitimate items flow through untouched.

## The build and journey

This started with a conversation with our director. We thought we should use AI to gather relevant cybersecurity articles and get them to our team every day. Right away I knew this was the capstone I wanted to build. It serves a real purpose, and I end up with a working system I can later translate for my own team. What began as "curate the articles" grew, as I worked, into the harder problem underneath it: deciding which threats matter to us, and giving analysts something they can act on the same morning.

I built it end to end in Antigravity, using `agents-cli` and ADK 2.0, and it was a breeze to work with. For the first time in my life, the thing I had to decide was what to build, the design choices, and the use case, rather than being limited by my own ability to code, the time it takes, and the brutal testing phase to get a working prototype. That shift alone made me feel like a creator and gave me the confidence to build more tuned, specific projects for my own needs.

It was not one-shot, and learning that was half the value. I quickly realized I had to be very specific with Antigravity and do my own research and thinking instead of expecting the whole project in one go. So I split the work into phases and moved one phase at a time, checking that each was sound and that I understood what it was doing before continuing. That discipline paid off. The clearest example was a grounding bug that made it all the way to a "working" demo. The snapshot used a fabricated CVE ID that happened to collide with a real, unrelated Google Chrome CVE in NVD. The grounding step looked it up and overwrote a Palo Alto PAN-OS advisory with Chrome's data, producing a briefing that contradicted itself, and I found a hardcoded band-aid that had been added to paper over it. Fixing it properly, with fictional CVE IDs that cannot collide and an honest "unverified" state instead of a faked result, made the anti-hallucination guarantee genuinely honest instead of accidentally correct. It was also a lesson in not trusting the agent's own status reports at face value. More than once it reported work as finished that was not, and reviewing each phase myself is what caught it.

Along the way I picked up ADK's principles and fundamentals, and how to work inside an agentic IDE: managing context deliberately and finding more efficient ways to interact with it to get exactly what I wanted.

## Results, value, and roadmap

The demo run over the frozen snapshot produces one ranked briefing with two fully worked hunt guides, one confirmed by a deterministic stack match (Palo Alto PAN-OS) and one surfaced entirely through LLM reasoning about technique (a credential-phishing campaign), plus a quarantined red-team item that shows the injection screen holding under a staged attack. The value is straightforward. Analysts stop reading every article to find the few that matter to us, and they get hunting guides that are ready to go, so they can hunt for threats right away.

Beyond the capstone, this fits into a larger AI-SOC project I recently started building: a multi-agent setup with MCP servers and, in effect, a SOC brain, where connected and separate agents perform red-team testing, triage incidents, and use detection-as-code to push for new and better detection rules. The Curator slots in as an add-on. An agent can take each new vulnerability it surfaces and work on testing and building detection rules from it. The KQL and Sigma queries it already produces are the natural interface for that. Sigma converts directly to Splunk SPL and other backends, so the same hunt guide can target Sentinel, Splunk, or another SIEM without regeneration, and the next step is closing the loop so hunts fire automatically against the environment. That stays a hunt, not an auto-deployed rule: read-only, reviewed, and reversible. The human-in-the-loop boundary this project treats as a security control holds even as the manual step it replaces gets automated away.
