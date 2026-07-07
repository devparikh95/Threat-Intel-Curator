# Video Outline — Autonomous Threat Intel Curator

**Hard limits:** ≤ 5:00, published to YouTube, attached to Media Gallery, cover image required.
**Must appear (graded):** Antigravity (build), deployability (discussed), the red-team quarantine (demo).
**Narration budget:** ~700 words ≈ 4:40 at a natural pace — leaves ~20s of breathing room for on-screen pauses. Script before you film; record the demo at least twice for clean footage.

---

## The 5 beats at a glance

| Time | Beat | On screen | Purpose |
|------|------|-----------|---------|
| 0:00–0:30 | Hook + Problem | You / title card, or a wall of advisories | Make them feel the CTI overload |
| 0:30–1:00 | Why agents | Simple two-funnel graphic | Prove it's judgment, not a feed reader |
| 1:00–2:00 | Architecture | The pipeline diagram (README) | Code-vs-LLM routing, MCP, security screen |
| 2:00–3:30 | **Demo** | Terminal + the generated briefing | The briefing + **the quarantine money shot** |
| 3:30–4:30 | The Build | Antigravity IDE | How it was built + the review story |
| 4:30–5:00 | Value + roadmap | Briefing / AI-SOC sketch | Impact + deployability + roadmap |

---

## Full script (read this aloud)

### 0:00–0:30 — Hook + Problem
> *On screen: you talking, or a fast scroll of advisory headlines.*

"Every day, hundreds of new vulnerabilities, advisories, and attack write-ups get published. If you run a SOC, you can't read them all — and almost none of them apply to your stack. So the real question isn't *what's new*. It's *what's new that could actually hit us, and could we even see it in our logs?* Answering that by hand, every single morning, is slow, repetitive, and easy to get wrong."

### 0:30–1:00 — Why agents
> *On screen: a simple graphic — one arrow "has a product? → code match", one arrow "no product? → LLM judgment".*

"A tool that just summarizes feeds is a newsletter, not an agent. The value here is judgment. When a threat names a product, matching it to our stack is a fact — so I do that in plain code. But a new phishing kit has no version number. Deciding if it's relevant means reading it and reasoning about whether our logs could even detect it. That's where the LLM earns its place. Code where it's deterministic, AI only where there's real judgment."

### 1:00–2:00 — Architecture
> *On screen: the pipeline diagram from the README, highlighting each node as you name it.*

"Here's how it works. An MCP server pulls intel from NVD, RSS feeds, and GitHub. Before anything reaches a model, a security screen checks it for prompt injection. Clean items get routed — product matches go through a deterministic filter, everything else goes to an LLM relevance analyzer. Relevant items are grounded against the authoritative NVD record, so a malicious blog can't lie about a CVE. Then a generator writes the hunt guide — KQL and Sigma queries, why it matters to us, and how to read the results. A critic validates those queries and repairs them if they're malformed. Finally, everything is ranked into one briefing. It's built on ADK with Gemini models, and the whole thing is driven by configuration, not hard-coded."

### 2:00–3:30 — Demo (the most important 90 seconds)
> *On screen: terminal, then the generated `briefings/YYYY-MM-DD.md`.*

"Let me run it — one command, over a frozen snapshot."
> *Run: `uv run python run.py`. Let it finish, open the briefing.*

"It produces today's briefing: two actionable threats. The first is a PAN-OS vulnerability, matched to our stack deterministically. Look at the grounding line — it couldn't verify this CVE against NVD, so instead of trusting the source, it flags the data as *unverified*. Honest, not hallucinated. Underneath: ready-to-run KQL and Sigma hunt queries, and what a hit or a miss actually means."

> *Scroll to the second threat.*

"The second threat had no CVE at all — a phishing campaign the LLM judged relevant because we collect email and cloud logs."

> *Scroll to the Quarantine Lane — pause here.*

"And this is the part I'm most proud of. This item was a planted injection attack — *'ignore previous instructions.'* The security screen caught it and quarantined it to a review lane, before any model ever saw it. That's the whole threat model, working end to end."

> *Optional (if time): flash `python scratch/demo_critic.py` showing a malformed query being auto-repaired.*

### 3:30–4:30 — The Build (Antigravity)
> *On screen: the Antigravity IDE — show the phases / a node file / the graph.*

"I built this entirely in Antigravity, scaffolded with agents-cli on ADK 2.0. For the first time, my job wasn't fighting my own code — it was deciding *what* to build, the architecture, and the security model, and reviewing every phase. I fed it the spec one phase at a time. It was not one-shot — I had to be specific, and I had to check its work. Here's a real example: a test CVE I used happened to collide with a real one in NVD, and the grounding step quietly overwrote my data with the wrong record. Catching that, and fixing it to fail honestly instead of confidently wrong, is exactly the kind of review this way of building needs."

### 4:30–5:00 — Value + roadmap + deployability
> *On screen: the briefing again, then a simple sketch of the larger AI-SOC.*

"The payoff is simple: analysts stop reading everything to find the few that matter, and they get hunts ready to run immediately. It's built to deploy as a scheduled 6 AM job on Agent Runtime, and it slots into a larger AI-SOC platform I'm building — where an agent turns each new vulnerability into tested detection rules. From intel to hunt, automatically, with a human always in the loop."

---

## Recording checklist

- [ ] **Set your Gemini key and pre-run once** so the demo run is warm and won't hit a cold 503 (retry if the model is briefly overloaded).
- [ ] **Pause Antigravity** during filming — it has deleted `briefings/` mid-run before. Generate the briefing, then don't let anything touch the folder.
- [ ] Record the **demo segment at least twice** — it's the highest-stakes 90 seconds.
- [ ] Zoom your terminal/editor font so text is readable at 1080p.
- [ ] Keep the quarantine reveal **slow** — it's the memorable beat; don't rush past it.
- [ ] Confirm the three required elements are all in the cut: **Antigravity IDE**, **deployability sentence**, **red-team quarantine**.
- [ ] Export, upload to **YouTube**, attach to **Media Gallery**, add a **cover image**.
- [ ] Final length **≤ 5:00** — if long, trim the architecture beat first (the diagram carries it visually).

## Cover image idea
A single frame of the briefing with the 🎯 actionable hunts at top and the 🛡️ quarantine lane visible at the bottom, titled "Autonomous Threat Intel Curator" — it shows the product and the security angle in one glance.
