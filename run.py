"""
Run the Threat Intel Curator pipeline end-to-end over the frozen snapshot and
write a dated Threat Hunt Briefing to briefings/YYYY-MM-DD.md.

This is the single-command demo entrypoint:

    python run.py                # run over the frozen snapshot (data/snapshot/items.json)
    python run.py live           # run over live feeds (RSS/NVD/GitHub, needs network + keys)

The pipeline mirrors src/agent/graph.py exactly (same nodes, same per-item routing),
but drives the nodes' plain `_impl` functions directly so it runs as one command
without the ADK web runtime. The LLM nodes require a Gemini API key in .env
(GEMINI_API_KEY); see README.md for setup.
"""

import asyncio
import sys

from dotenv import load_dotenv

from src.agent.nodes.ingestion import ingestion_impl
from src.agent.nodes.security_screen import security_screen_impl
from src.agent.nodes.stack_filter import stack_filter_impl
from src.agent.nodes.relevance_analyzer import relevance_analyzer_impl
from src.agent.nodes.grounding import grounding_impl
from src.agent.nodes.hunt_guide_generator import hunt_guide_generator_impl
from src.agent.nodes.critic import critic_impl
from src.agent.nodes.briefing_assembler import briefing_assembler_impl
from src.agent.utils.logging_utils import get_logger

logger = get_logger("runner")


async def run(mode: str = "snapshot") -> str:
    # 1. Ingestion (snapshot or live)
    items = await ingestion_impl(None, mode)
    logger.info(f"Ingested {len(items)} items in '{mode}' mode.")

    # 2. Security screen (pre-LLM trust boundary)
    clean_items, quarantined_items = await security_screen_impl(None, items)

    processed_items = []
    for item in clean_items:
        # Code-based routing: deterministic CPE/CVE match vs. LLM TTP judgment
        if item.cpe or item.cve_id:
            item = await stack_filter_impl(None, item)
        else:
            item = await relevance_analyzer_impl(None, item)

        # Only ground + generate for relevant items
        if item.relevance_verdict is True:
            item = await grounding_impl(None, item)
            item = await hunt_guide_generator_impl(None, item)
            item = await critic_impl(None, item)

        processed_items.append(item)

    # 3. Assemble + write the briefing
    briefing_path = await briefing_assembler_impl(
        None, processed_items=processed_items, quarantined_items=quarantined_items
    )
    return briefing_path


def main() -> None:
    load_dotenv()
    mode = sys.argv[1].strip().lower() if len(sys.argv) > 1 else "snapshot"
    briefing_path = asyncio.run(run(mode))
    print(f"\n[OK] Briefing written to: {briefing_path}")


if __name__ == "__main__":
    main()
