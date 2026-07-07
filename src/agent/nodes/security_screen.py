from google.adk.workflow import node
from google.adk import Context
from src.agent.state import IntelItem
from src.security import injection_guard
from typing import List, Tuple
from src.agent.utils.logging_utils import get_logger

logger = get_logger("security_screen")

async def security_screen_impl(ctx: Context, items: List[IntelItem]) -> Tuple[List[IntelItem], List[IntelItem]]:
    """
    Core logic of the security screen, callable directly (in tests and the runner).
    Scans a list of IntelItems for prompt injection.
    Returns (clean_items, quarantined_items).
    """
    logger.info("Running injection screen on items...")
    clean = []
    quarantined = []

    for item in items:
        is_injected, reason = injection_guard.scan_text(item.content)
        if is_injected:
            logger.warning(f"QUARANTINED item {item.id}: {reason}")
            item.quarantined = True
            item.quarantine_reason = reason
            quarantined.append(item)
        else:
            clean.append(item)

    return clean, quarantined

@node(name="security_screen_node")
async def security_screen_node(ctx: Context, items: List[IntelItem]) -> Tuple[List[IntelItem], List[IntelItem]]:
    return await security_screen_impl(ctx, items)
