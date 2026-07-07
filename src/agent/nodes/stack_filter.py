from google.adk.workflow import node
from google.adk import Context
from src.agent.state import IntelItem
import yaml
import os
from src.agent.utils.logging_utils import get_logger

logger = get_logger("stack_filter")

async def stack_filter_impl(ctx: Context, item: IntelItem) -> IntelItem:
    """
    Core logic of stack filter, callable directly in tests.
    """
    logger.info(f"Checking CPE match for {item.id} ({item.title})...")
    
    config_path = os.path.join("config", "stack_profile.yaml")
    if not os.path.exists(config_path):
        item.relevance_verdict = False
        item.relevance_reason = "No stack profile configuration found."
        return item
        
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
        
    products = config.get("products", [])
    item_cpe = item.cpe or ""
    
    for prod in products:
        cpe_prefix = prod.get("cpe_prefix")
        if cpe_prefix and item_cpe.startswith(cpe_prefix):
            item.relevance_verdict = True
            item.relevance_reason = f"Deterministic match: Product '{prod.get('product')}' ({prod.get('vendor')}) matched CPE prefix '{cpe_prefix}'"
            return item
            
    item.relevance_verdict = False
    item.relevance_reason = f"No CPE prefix match in stack profile for CPE: {item_cpe}"
    return item

@node(name="stack_filter_node")
async def stack_filter_node(ctx: Context, item: IntelItem) -> IntelItem:
    return await stack_filter_impl(ctx, item)
