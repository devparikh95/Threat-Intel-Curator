from google.adk import Workflow, Context, Event
from google.adk.workflow import node

from src.agent.nodes.ingestion import ingestion_node
from src.agent.nodes.security_screen import security_screen_node
from src.agent.nodes.stack_filter import stack_filter_node
from src.agent.nodes.relevance_analyzer import relevance_analyzer_node
from src.agent.nodes.grounding import grounding_node
from src.agent.nodes.hunt_guide_generator import hunt_guide_generator_node
from src.agent.nodes.critic import critic_node
from src.agent.nodes.briefing_assembler import briefing_assembler_node

from src.agent.utils.logging_utils import get_logger

logger = get_logger("workflow")

@node(name="main_workflow")
async def main_workflow(ctx: Context, node_input: str):
    """
    The main coordinator for the Threat Intel Curator dynamic workflow.
    Iterates over external CTI data and branches dynamically per item.
    """
    logger.info("Starting curation workflow...")
    
    # 1. Ingestion
    items = await ctx.run_node(ingestion_node, node_input=node_input)
    
    # 2. Security Screen
    clean_items, quarantined_items = await ctx.run_node(security_screen_node, items=items)
    
    processed_items = []
    
    # 3. Process items in a loop with per-item branching
    for item in clean_items:
        # PURE CODE ROUTING DECISION: CVE/CPE presence
        if item.cpe or item.cve_id:
            # Route to deterministic CPE Stack Filter (pure code, no LLM)
            item_result = await ctx.run_node(stack_filter_node, item=item)
        else:
            # Route to LLM-based Relevance Analyzer (TTP analysis)
            item_result = await ctx.run_node(relevance_analyzer_node, item=item)
            
        # Ground and generate hunt guides only if the item is relevant
        if item_result.relevance_verdict is True:
            # Grounding
            item_result = await ctx.run_node(grounding_node, item=item_result)
            # Hunt guide generation
            item_result = await ctx.run_node(hunt_guide_generator_node, item=item_result)
            # Critic validation
            item_result = await ctx.run_node(critic_node, item=item_result)
            
        processed_items.append(item_result)
        
    # 4. Assemble the final briefing
    briefing_path = await ctx.run_node(
        briefing_assembler_node, 
        processed_items=processed_items, 
        quarantined_items=quarantined_items
    )
    
    # Read written briefing file and emit as output message
    with open(briefing_path, "r", encoding="utf-8") as f:
        briefing_content = f.read()
        
    yield Event(message=briefing_content)

# Root agent wrapped in the ADK Workflow
root_agent = Workflow(
    name="threat_intel_curator_workflow",
    edges=[("START", main_workflow)],
)
