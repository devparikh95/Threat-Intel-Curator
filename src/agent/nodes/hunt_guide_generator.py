from google.adk.workflow import node
from google.adk import Context
from src.agent.state import IntelItem, HuntGuide, HuntQuery
import yaml
import os
from google.genai import types
from src.agent.utils.logging_utils import get_logger
from src.agent.utils.llm_utils import get_llm_client, load_prompts

logger = get_logger("hunt_guide_generator")

async def hunt_guide_generator_impl(ctx: Context, item: IntelItem) -> IntelItem:
    """
    Core logic of hunt guide generator, callable directly in tests.
    """
    logger.info(f"Generating hunt guide for {item.id} ({item.title})...")
    
    # 1. Load config
    config_path = os.path.join("config", "stack_profile.yaml")
    if not os.path.exists(config_path):
        # Fallback to simulated guide if config is missing
        config = {}
    else:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
            
    products = config.get("products", [])
    log_sources = config.get("log_sources", [])
    
    # 2. Check if we should fallback (offline/no credentials mode)
    client, is_offline = get_llm_client()
        
    if is_offline:
        raise RuntimeError("LLM client is offline (no credentials available for hunt guide generator).")
        
    # 3. Running real LLM call
    try:
        model_name = config.get("models", {}).get("hunt_guide_generator", "gemini-2.5-pro")
        
        # Load externalized prompts
        prompts = load_prompts()
        hunt_prompts = prompts.get("hunt_guide_generator", {})
        
        system_instruction_tmpl = hunt_prompts.get("system_instruction", "")
        system_instruction = system_instruction_tmpl.format(
            log_sources=log_sources,
            products=products
        )
        
        user_prompt_tmpl = hunt_prompts.get("user_prompt_template", "")
        user_prompt = user_prompt_tmpl.format(
            title=item.title,
            source=item.source,
            content=item.content,
            relevance_reason=item.relevance_reason,
            grounding_details=item.grounding_details
        )
        
        response = client.models.generate_content(
            model=model_name,
            contents=user_prompt,
            config={
                'response_mime_type': 'application/json',
                'response_schema': HuntGuide,
                'system_instruction': system_instruction,
            }
        )
        
        guide = response.parsed
        if guide:
            item.hunt_guide = guide
        else:
            raise ValueError("Parsed LLM hunt guide was empty or malformed.")
            
    except Exception as e:
        logger.error(f"LLM call failed or client init failed: {e}")
        raise e
        
    return item

@node(name="hunt_guide_generator_node")
async def hunt_guide_generator_node(ctx: Context, item: IntelItem) -> IntelItem:
    return await hunt_guide_generator_impl(ctx, item)


