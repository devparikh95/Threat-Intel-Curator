from google.adk.workflow import node
from google.adk import Context
from src.agent.state import IntelItem
import yaml
import os
from pydantic import BaseModel, Field
from google.genai import types
from src.agent.utils.logging_utils import get_logger
from src.agent.utils.llm_utils import get_llm_client, load_prompts

logger = get_logger("relevance_analyzer")

class RelevanceVerdict(BaseModel):
    relevance_verdict: bool = Field(description="True if the advisory is relevant to the organization's tech stack or generic threat interests, otherwise False")
    relevance_reason: str = Field(description="Explanation of why this threat is or is not relevant, referencing specific products, log sources, or generic interests")

async def relevance_analyzer_impl(ctx: Context, item: IntelItem) -> IntelItem:
    """
    LLM relevance analysis for non-CPE (TTP-only) items.
    """
    logger.info(f"Analyzing TTP relevance for {item.id} ({item.title})...")
    
    # 1. Load config
    config_path = os.path.join("config", "stack_profile.yaml")
    if not os.path.exists(config_path):
        item.relevance_verdict = False
        item.relevance_reason = "No stack profile configuration found."
        return item
        
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}
        
    interests = config.get("generic_threat_interests", [])
    log_sources = config.get("log_sources", [])
    
    # 2. Check if we should fallback to keyword check (offline/no credentials mode)
    client, is_offline = get_llm_client()
        
    if is_offline:
        raise RuntimeError("LLM client is offline (no credentials available for relevance analyzer).")
        
    # 3. Running real LLM Call
    try:
        # Determine model
        model_name = config.get("models", {}).get("relevance_analyzer", "gemini-2.5-flash")
        
        # Load externalized prompts
        prompts = load_prompts()
        relevance_prompts = prompts.get("relevance_analyzer", {})
        
        system_instruction_tmpl = relevance_prompts.get("system_instruction", "")
        system_instruction = system_instruction_tmpl.format(
            log_sources=log_sources,
            interests=interests
        )
        
        user_prompt_tmpl = relevance_prompts.get("user_prompt_template", "")
        user_prompt = user_prompt_tmpl.format(
            title=item.title,
            source=item.source,
            content=item.content
        )
        
        response = client.models.generate_content(
            model=model_name,
            contents=user_prompt,
            config={
                'response_mime_type': 'application/json',
                'response_schema': RelevanceVerdict,
                'system_instruction': system_instruction,
            }
        )
        
        verdict = response.parsed
        # Make sure parsed object exists, fallback if not
        if verdict:
            item.relevance_verdict = verdict.relevance_verdict
            item.relevance_reason = verdict.relevance_reason
        else:
            raise ValueError("Parsed LLM response was empty or malformed.")
            
    except Exception as e:
        logger.error(f"LLM call failed or client init failed: {e}")
        raise e
        
    return item

@node(name="relevance_analyzer_node")
async def relevance_analyzer_node(ctx: Context, item: IntelItem) -> IntelItem:
    return await relevance_analyzer_impl(ctx, item)


