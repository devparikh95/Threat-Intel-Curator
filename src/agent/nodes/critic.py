from google.adk.workflow import node
from google.adk import Context
from src.agent.state import IntelItem, HuntQuery
from pydantic import BaseModel, Field
from typing import List
import yaml
import os
from google.genai import types
from src.agent.utils.logging_utils import get_logger
from src.agent.utils.llm_utils import get_llm_client, load_prompts

logger = get_logger("critic")

class CriticFeedback(BaseModel):
    corrected_queries: List[HuntQuery] = Field(description="List of KQL and Sigma queries corrected for syntax, schema completeness, and log source compatibility")

async def critic_impl(ctx: Context, item: IntelItem) -> IntelItem:
    """
    Critic and validator node (stretch goal).
    Validates generated hunt queries for syntax and structural correctness.
    If weak/malformed queries are detected, triggers an LLM correction step.
    """
    logger.info(f"Validating generated hunt queries for {item.id}...")
    
    if not item.hunt_guide or not item.hunt_guide.queries:
        logger.warning("No hunt guide or queries found to validate!")
        return item
        
    has_errors = False
    validation_notes = []
    
    # 1. Quick Python structure verification
    for idx, q in enumerate(item.hunt_guide.queries):
        is_valid = True
        error_msg = ""
        
        # Clean any accidental markdown codeblock wraps
        clean_query = q.query.strip()
        if clean_query.startswith("```"):
            lines = clean_query.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            clean_query = "\n".join(lines).strip()
            q.query = clean_query
            
        if q.query_type.upper() == "SIGMA":
            try:
                data = yaml.safe_load(q.query)
                if not isinstance(data, dict):
                    is_valid = False
                    error_msg = "Sigma query is not a valid YAML dictionary."
                else:
                    if "logsource" not in data or "detection" not in data:
                        is_valid = False
                        error_msg = "Missing 'logsource' or 'detection' sections in Sigma YAML."
            except Exception as e:
                is_valid = False
                error_msg = f"Failed to parse Sigma YAML: {e}"
                
        elif q.query_type.upper() == "KQL":
            if not q.query:
                is_valid = False
                error_msg = "KQL query is empty."
            elif "|" not in q.query:
                is_valid = False
                error_msg = "KQL query is missing pipe (|) operators."
                
        if not is_valid:
            has_errors = True
            validation_notes.append(f"Query {idx+1} ({q.query_type}): {error_msg}")
            logger.warning(f"Query {idx+1} ({q.query_type}) failed check: {error_msg}")
            
    # 2. If errors are present and we have credentials, trigger LLM Self-Correction Loop
    if has_errors:
        client, is_offline = get_llm_client()
            
        if is_offline:
            item.hunt_guide.critic_status = "Failed"
            item.hunt_guide.critic_notes = validation_notes + ["LLM client is offline (no credentials available for critic self-correction)."]
            return item
            
        # Run real LLM Correction Loop
        try:
            logger.info("Triggering LLM self-correction loop to repair queries...")
            
            # Load stack profile log sources for reference
            config_path = os.path.join("config", "stack_profile.yaml")
            log_sources = []
            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f) or {}
                    log_sources = config.get("log_sources", [])
                    
            model_name = "gemini-3.1-flash-lite"  # Use fast model for critique triage
            
            # Load externalized prompts
            prompts = load_prompts()
            critic_prompts = prompts.get("critic", {})
            
            system_instruction_tmpl = critic_prompts.get("system_instruction", "")
            system_instruction = system_instruction_tmpl.format(
                log_sources=log_sources
            )
            
            queries_str = ""
            for idx, q in enumerate(item.hunt_guide.queries):
                queries_str += f"\n--- Query {idx+1} ({q.query_type}) ---\nDescription: {q.description}\nQuery text:\n{q.query}\n"
                
            user_prompt_tmpl = critic_prompts.get("user_prompt_template", "")
            user_prompt = user_prompt_tmpl.format(
                title=item.title,
                validation_notes="\n".join(validation_notes),
                queries=queries_str
            )
            
            response = client.models.generate_content(
                model=model_name,
                contents=user_prompt,
                config={
                    'response_mime_type': 'application/json',
                    'response_schema': CriticFeedback,
                    'system_instruction': system_instruction,
                }
            )
            
            feedback = response.parsed
            if feedback and feedback.corrected_queries:
                logger.info(f"LLM successfully corrected {len(feedback.corrected_queries)} queries.")
                item.hunt_guide.queries = feedback.corrected_queries
                item.hunt_guide.critic_status = "Fixed"
                item.hunt_guide.critic_notes = validation_notes
            else:
                item.hunt_guide.critic_status = "Failed"
                item.hunt_guide.critic_notes = validation_notes + ["Parsed Critic feedback was empty."]
                
        except Exception as e:
            logger.error(f"LLM self-correction loop failed: {e}")
            item.hunt_guide.critic_status = "Failed"
            item.hunt_guide.critic_notes = validation_notes + [f"LLM self-correction failed: {e}"]
                
    else:
        logger.info("All queries passed validation checks successfully.")
        item.hunt_guide.critic_status = "Passed"
        item.hunt_guide.critic_notes = []
        
    return item

@node(name="critic_node")
async def critic_node(ctx: Context, item: IntelItem) -> IntelItem:
    return await critic_impl(ctx, item)



