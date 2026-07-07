import os
import yaml
from typing import Tuple, Dict, Any
from google import genai
from src.agent.utils.logging_utils import get_logger

logger = get_logger("llm_utils")

def get_llm_client() -> Tuple[genai.Client | None, bool]:
    """
    Checks environment credentials and instantiates a genai.Client.
    Returns (client, is_offline_mode).
    """
    has_project = bool(os.environ.get("GOOGLE_CLOUD_PROJECT"))
    has_api_key = bool(os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"))
    
    # Check if we have standard GCP credentials available as fallback
    has_gcp_creds = False
    if not has_project and not has_api_key:
        try:
            import google.auth
            _, project = google.auth.default()
            if project:
                os.environ["GOOGLE_CLOUD_PROJECT"] = project
                has_gcp_creds = True
        except Exception:
            pass
            
    if not (has_project or has_api_key or has_gcp_creds):
        return None, True
        
    try:
        client = genai.Client()
        return client, False
    except Exception as e:
        logger.warning(f"Failed to initialize genai.Client: {e}. Falling back to offline mode.")
        return None, True

def load_prompts() -> Dict[str, Any]:
    """
    Loads externalized prompts from config/prompts.yaml.
    """
    prompts_path = os.path.join("config", "prompts.yaml")
    if not os.path.exists(prompts_path):
        logger.warning(f"Prompts configuration file not found at {prompts_path}!")
        return {}
    try:
        with open(prompts_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Error loading prompts configuration: {e}")
        return {}
