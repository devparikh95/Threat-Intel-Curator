import pytest
import io
import json
import os
from unittest.mock import patch, MagicMock
from src.agent.state import IntelItem
from src.agent.nodes.relevance_analyzer import relevance_analyzer_impl, RelevanceVerdict

@pytest.mark.asyncio
async def test_relevance_analyzer_fallback_no_credentials():
    item = IntelItem(
        id="BLOG-TEST-1",
        title="Phishing Advisory",
        source="RSS",
        content="Threat actors are using phishing kits to steal credentials.",
    )
    
    mock_stack_yaml = """
generic_threat_interests:
  - phishing
log_sources:
  - edr_process_events
"""
    
    def mock_exists(path):
        return True
        
    def mock_open_impl(path, mode="r", encoding=None):
        return io.StringIO(mock_stack_yaml)

    # Ensure no credentials are set in environment for this test
    with patch.dict(os.environ, {}, clear=True), \
         patch("os.path.exists", side_effect=mock_exists), \
         patch("builtins.open", side_effect=mock_open_impl):
         
         with pytest.raises(RuntimeError) as exc_info:
             await relevance_analyzer_impl(None, item)
         assert "LLM client is offline" in str(exc_info.value)

@pytest.mark.asyncio
@patch("src.agent.nodes.relevance_analyzer.load_prompts")
@patch("src.agent.nodes.relevance_analyzer.get_llm_client")
async def test_relevance_analyzer_llm_success(mock_get_llm_client, mock_load_prompts):
    item = IntelItem(
        id="BLOG-TEST-2",
        title="Malware advisory",
        source="RSS",
        content="Some malicious activity description",
    )
    
    mock_stack_yaml = """
generic_threat_interests:
  - malware
log_sources:
  - edr_process_events
models:
  relevance_analyzer: "gemini-2.5-flash"
"""
    
    def mock_exists(path):
        return True
        
    def mock_open_impl(path, mode="r", encoding=None):
        return io.StringIO(mock_stack_yaml)

    # Setup GenAI Mock
    mock_client = MagicMock()
    mock_get_llm_client.return_value = (mock_client, False)
    mock_load_prompts.return_value = {
        "relevance_analyzer": {
            "system_instruction": "System: {log_sources} {interests}",
            "user_prompt_template": "User: {title} {source} {content}"
        }
    }
    
    mock_response = MagicMock()
    mock_response.parsed = RelevanceVerdict(
        relevance_verdict=True,
        relevance_reason="LLM verified relevance: organization has edr logs to detect this malware."
    )
    mock_client.models.generate_content.return_value = mock_response

    # Set mock credential in environment
    with patch.dict(os.environ, {"GOOGLE_API_KEY": "mock_key"}), \
         patch("os.path.exists", side_effect=mock_exists), \
         patch("builtins.open", side_effect=mock_open_impl):
          
         result = await relevance_analyzer_impl(None, item)
         
         # Assert mock LLM response was parsed and set correctly
         assert result.relevance_verdict is True
         assert "LLM verified relevance" in result.relevance_reason
         mock_client.models.generate_content.assert_called_once()

@pytest.mark.asyncio
@patch("src.agent.nodes.relevance_analyzer.load_prompts")
@patch("src.agent.nodes.relevance_analyzer.get_llm_client")
async def test_relevance_analyzer_llm_failure_fallback(mock_get_llm_client, mock_load_prompts):
    item = IntelItem(
        id="BLOG-TEST-3",
        title="Phishing kit campaign",
        source="RSS",
        content="Stealing cloud tokens via phishing kits.",
    )
    
    mock_stack_yaml = """
generic_threat_interests:
  - phishing
log_sources:
  - cloudtrail
"""
    
    def mock_exists(path):
        return True
        
    def mock_open_impl(path, mode="r", encoding=None):
        return io.StringIO(mock_stack_yaml)

    # Setup GenAI Mock to raise exception
    mock_client = MagicMock()
    mock_get_llm_client.return_value = (mock_client, False)
    mock_load_prompts.return_value = {
        "relevance_analyzer": {
            "system_instruction": "System: {log_sources} {interests}",
            "user_prompt_template": "User: {title} {source} {content}"
        }
    }
    mock_client.models.generate_content.side_effect = Exception("API Quota Exceeded")

    with patch.dict(os.environ, {"GOOGLE_CLOUD_PROJECT": "mock_project"}), \
         patch("os.path.exists", side_effect=mock_exists), \
         patch("builtins.open", side_effect=mock_open_impl):
          
         with pytest.raises(Exception) as exc_info:
             await relevance_analyzer_impl(None, item)
         assert "API Quota Exceeded" in str(exc_info.value)
