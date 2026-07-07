import pytest
import io
import json
import os
from unittest.mock import patch, MagicMock
from src.agent.state import IntelItem, HuntGuide, HuntQuery
from src.agent.nodes.hunt_guide_generator import hunt_guide_generator_impl

@pytest.mark.asyncio
async def test_generator_fallback_no_credentials():
    item = IntelItem(
        id="CVE-2026-9999",
        title="Palo Alto Networks PAN-OS RCE",
        source="NVD",
        content="Exploit details",
        relevance_reason="CPE match"
    )
    
    mock_stack_yaml = """
generic_threat_interests:
  - malware
log_sources:
  - edr_process_events
"""
    
    def mock_exists(path):
        return True
        
    def mock_open_impl(path, mode="r", encoding=None):
        return io.StringIO(mock_stack_yaml)

    with patch.dict(os.environ, {}, clear=True), \
         patch("os.path.exists", side_effect=mock_exists), \
         patch("builtins.open", side_effect=mock_open_impl):
          
         with pytest.raises(RuntimeError) as exc_info:
             await hunt_guide_generator_impl(None, item)
         assert "LLM client is offline" in str(exc_info.value)

@pytest.mark.asyncio
@patch("src.agent.nodes.hunt_guide_generator.load_prompts")
@patch("src.agent.nodes.hunt_guide_generator.get_llm_client")
async def test_generator_llm_success(mock_get_llm_client, mock_load_prompts):
    item = IntelItem(
        id="CVE-2026-9999",
        title="Palo Alto Networks PAN-OS RCE",
        source="NVD",
        content="Exploit details",
        relevance_reason="CPE match"
    )
    
    mock_stack_yaml = """
generic_threat_interests:
  - malware
log_sources:
  - edr_process_events
models:
  hunt_guide_generator: "gemini-2.5-pro"
"""
    
    def mock_exists(path):
        return True
        
    def mock_open_impl(path, mode="r", encoding=None):
        return io.StringIO(mock_stack_yaml)

    # Setup GenAI Mock
    mock_client = MagicMock()
    mock_get_llm_client.return_value = (mock_client, False)
    mock_load_prompts.return_value = {
        "hunt_guide_generator": {
            "system_instruction": "System: {log_sources} {products}",
            "user_prompt_template": "User: {title} {source} {content} {relevance_reason} {grounding_details}"
        }
    }
    
    mock_response = MagicMock()
    mock_response.parsed = HuntGuide(
        threat_context="Technical analysis of PAN-OS RCE.",
        why_it_matters="Relevant to our Palo Alto firewalls.",
        queries=[
            HuntQuery(query_type="KQL", query="DeviceProcessEvents | where ProcessCommandLine has 'pan-os-exploit'", description="KQL query"),
            HuntQuery(query_type="Sigma", query="logsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: 'suspicious'\n  condition: selection", description="Sigma query")
        ],
        interpretation_guidance="Verify alerts."
    )
    mock_client.models.generate_content.return_value = mock_response

    with patch.dict(os.environ, {"GOOGLE_API_KEY": "mock_key"}), \
         patch("os.path.exists", side_effect=mock_exists), \
         patch("builtins.open", side_effect=mock_open_impl):
          
         result = await hunt_guide_generator_impl(None, item)
         
         assert result.hunt_guide is not None
         assert result.hunt_guide.threat_context == "Technical analysis of PAN-OS RCE."
         assert len(result.hunt_guide.queries) == 2
         assert "pan-os-exploit" in result.hunt_guide.queries[0].query
         mock_client.models.generate_content.assert_called_once()
