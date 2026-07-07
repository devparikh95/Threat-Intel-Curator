import pytest
import os
from unittest.mock import patch, MagicMock
from src.agent.state import IntelItem, HuntGuide, HuntQuery
from src.agent.nodes.critic import critic_impl, CriticFeedback

@pytest.mark.asyncio
async def test_critic_valid_queries():
    queries = [
        HuntQuery(
            query_type="KQL",
            query="DeviceProcessEvents | where ProcessCommandLine has 'exploit'",
            description="Valid process query"
        ),
        HuntQuery(
            query_type="Sigma",
            query="logsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: 'suspicious'\n  condition: selection",
            description="Valid Sigma query"
        )
    ]
    
    item = IntelItem(
        id="CVE-2026-9999",
        title="Valid Test CVE",
        source="NVD",
        content="Details",
        hunt_guide=HuntGuide(
            threat_context="Context",
            why_it_matters="Matters",
            queries=queries,
            interpretation_guidance="Guidance"
        )
    )
    
    result = await critic_impl(None, item)
    assert result.hunt_guide is not None
    assert "VALIDATION" not in result.hunt_guide.queries[0].description
    assert "VALIDATION" not in result.hunt_guide.queries[1].description

@pytest.mark.asyncio
async def test_critic_invalid_queries_fallback_no_credentials():
    queries = [
        HuntQuery(
            query_type="KQL",
            query="DeviceProcessEvents without pipe operators",
            description="Invalid process query"
        ),
        HuntQuery(
            query_type="Sigma",
            query="invalid: yaml: string: - {",
            description="Invalid Sigma query"
        )
    ]
    
    item = IntelItem(
        id="CVE-2026-9999",
        title="Invalid Test CVE",
        source="NVD",
        content="Details",
        hunt_guide=HuntGuide(
            threat_context="Context",
            why_it_matters="Matters",
            queries=queries,
            interpretation_guidance="Guidance"
        )
    )
    
    with patch.dict(os.environ, {}, clear=True):
        result = await critic_impl(None, item)
        assert result.hunt_guide.critic_status == "Failed"
        assert any("offline" in note for note in result.hunt_guide.critic_notes)

@pytest.mark.asyncio
@patch("src.agent.nodes.critic.load_prompts")
@patch("src.agent.nodes.critic.get_llm_client")
async def test_critic_invalid_queries_llm_success(mock_get_llm_client, mock_load_prompts):
    queries = [
        HuntQuery(
            query_type="KQL",
            query="DeviceProcessEvents without pipe operators",
            description="Invalid process query"
        )
    ]
    
    item = IntelItem(
        id="CVE-2026-9999",
        title="Invalid Test CVE",
        source="NVD",
        content="Details",
        hunt_guide=HuntGuide(
            threat_context="Context",
            why_it_matters="Matters",
            queries=queries,
            interpretation_guidance="Guidance"
        )
    )
    
    # Setup GenAI Mock
    mock_client = MagicMock()
    mock_get_llm_client.return_value = (mock_client, False)
    mock_load_prompts.return_value = {
        "critic": {
            "system_instruction": "System: {log_sources}",
            "user_prompt_template": "User: {title} {validation_notes} {queries}"
        }
    }
    
    mock_response = MagicMock()
    mock_response.parsed = CriticFeedback(
        corrected_queries=[
            HuntQuery(
                query_type="KQL",
                query="DeviceProcessEvents | where ProcessCommandLine has 'fixed-exploit'",
                description="Fixed process query"
            )
        ]
    )
    mock_client.models.generate_content.return_value = mock_response

    with patch.dict(os.environ, {"GOOGLE_API_KEY": "mock_key"}):
        result = await critic_impl(None, item)
        assert result.hunt_guide is not None
        assert result.hunt_guide.queries[0].query == "DeviceProcessEvents | where ProcessCommandLine has 'fixed-exploit'"
        mock_client.models.generate_content.assert_called_once()

@pytest.mark.asyncio
@patch("src.agent.nodes.critic.load_prompts")
@patch("src.agent.nodes.critic.get_llm_client")
async def test_critic_invalid_queries_llm_failure(mock_get_llm_client, mock_load_prompts):
    queries = [
        HuntQuery(
            query_type="KQL",
            query="DeviceProcessEvents without pipe",
            description="Invalid process query"
        )
    ]
    
    item = IntelItem(
        id="CVE-2026-9999",
        title="Invalid Test CVE",
        source="NVD",
        content="Details",
        hunt_guide=HuntGuide(
            threat_context="Context",
            why_it_matters="Matters",
            queries=queries,
            interpretation_guidance="Guidance"
        )
    )
    
    mock_client = MagicMock()
    mock_get_llm_client.return_value = (mock_client, False)
    mock_load_prompts.return_value = {
        "critic": {
            "system_instruction": "System: {log_sources}",
            "user_prompt_template": "User: {title} {validation_notes} {queries}"
        }
    }
    mock_client.models.generate_content.side_effect = Exception("API Unavailable")

    with patch.dict(os.environ, {"GOOGLE_API_KEY": "mock_key"}):
        result = await critic_impl(None, item)
        assert result.hunt_guide.critic_status == "Failed"
        assert any("API Unavailable" in note for note in result.hunt_guide.critic_notes)
