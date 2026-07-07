import pytest
import json
import io
import os
from unittest.mock import patch, MagicMock
from src.agent.nodes.ingestion import ingestion_impl
from src.agent.state import IntelItem

@pytest.mark.asyncio
async def test_ingestion_snapshot_mode():
    mock_items = [
        {
            "id": "CVE-2026-9999",
            "title": "Palo Alto Networks PAN-OS RCE",
            "source": "NVD",
            "content": "A vulnerability in PAN-OS",
            "cve_id": "CVE-2026-9999",
            "cpe": "cpe:2.3:o:paloaltonetworks:pan-os:10.1.0",
            "severity": 9.8,
            "quarantined": False
        }
    ]
    
    def mock_exists_impl(path):
        if "items.json" in path:
            return True
        return False

    def mock_open_impl(path, mode="r"):
        if "items.json" in path:
            return io.StringIO(json.dumps(mock_items))
        return io.StringIO("")

    with patch("os.path.exists", side_effect=mock_exists_impl), \
         patch("builtins.open", side_effect=mock_open_impl):
        
        result = await ingestion_impl(None, "snapshot")
        
        assert len(result) == 1
        assert result[0].id == "CVE-2026-9999"
        assert result[0].title == "Palo Alto Networks PAN-OS RCE"
        assert result[0].severity == 9.8

@pytest.mark.asyncio
@patch("src.agent.nodes.ingestion.fetch_rss")
@patch("src.agent.nodes.ingestion.github_search")
@patch("src.agent.nodes.ingestion.nvd_query")
async def test_ingestion_live_mode(mock_nvd, mock_github, mock_rss):
    rss_response = {
        "feed_title": "MSRC Blog",
        "feed_description": "Microsoft Security Response Center",
        "entries": [
            {
                "title": "New Defender advisory for CVE-2026-1111",
                "link": "https://example.com/1",
                "published": "2026-06-25",
                "summary": "This is a summary of CVE-2026-1111",
                "id": "msrc-1"
            }
        ]
    }
    mock_rss.return_value = json.dumps(rss_response)
    
    github_response = [
        {
            "name": "defender-exploit",
            "full_name": "user/defender-exploit",
            "html_url": "https://github.com/user/defender-exploit",
            "description": "Exploit PoC for defender",
            "stargazers_count": 5,
            "updated_at": "2026-06-25"
        }
    ]
    mock_github.return_value = json.dumps(github_response)
    
    nvd_response = {
        "cve_id": "CVE-2026-1111",
        "description": "Authoritative description of CVE-2026-1111",
        "cvss_score": 8.5,
        "cpes": ["cpe:2.3:a:microsoft:defender:1.0"]
    }
    mock_nvd.return_value = json.dumps(nvd_response)
    
    mock_sources_yaml = """
rss:
  - https://example.com/rss
github:
  poc_lookback_days: 7
"""
    mock_stack_yaml = """
products:
  - vendor: microsoft
    product: defender_for_endpoint
    cpe_prefix: "cpe:2.3:a:microsoft:defender"
"""
    
    def mock_exists(path):
        return True
        
    def mock_open_impl(path, mode="r"):
        if "sources.yaml" in path:
            return io.StringIO(mock_sources_yaml)
        elif "stack_profile.yaml" in path:
            return io.StringIO(mock_stack_yaml)
        return io.StringIO("")

    with patch("os.path.exists", side_effect=mock_exists), \
         patch("builtins.open", side_effect=mock_open_impl):
         
         result = await ingestion_impl(None, "live")
         
         assert len(result) >= 2
         
         # Find RSS item
         rss_item = next(item for item in result if item.source.startswith("RSS:"))
         assert rss_item.cve_id == "CVE-2026-1111"
         assert rss_item.severity == 8.5
         assert rss_item.cpe == "cpe:2.3:a:microsoft:defender:1.0"
         assert "NVD Reference Description" in rss_item.content
