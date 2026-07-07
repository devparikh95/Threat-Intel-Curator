import pytest
import json
from unittest.mock import patch
from src.agent.state import IntelItem
from src.agent.nodes.grounding import grounding_impl

@pytest.mark.asyncio
@patch("src.agent.nodes.grounding.nvd_query")
async def test_grounding_success(mock_nvd):
    item = IntelItem(
        id="CVE-2026-9999",
        title="Test CVE",
        source="Test",
        content="Test content",
        cve_id="CVE-2026-9999",
        severity=None,
        cpe=None
    )
    
    nvd_response = {
        "cve_id": "CVE-2026-9999",
        "description": "Exploit details about CVE-2026-9999",
        "cvss_score": 9.8,
        "cpes": ["cpe:2.3:o:paloaltonetworks:pan-os:10.1.0"]
    }
    mock_nvd.return_value = json.dumps(nvd_response)
    
    result = await grounding_impl(None, item)
    
    assert result.grounding_status == "Grounded"
    assert result.severity == 9.8
    assert result.cpe == "cpe:2.3:o:paloaltonetworks:pan-os:10.1.0"
    assert "Verified CVE CVE-2026-9999 against NVD" in result.grounding_details
    mock_nvd.assert_called_once_with("CVE-2026-9999")

@pytest.mark.asyncio
@patch("src.agent.nodes.grounding.nvd_query")
async def test_grounding_unverified_preserves_source_claims(mock_nvd):
    """When NVD cannot confirm a CVE, the item is flagged Unverified and the
    source-provided severity/CPE are preserved but explicitly labelled unverified
    (never silently promoted to authoritative)."""
    item = IntelItem(
        id="CVE-2099-90001",
        title="Synthetic CVE",
        source="Test",
        content="Test content",
        cve_id="CVE-2099-90001",
        severity=9.8,
        cpe="cpe:2.3:o:paloaltonetworks:pan-os:10.1.0"
    )

    mock_nvd.return_value = json.dumps({"error": "No details found for CVE-2099-90001"})

    result = await grounding_impl(None, item)

    assert result.grounding_status == "Unverified"
    assert "Could not independently verify" in result.grounding_details
    assert "UNVERIFIED" in result.grounding_details
    # Source claims are preserved (for ranking) but flagged, not overwritten.
    assert result.severity == 9.8
    assert result.cpe == "cpe:2.3:o:paloaltonetworks:pan-os:10.1.0"
    mock_nvd.assert_called_once_with("CVE-2099-90001")

@pytest.mark.asyncio
async def test_grounding_no_cve():
    item = IntelItem(
        id="BLOG-101",
        title="Test Blog",
        source="Test",
        content="Test content",
        cve_id=None
    )
    result = await grounding_impl(None, item)
    assert result.grounding_status == "Not Applicable"
    assert "No CVE ID to verify" in result.grounding_details
