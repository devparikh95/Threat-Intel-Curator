import pytest
from src.agent.state import IntelItem
from src.agent.nodes.stack_filter import stack_filter_impl

@pytest.mark.asyncio
async def test_stack_filter_match():
    item = IntelItem(
        id="CVE-TEST-1",
        title="Test Palo Alto networks OS issue",
        source="Test",
        content="A vulnerability in PAN-OS.",
        cpe="cpe:2.3:o:paloaltonetworks:pan-os:10.1.0"
    )
    result = await stack_filter_impl(None, item)
    assert result.relevance_verdict is True
    assert "Deterministic match" in result.relevance_reason

@pytest.mark.asyncio
async def test_stack_filter_mismatch():
    item = IntelItem(
        id="CVE-TEST-2",
        title="Test Fake product issue",
        source="Test",
        content="A vulnerability in Fake OS.",
        cpe="cpe:2.3:o:fake:product:1.0.0"
    )
    result = await stack_filter_impl(None, item)
    assert result.relevance_verdict is False
    assert "No CPE prefix match" in result.relevance_reason
