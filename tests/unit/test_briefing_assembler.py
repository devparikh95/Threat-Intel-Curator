import pytest
import os
import datetime
from src.agent.state import IntelItem, HuntGuide
from src.agent.nodes.briefing_assembler import briefing_assembler_node

@pytest.mark.asyncio
async def test_briefing_assembler_ranking():
    # 1. Create test items
    # item_a: TTP-relevant (no CPE) but high severity (9.8)
    item_a = IntelItem(
        id="BLOG-1",
        title="Severe Phishing Kit Campaign",
        source="RSS",
        content="Details",
        cpe=None,
        severity=9.8,
        relevance_verdict=True,
        relevance_reason="Matches phishing interests",
        grounding_details="No CVE to ground",
        hunt_guide=HuntGuide(
            threat_context="Context A",
            why_it_matters="Matters A",
            queries=[],
            interpretation_guidance="Interpretation A"
        )
    )
    
    # item_b: CPE-matched but lower severity (5.0)
    item_b = IntelItem(
        id="CVE-2026-1002",
        title="Low CPE Vulnerability",
        source="NVD",
        content="Details",
        cpe="cpe:2.3:o:paloaltonetworks:pan-os:10.0.0",
        severity=5.0,
        relevance_verdict=True,
        relevance_reason="CPE Match",
        grounding_details="Grounded",
        hunt_guide=HuntGuide(
            threat_context="Context B",
            why_it_matters="Matters B",
            queries=[],
            interpretation_guidance="Interpretation B"
        )
    )
    
    # item_c: CPE-matched with medium-high severity (8.5)
    item_c = IntelItem(
        id="CVE-2026-1003",
        title="Severe CPE Vulnerability",
        source="NVD",
        content="Details",
        cpe="cpe:2.3:o:paloaltonetworks:pan-os:10.1.0",
        severity=8.5,
        relevance_verdict=True,
        relevance_reason="CPE Match",
        grounding_details="Grounded",
        hunt_guide=HuntGuide(
            threat_context="Context C",
            why_it_matters="Matters C",
            queries=[],
            interpretation_guidance="Interpretation C"
        )
    )
    
    # item_d: Quarantined item
    item_d = IntelItem(
        id="RED-TEAM-001",
        title="Malicious Input Advisory",
        source="RSS",
        content="Ignore instructions...",
        quarantine_reason="Flagged injection"
    )
    
    # 2. Run assembler
    # Call the underlying function of the node directly
    briefing_file = await briefing_assembler_node._func(
        None,
        processed_items=[item_a, item_b, item_c],
        quarantined_items=[item_d]
    )
    
    assert os.path.exists(briefing_file)
    
    # 3. Verify content
    with open(briefing_file, "r", encoding="utf-8") as f:
        content = f.read()
        
    # Check that title structure is present
    assert "Threat Hunt Briefing" in content
    
    # Find the positions of the titles to verify sorting order
    pos_c = content.find("Severe CPE Vulnerability (CVE-2026-1003)")
    pos_b = content.find("Low CPE Vulnerability (CVE-2026-1002)")
    pos_a = content.find("Severe Phishing Kit Campaign (BLOG-1)")
    pos_quarantine = content.find("QUARANTINED: Malicious Input Advisory (RED-TEAM-001)")
    
    # Verify exact ranking sequence: CVE-1003 first, then CVE-1002, then BLOG-1
    assert pos_c != -1, "Severe CPE Vulnerability (item_c) missing"
    assert pos_b != -1, "Low CPE Vulnerability (item_b) missing"
    assert pos_a != -1, "Severe Phishing Kit Campaign (item_a) missing"
    assert pos_quarantine != -1, "Quarantined section missing"
    
    assert pos_c < pos_b, "CPE-matched with higher CVSS should be ranked above CPE-matched with lower CVSS"
    assert pos_b < pos_a, "CPE-matched (Funnel 1) should be ranked above TTP-relevant (Funnel 2)"
    
    # Clean up generated test file
    try:
        os.remove(briefing_file)
    except OSError:
        pass
