from google.adk.workflow import node
from google.adk import Context
from src.agent.state import IntelItem
from src.mcp.server import nvd_query
import json
from src.agent.utils.logging_utils import get_logger

logger = get_logger("grounding")

async def grounding_impl(ctx: Context, item: IntelItem) -> IntelItem:
    """
    Core logic of CVE grounding, callable directly in tests.
    """
    logger.info(f"Grounding CVE details for {item.id}...")
    
    if not item.cve_id:
        item.grounding_status = "Not Applicable"
        item.grounding_details = "No CVE ID to verify."
        return item
        
    try:
        # Call NVD query tool
        nvd_json = nvd_query(item.cve_id)
        nvd_data = json.loads(nvd_json)
        
        if "error" in nvd_data:
            # NVD could not confirm this CVE (not found / API unavailable).
            # Anti-hallucination stance: do NOT fabricate authoritative facts and
            # do NOT silently promote the source advisory's claims to "verified".
            # Flag the item Unverified and keep its source-provided fields clearly
            # labelled as unverified so downstream nodes never assert them as truth.
            logger.warning(f"NVD verification unavailable for {item.cve_id}: {nvd_data['error']}")
            item.grounding_status = "Unverified"
            item.grounding_details = (
                f"Could not independently verify {item.cve_id} against NVD "
                f"({nvd_data['error']}). Severity ({item.severity}) and CPE "
                f"({item.cpe}) shown are UNVERIFIED claims from the source advisory."
            )
            return item

        # Success path - authoritative NVD record overrides any source claims
        severity = nvd_data.get("cvss_score")
        cpes = nvd_data.get("cpes", [])
        desc = nvd_data.get("description", "")

        if severity is not None:
            item.severity = severity
        if cpes:
            item.cpe = cpes[0]

        item.grounding_status = "Grounded"
        item.grounding_details = f"Verified CVE {item.cve_id} against NVD. Severity: {severity or 'N/A'}. Description: {desc[:100]}... CPEs: {cpes}"

    except Exception as e:
        logger.error(f"Error during NVD query for {item.cve_id}: {e}")
        item.grounding_status = "Failed"
        item.grounding_details = f"Grounding Error: {str(e)}"

    return item

@node(name="grounding_node")
async def grounding_node(ctx: Context, item: IntelItem) -> IntelItem:
    return await grounding_impl(ctx, item)

