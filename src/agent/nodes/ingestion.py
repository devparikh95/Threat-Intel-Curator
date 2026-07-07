from google.adk.workflow import node
from google.adk import Context
from src.agent.state import IntelItem
from typing import List
import os
import json
import yaml
import re
from src.mcp.server import fetch_rss, github_search, nvd_query
from src.agent.utils.logging_utils import get_logger

logger = get_logger("ingestion")

async def ingestion_impl(ctx: Context, node_input: str) -> List[IntelItem]:
    """
    Core logic of ingestion, callable directly in tests.
    """
    input_str = (node_input or "").strip().lower()
    
    # 1. Snapshot Mode
    if not input_str or input_str == "snapshot":
        snapshot_path = os.path.join("data", "snapshot", "items.json")
        logger.info(f"Running in Snapshot Mode. Loading from: {snapshot_path}")
        if not os.path.exists(snapshot_path):
            logger.warning(f"Snapshot file {snapshot_path} not found! Returning empty list.")
            return []
            
        with open(snapshot_path, "r") as f:
            items_data = json.load(f)
        return [IntelItem(**item) for item in items_data]
        
    # 2. Live Mode
    logger.info("Running in Live Mode. Fetching from external feeds...")
    items: List[IntelItem] = []
    
    # Read configs
    sources_path = os.path.join("config", "sources.yaml")
    stack_path = os.path.join("config", "stack_profile.yaml")
    
    sources = {}
    if os.path.exists(sources_path):
        with open(sources_path, "r") as f:
            sources = yaml.safe_load(f) or {}
            
    stack_profile = {}
    if os.path.exists(stack_path):
        with open(stack_path, "r") as f:
            stack_profile = yaml.safe_load(f) or {}
            
    # Fetch RSS feeds
    rss_urls = sources.get("rss", [])
    for url in rss_urls:
        logger.info(f"Fetching RSS feed: {url}")
        try:
            rss_json = fetch_rss(url)
            feed_data = json.loads(rss_json)
            if "error" in feed_data:
                logger.error(f"Error fetching RSS {url}: {feed_data['error']}")
                continue
                
            feed_title = feed_data.get("feed_title", "Unknown RSS")
            for entry in feed_data.get("entries", []):
                title = entry.get("title", "")
                summary = entry.get("summary", "")
                link = entry.get("link", "")
                entry_id = entry.get("id") or link or title
                
                # Check for CVEs in title/summary
                cve_id = None
                cve_matches = re.findall(r"\b(CVE-\d{4}-\d{4,7})\b", f"{title} {summary}", re.IGNORECASE)
                if cve_matches:
                    cve_id = cve_matches[0].upper()
                    
                # Normalize source name
                source_name = f"RSS: {feed_title}"
                
                # Initialize fields
                cpe = None
                severity = None
                
                # If CVE found, enrich with NVD data
                if cve_id:
                    logger.info(f"Found CVE {cve_id} in RSS. Querying NVD details...")
                    try:
                        nvd_json = nvd_query(cve_id)
                        nvd_data = json.loads(nvd_json)
                        if "error" not in nvd_data:
                            severity = nvd_data.get("cvss_score")
                            cpes = nvd_data.get("cpes", [])
                            if cpes:
                                # Pick the first CPE
                                cpe = cpes[0]
                            # Optionally append NVD description for richer context
                            nvd_desc = nvd_data.get("description")
                            if nvd_desc:
                                summary = f"{summary}\n\n[NVD Reference Description]\n{nvd_desc}"
                    except Exception as e:
                        logger.error(f"Failed to enrich CVE {cve_id} from NVD: {e}")
                        
                item = IntelItem(
                    id=f"RSS-{entry_id}",
                    title=title,
                    source=source_name,
                    content=summary,
                    cve_id=cve_id,
                    cpe=cpe,
                    severity=severity
                )
                items.append(item)
        except Exception as e:
            logger.error(f"Error processing RSS feed {url}: {e}")
            
    # Fetch GitHub PoCs
    # We search GitHub based on products in the stack profile to find relevant PoCs
    products = stack_profile.get("products", [])
    for prod in products:
        vendor = prod.get("vendor", "")
        product_name = prod.get("product", "")
        cpe_prefix = prod.get("cpe_prefix", "")
        
        query = f"{product_name} exploit"
        logger.info(f"Searching GitHub for PoCs with query: '{query}'")
        try:
            github_json = github_search(query)
            repos = json.loads(github_json)
            if isinstance(repos, dict) and "error" in repos:
                logger.error(f"Error searching GitHub: {repos['error']}")
                continue
                
            for repo in repos:
                name = repo.get("name", "")
                desc = repo.get("description", "") or ""
                html_url = repo.get("html_url", "")
                
                # Check for CVEs
                cve_id = None
                cve_matches = re.findall(r"\b(CVE-\d{4}-\d{4,7})\b", f"{name} {desc}", re.IGNORECASE)
                if cve_matches:
                    cve_id = cve_matches[0].upper()
                    
                cpe = cpe_prefix or None
                severity = None
                
                if cve_id:
                    logger.info(f"Found CVE {cve_id} in GitHub repo. Querying NVD...")
                    try:
                        nvd_json = nvd_query(cve_id)
                        nvd_data = json.loads(nvd_json)
                        if "error" not in nvd_data:
                            severity = nvd_data.get("cvss_score")
                            cpes = nvd_data.get("cpes", [])
                            if cpes:
                                cpe = cpes[0]
                    except Exception as e:
                        logger.error(f"Failed to enrich CVE {cve_id}: {e}")
                        
                item = IntelItem(
                    id=f"GH-{repo.get('full_name')}",
                    title=f"GitHub Exploit PoC: {name}",
                    source="GitHub PoC",
                    content=f"Repository: {html_url}\nDescription: {desc}",
                    cve_id=cve_id,
                    cpe=cpe,
                    severity=severity
                )
                items.append(item)
        except Exception as e:
            logger.error(f"Error processing GitHub search for {product_name}: {e}")
            
    return items

@node(name="ingestion_node")
async def ingestion_node(ctx: Context, node_input: str) -> List[IntelItem]:
    return await ingestion_impl(ctx, node_input)
