from google.adk.workflow import node
from google.adk import Context
from src.agent.state import IntelItem
from typing import List
import os
import datetime
from src.agent.utils.logging_utils import get_logger

logger = get_logger("briefing_assembler")

async def briefing_assembler_impl(ctx: Context, processed_items: List[IntelItem], quarantined_items: List[IntelItem]) -> str:
    """
    Core logic of the briefing assembler, callable directly (in tests and the runner).
    Ranks relevant items and builds the daily Threat Hunt Briefing markdown document.
    Saves it to the briefings/ directory.
    """
    logger.info("Assembling briefing...")
    
    # 1. Separate relevant and non-relevant items
    relevant_items = [item for item in processed_items if item.relevance_verdict is True]
    
    # 2. Sort relevant items: CPE-matched items (Funnel 1) first, then TTP-relevant (Funnel 2), then by severity score
    def sort_key(item: IntelItem):
        is_cpe_match = 1 if item.cpe else 0
        severity_score = item.severity or 0.0
        return (is_cpe_match, severity_score)
        
    relevant_items.sort(key=sort_key, reverse=True)
    
    # 3. Format markdown content
    today_str = datetime.date.today().strftime("%Y-%m-%d")
    md_content = f"# Threat Hunt Briefing — {today_str}\n\n"
    md_content += f"> **Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    md_content += f"> **Monitored Threat Advisories:** {len(processed_items)}\n"
    md_content += f"> **Actionable Threats Identified:** {len(relevant_items)}\n\n"
    md_content += "---\n\n"
    
    if not relevant_items:
        md_content += "## No actionable threat hunts identified for your stack profile today.\n\n"
    else:
        md_content += "## 🎯 ACTIONABLE THREAT HUNTS\n\n"
        for i, item in enumerate(relevant_items, 1):
            guide = item.hunt_guide
            md_content += f"### {i}. {item.title} ({item.id})\n\n"
            md_content += f"- **Source:** {item.source}\n"
            md_content += f"- **Severity (CVSS):** {item.severity or 'N/A'}\n"
            md_content += f"- **Relevance Reason:** {item.relevance_reason}\n"
            md_content += f"- **Grounding:** {item.grounding_details}\n\n"
            
            if guide:
                md_content += f"- **Query Validation:** {guide.critic_status}\n"
                if guide.critic_notes:
                    notes = "; ".join(guide.critic_notes)
                    md_content += f"  *(Notes: {notes})*\n"
                md_content += "\n#### Threat Context\n"
                md_content += f"{guide.threat_context}\n\n"
                md_content += "#### Why It Matters to Our Stack\n"
                md_content += f"{guide.why_it_matters}\n\n"
                
                md_content += "#### Hunt Queries\n"
                for q in guide.queries:
                    md_content += f"**{q.query_type}:** *{q.description}*\n"
                    md_content += f"```\n{q.query}\n```\n\n"
                    
                md_content += "#### Hit/Miss Interpretation\n"
                md_content += f"{guide.interpretation_guidance}\n\n"
            md_content += "---\n\n"
            
    # 4. Quarantine human-review section
    md_content += "## 🛡️ SECURITY REVIEW & QUARANTINE LANE\n\n"
    if not quarantined_items:
        md_content += "No items were flagged or quarantined by the security screen today.\n"
    else:
        md_content += "The following items matched prompt-injection patterns and were quarantined to prevent agent poisoning:\n\n"
        for item in quarantined_items:
            md_content += f"### ⚠️ QUARANTINED: {item.title} ({item.id})\n\n"
            md_content += f"- **Source:** {item.source}\n"
            md_content += f"- **Quarantine Reason:** {item.quarantine_reason}\n"
            md_content += "- **Raw Content Preview:**\n"
            md_content += f"  > *{item.content[:200]}...*\n\n"
            
    # Write to briefings folder
    os.makedirs("briefings", exist_ok=True)
    file_path = os.path.join("briefings", f"{today_str}.md")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    logger.info(f"Briefing saved to {file_path}")
    return file_path

@node(name="briefing_assembler_node")
async def briefing_assembler_node(ctx: Context, processed_items: List[IntelItem], quarantined_items: List[IntelItem]) -> str:
    return await briefing_assembler_impl(ctx, processed_items, quarantined_items)
