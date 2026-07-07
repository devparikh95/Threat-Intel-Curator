from typing import Any, Optional, List
from pydantic import BaseModel, Field

class HuntQuery(BaseModel):
    query_type: str = Field(..., description="The query language/type, e.g., 'KQL' or 'Sigma'")
    query: str = Field(..., description="The actual query string")
    description: str = Field(..., description="Brief explanation of what this query hunts for")

class HuntGuide(BaseModel):
    threat_context: str = Field(..., description="High-level background on the threat and technical behavior")
    why_it_matters: str = Field(..., description="Analysis of why this threat is relevant to the organization's tech stack")
    queries: List[HuntQuery] = Field(default_factory=list, description="List of KQL and Sigma hunt queries")
    interpretation_guidance: str = Field(..., description="Guidance on what a query hit or miss means for the analyst")
    critic_status: str = Field("Not Run", description="Validation status of the queries: Not Run, Passed, Fixed, or Failed")
    critic_notes: List[str] = Field(default_factory=list, description="Validation or error notes from the critic")

class IntelItem(BaseModel):
    id: str = Field(..., description="Unique identifier for the intelligence item")
    title: str = Field(..., description="Title of the advisory or writeup")
    source: str = Field(..., description="The source of the intel (e.g., 'NVD', 'RSS: MSRC', 'GitHub PoC')")
    content: str = Field(..., description="Raw text content / description of the threat")
    cve_id: Optional[str] = Field(None, description="Associated CVE identifier, if any")
    cpe: Optional[str] = Field(None, description="CPE string or product identifier, if any")
    severity: Optional[float] = Field(None, description="CVSS severity score, if any")
    
    # Process annotations
    quarantined: bool = Field(False, description="Whether this item was quarantined by the security screen")
    quarantine_reason: Optional[str] = Field(None, description="Reason for quarantine, if applicable")
    relevance_verdict: Optional[bool] = Field(None, description="Relevance verdict: True, False, or None if unexamined")
    relevance_reason: Optional[str] = Field(None, description="Explanation for the relevance decision")
    grounding_status: Optional[str] = Field("Pending", description="Grounding status: Grounded, Failed, Pending, or Not Applicable")
    grounding_details: Optional[str] = Field(None, description="Details of grounding validation against authoritative records")
    hunt_guide: Optional[HuntGuide] = Field(None, description="Generated hunt guide containing context and queries")

class PipelineState(BaseModel):
    items: List[IntelItem] = Field(default_factory=list, description="Active threat intelligence items being processed")
    quarantined_items: List[IntelItem] = Field(default_factory=list, description="Items quarantined due to security screen violations")
    briefing_path: Optional[str] = Field(None, description="Path where the final briefing was written")
