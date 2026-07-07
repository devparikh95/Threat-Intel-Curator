import asyncio
import os
from src.agent.state import IntelItem, HuntGuide, HuntQuery
from src.agent.nodes.critic import critic_impl

async def main():
    print("--- Running Critic Demo ---")
    
    # 1. Create a dummy IntelItem with malformed queries
    queries = [
        HuntQuery(
            query_type="KQL",
            query="DeviceProcessEvents without pipe operators",
            description="Malformed process query"
        ),
        HuntQuery(
            query_type="Sigma",
            query="invalid: yaml\n  missing: sections\n  like: logsource",
            description="Malformed Sigma query"
        )
    ]
    
    item = IntelItem(
        id="CVE-2026-DEMO",
        title="Demo Item for Critic Validator",
        source="Demo",
        content="Testing the critic validator on malformed queries.",
        hunt_guide=HuntGuide(
            threat_context="Context",
            why_it_matters="Matters",
            queries=queries,
            interpretation_guidance="Guidance"
        )
    )
    
    print("\n[Input] Original Queries:")
    for i, q in enumerate(item.hunt_guide.queries):
        print(f"  {i+1}. [{q.query_type}] {q.query}")
        
    print("\n[Action] Running critic_impl()...\n")
    
    # 2. Run critic
    result = await critic_impl(None, item)
    
    # 3. Print the output
    print(f"\n[Result] Critic Status: {result.hunt_guide.critic_status}")
    if result.hunt_guide.critic_notes:
        print("[Result] Critic Notes:")
        for note in result.hunt_guide.critic_notes:
            print(f"  - {note}")
            
    print("\n[Output] Final Queries:")
    for i, q in enumerate(result.hunt_guide.queries):
        print(f"  {i+1}. [{q.query_type}] {q.query}")

if __name__ == "__main__":
    asyncio.run(main())
