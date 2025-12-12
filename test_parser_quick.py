"""Quick test of the STIX parser"""

from mitre_mcp_server.utils.stix_parser import get_manager

# print("🧪 Testing STIX Parser...\n")

# # Get the manager
# manager = get_manager()

# # Load enterprise domain
# print("📥 Loading enterprise domain...")
# manager.load_domain("enterprise")

# # Get stats
# stats = manager.get_stats("enterprise")
# print(f"\n📊 Stats: {stats}")

# # Test: Get a technique
# print("\n🔍 Testing: Get technique T1566 (Phishing)...")
# tech = manager.get_technique_by_id("T1566")
# if tech:
#     print(f"✓ Found: {tech.name}")
# else:
#     print("✗ Not found")

# # Test: Search groups
# print("\n🔍 Testing: Search for APT29...")
# groups = manager.search_groups("Deputy Dog")
# if groups:
#     print(f"✓ Found {len(groups)} group(s)")
#     print(f"   Name: {groups[0].name}")
# else:
#     print("✗ Not found")

# print("\n✅ Parser test complete!")

manager = get_manager()
manager.load_domain("enterprise")

# Get the technique
tech = manager.get_technique_by_id("T1566")

print(f"Type: {type(tech)}")
print(f"\nRaw object: {tech}")
print(f"\n--- Attributes ---")
print(f"Name: {tech.name}")
print(f"ID (STIX): {tech.id}")
print(f"Description: {tech.description[:200]}...")  # First 200 chars
print(f"\nHas 'kill_chain_phases'? {hasattr(tech, 'kill_chain_phases')}")
if hasattr(tech, 'kill_chain_phases'):
    print(f"Tactics: {tech.kill_chain_phases}")