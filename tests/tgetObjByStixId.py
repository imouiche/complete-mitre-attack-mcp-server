"""Test get_object_by_stix_id method"""

from mitre_mcp_server.utils.stix_parser import get_manager

print("🧪 Testing get_object_by_stix_id...\n")

manager = get_manager()
manager.load_domain("enterprise")

# First, get Phishing technique to see its STIX ID
tech = manager.get_technique_by_id("T1566")
stix_id = tech.id
print(f"Phishing STIX ID: {stix_id}\n")

# Test: Get it back using STIX ID
print("Test: Get object by STIX ID")
retrieved = manager.get_object_by_stix_id(stix_id)
if retrieved:
    print(f"✓ Found: {retrieved.name}")
    print(f"  Same object? {retrieved.id == tech.id}")
else:
    print("✗ Not found")

# Test invalid STIX ID
print("\nTest: Invalid STIX ID")
invalid = manager.get_object_by_stix_id("invalid-uuid-123")
if invalid is None:
    print("✓ Correctly returned None")
else:
    print("✗ Should have returned None")

print("\n✅ Test complete!")