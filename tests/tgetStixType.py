#!/usr/bin/env python3
"""Test get_stix_type method"""

from mitre_mcp_server.utils.stix_parser import get_manager

print("🧪 Testing get_stix_type...\n")

manager = get_manager()
manager.load_domain("enterprise")

# Get different object types and check their STIX types
print("Test 1: Get STIX type for Phishing technique")
tech = manager.get_technique_by_id("T1566")
stix_type = manager.get_stix_type(tech.id)
print(f"✓ STIX ID: {tech.id}")
print(f"  Type: {stix_type}")
print(f"  Correct? {stix_type == 'attack-pattern'}")

print("\nTest 2: Get STIX type for APT29 group")
group = manager.get_group_by_name("APT29")
if group:
    stix_type = manager.get_stix_type(group.id)
    print(f"✓ STIX ID: {group.id}")
    print(f"  Type: {stix_type}")
    print(f"  Correct? {stix_type == 'intrusion-set'}")

print("\nTest 3: Invalid STIX ID")
invalid_type = manager.get_stix_type("invalid-id-123")
if invalid_type is None:
    print("✓ Correctly returned None for invalid ID")
else:
    print(f"✗ Should return None, got: {invalid_type}")

print("\n✅ Test complete!")