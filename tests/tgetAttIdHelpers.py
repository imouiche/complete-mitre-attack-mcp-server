#!/usr/bin/env python3
"""Test get_attack_id method"""

from mitre_mcp_server.utils.stix_parser import get_manager

print("🧪 Testing get_attack_id...\n")

manager = get_manager()
manager.load_domain("enterprise")

# Test 1: Get ATT&CK ID from STIX ID for a technique
print("Test 1: Convert Phishing STIX ID to ATT&CK ID")
tech = manager.get_technique_by_id("T1566")
print(f"Original ATT&CK ID: T1566")
print(f"STIX ID: {tech.id}")
attack_id = manager.get_attack_id(tech.id)
print(f"Converted back to: {attack_id}")
print(f"✓ Match? {attack_id == 'T1566'}")

# Test 2: Get ATT&CK ID for a group
print("\nTest 2: Convert APT29 STIX ID to ATT&CK ID")
group = manager.get_group_by_name("APT29")
if group:
    attack_id = manager.get_attack_id(group.id)
    print(f"STIX ID: {group.id}")
    print(f"ATT&CK ID: {attack_id}")
    print(f"✓ Got ID: {attack_id}")

# Test 3: Invalid STIX ID
print("\nTest 3: Invalid STIX ID")
invalid_id = manager.get_attack_id("invalid-stix-id-123")
if invalid_id is None:
    print("✓ Correctly returned None for invalid ID")
else:
    print(f"✗ Should return None, got: {invalid_id}")

print("\n✅ Test complete!")

# Add this test at the end
print("\nTest 4: Get name from STIX ID")
tech = manager.get_technique_by_id("T1566")
name = manager.get_name(tech.id)
print(f"STIX ID: {tech.id}")
print(f"Name: {name}")
print(f"✓ Correct? {name == 'Phishing'}")

