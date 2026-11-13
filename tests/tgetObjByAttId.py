#!/usr/bin/env python3
"""Test get_object_by_attack_id method"""

from mitre_mcp_server.utils.stix_parser import get_manager

print("🧪 Testing get_object_by_attack_id...\n")

manager = get_manager()
manager.load_domain("enterprise")

# Test 1: Get a technique
print("Test 1: Get Technique T1566 (Phishing)")
tech = manager.get_object_by_attack_id("T1566", "attack-pattern")
if tech:
    print(f"✓ Found: {tech.name}")
    print(f"  Type: {tech.type}")
    print(f"  Description: {tech.description[:100]}...")
else:
    print("✗ Not found")

# Test 2: Get a group
print("\nTest 2: Get Group G0016 (APT29)")
group = manager.get_object_by_attack_id("G0016", "intrusion-set")
if group:
    print(f"✓ Found: {group.name}")
    print(f"  Aliases: {getattr(group, 'aliases', [])}")
else:
    print("✗ Not found")

# Test 3: Get malware
print("\nTest 3: Get Malware S0154 (Cobalt Strike)")
malware = manager.get_object_by_attack_id("S0154", "malware")
if malware:
    print(f"✓ Found: {malware.name}")
    print(f"  Type: {malware.type}")
else:
    print("✗ Not found")

# Test 4: Get mitigation
print("\nTest 4: Get Mitigation M1013")
mitigation = manager.get_object_by_attack_id("M1013", "course-of-action")
if mitigation:
    print(f"✓ Found: {mitigation.name}")
else:
    print("✗ Not found")

# Test 5: Invalid ID (should return None gracefully)
print("\nTest 5: Invalid ID (should return None)")
invalid = manager.get_object_by_attack_id("INVALID123", "attack-pattern")
if invalid is None:
    print("✓ Correctly returned None for invalid ID")
else:
    print("✗ Should have returned None")

print("\n✅ All tests complete!")

print("\n" + "="*50)
print("Testing get_objects_by_type...\n")

# Test different types
types_to_test = [
    ("attack-pattern", "Techniques"),
    ("intrusion-set", "Groups"),
    ("malware", "Malware"),
    ("tool", "Tools"),
    ("course-of-action", "Mitigations")
]

for stix_type, label in types_to_test:
    objects = manager.get_objects_by_type(stix_type)
    print(f"{label} ({stix_type}): {len(objects)} objects")

# Show details for one type
print(f"\nFirst 5 groups:")
groups = manager.get_objects_by_type("intrusion-set")
for group in groups[:5]:
    attack_id = manager.get_attack_id(group.id)
    print(f"  - {attack_id}: {group.name}")


print("\n" + "="*50)
print("Testing get_objects_created_after...\n")

# Test: Get objects created since Jan 2024
print("Test: Get objects created since 2024-01-01")

objects = manager.get_objects_created_after("2024-01-01T00:00:00Z")
print(f"✓ Found {len(objects)} object(s) created since Jan 2024")

if objects:
    # Group by type
    by_type = {}
    for obj in objects:
        obj_type = obj.type
        by_type[obj_type] = by_type.get(obj_type, 0) + 1
    
    print(f"\nBreakdown by type:")
    for obj_type, count in sorted(by_type.items()):
        print(f"  {obj_type}: {count}")
    
    # Show first 5
    print(f"\nFirst 5 new objects:")
    for obj in objects[:5]:
        attack_id = manager.get_attack_id(obj.id)
        print(f"  - {attack_id}: {obj.name} ({obj.type})")
        print(f"    Created: {obj.created}")
else:
    print("  (No objects found - try older date)")


print("\n" + "="*50)
print("Testing get_objects_modified_after...\n")

# Test: Get objects modified since Jan 2024
print("Test: Get objects modified since 2024-01-01")

objects = manager.get_objects_modified_after("2024-01-01T00:00:00Z")
print(f"✓ Found {len(objects)} object(s) modified since Jan 2024")

if objects:
    # Group by type
    by_type = {}
    for obj in objects:
        obj_type = obj.type
        by_type[obj_type] = by_type.get(obj_type, 0) + 1
    
    print(f"\nBreakdown by type:")
    for obj_type, count in sorted(by_type.items()):
        print(f"  {obj_type}: {count}")
    
    # Show first 5 with modification dates
    print(f"\nFirst 5 modified objects:")
    for obj in objects[:5]:
        attack_id = manager.get_attack_id(obj.id)
        print(f"  - {attack_id}: {obj.name} ({obj.type})")
        print(f"    Modified: {obj.modified}")
else:
    print("  (No objects found)")