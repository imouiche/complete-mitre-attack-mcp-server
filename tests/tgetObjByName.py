"""Test get_objects_by_name method"""

from mitre_mcp_server.utils.stix_parser import get_manager

print("🧪 Testing get_objects_by_name...\n")

manager = get_manager()
manager.load_domain("enterprise")

# Test 1: Exact name match for technique
print("Test 1: Find 'Phishing' technique")
techs = manager.get_objects_by_name("Phishing", "attack-pattern")
print(f"✓ Found {len(techs)} technique(s)")
if techs:
    print(f"  Name: {techs[0].name}")

# Test 2: Exact name match for group
print("\nTest 2: Find 'APT29' group")
groups = manager.get_objects_by_name("APT29", "intrusion-set")
print(f"✓ Found {len(groups)} group(s)")
if groups:
    print(f"  Name: {groups[0].name}")

# Test 3: Case-sensitive (should not find)
print("\nTest 3: Case-sensitive test ('phishing' lowercase)")
techs_lower = manager.get_objects_by_name("phishing", "attack-pattern")
print(f"Found {len(techs_lower)} (should be 0 - case sensitive)")

# Test 4: Name doesn't exist
print("\nTest 4: Non-existent name")
none = manager.get_objects_by_name("DoesNotExist", "attack-pattern")
print(f"✓ Found {len(none)} (correctly empty)")

print("\n✅ Test complete!")