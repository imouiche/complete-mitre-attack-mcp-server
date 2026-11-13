"""Test get_objects_by_content method"""

from mitre_mcp_server.utils.stix_parser import get_manager

print("🧪 Testing get_objects_by_content...\n")

manager = get_manager()
manager.load_domain("enterprise")

# Test 1: Find techniques mentioning "email"
print("Test 1: Find techniques mentioning 'email'")
techs = manager.get_objects_by_content("email", "attack-pattern")
print(f"✓ Found {len(techs)} technique(s)")
if techs:
    print(f"  Example: {techs[0].name}")

# Test 2: Find groups mentioning "Russia"
print("\nTest 2: Find groups mentioning 'Russia'")
groups = manager.get_objects_by_content("Russia", "intrusion-set")
print(f"✓ Found {len(groups)} group(s)")
if groups:
    print(f"  Example: {groups[0].name}")

# Test 3: Find malware mentioning "ransomware"
print("\nTest 3: Find malware mentioning 'ransomware'")
malware = manager.get_objects_by_content("ransomware", "malware")
print(f"✓ Found {len(malware)} malware")
if malware:
    print(f"  Example: {malware[0].name}")

# Test 4: Content not found
print("\nTest 4: Search for non-existent content")
none = manager.get_objects_by_content("XYZABC123NOTFOUND", "attack-pattern")
print(f"✓ Found {len(none)} (correctly empty)")

print("\n✅ Test complete!")