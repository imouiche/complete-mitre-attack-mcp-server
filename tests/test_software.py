#!/usr/bin/env python3
"""Test software-related methods"""

from mitre_mcp_server.utils.stix_parser import get_manager

print("🧪 Testing get_software_by_alias...\n")

manager = get_manager()
manager.load_domain("enterprise")

# Test 1: Find Cobalt Strike by alias
print("Test 1: Find Cobalt Strike by alias 'Beacon'")
software = manager.get_software_by_alias("Beacon")
if software:
    print(f"✓ Found {len(software)} software")
    sw = software[0]
    print(f"  Name: {sw.name}")
    if hasattr(sw, 'aliases'):
        print(f"  Aliases: {sw.aliases}")
else:
    print("✗ Not found")

# Test 2: Try another alias
print("\nTest 2: Find software by another alias")
software2 = manager.get_software_by_alias("Mimilib")
if software2:
    print(f"✓ Found {len(software2)} software")
    print(f"  Name: {software2[0].name}")
else:
    print("✗ Not found")

# Test 3: Non-existent alias
print("\nTest 3: Non-existent alias")
none = manager.get_software_by_alias("NonExistentAlias123")
print(f"✓ Found {len(none)} (should be 0)")

print("\n✅ Test complete!")

print("\n" + "="*50)
print("Testing get_software_using_technique...\n")

# Test: Find software using Process Injection (T1055)
print("Test: Find software using T1055 (Process Injection)")
tech = manager.get_technique_by_id("T1055")

if tech:
    print(f"Technique: {tech.name}")
    print(f"STIX ID: {tech.id}\n")
    
    # Get software using this technique
    software = manager.get_software_using_technique(tech.id)
    print(f"✓ Found {len(software)} software using this technique")
    
    if software:
        print(f"\nFirst 10 software/tools:")
        for sw in software[:10]:
            # Handle dict format
            sw_obj = sw['object'] if isinstance(sw, dict) else sw
            attack_id = manager.get_attack_id(sw_obj.id)
            print(f"  - {attack_id}: {sw_obj.name} ({sw_obj.type})")
else:
    print("✗ Could not find technique")


print("\n" + "="*50)
print("Testing get_techniques_used_by_software...\n")

# Test: Find techniques used by Cobalt Strike
print("Test: Find techniques used by Cobalt Strike")
software_list = manager.search_software("Cobalt Strike")

if software_list:
    software = software_list[0]
    print(f"Software: {software.name}")
    attack_id = manager.get_attack_id(software.id)
    print(f"ATT&CK ID: {attack_id}\n")
    
    # Get techniques used by this software
    techniques = manager.get_techniques_used_by_software(software.id)
    print(f"✓ Found {len(techniques)} techniques used by this software")
    
    if techniques:
        print(f"\nFirst 10 techniques:")
        for tech in techniques[:10]:
            # Handle dict format
            tech_obj = tech['object'] if isinstance(tech, dict) else tech
            tech_attack_id = manager.get_attack_id(tech_obj.id)
            print(f"  - {tech_attack_id}: {tech_obj.name}")
else:
    print("✗ Could not find Cobalt Strike")