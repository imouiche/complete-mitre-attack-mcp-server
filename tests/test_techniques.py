
"""Test get all TTP methods"""

from mitre_mcp_server.utils.stix_parser import get_manager

print("🧪 Testing get_software_by_alias...\n")

manager = get_manager()
manager.load_domain("enterprise")

print("\n" + "="*50)
print("Testing get_all_techniques...\n")

# Get all techniques
techniques = manager.get_all_techniques()
print(f"✓ Found {len(techniques)} total techniques in enterprise domain")

# Show first 5
print(f"\nFirst 5 techniques:")
for tech in techniques[:5]:
    attack_id = manager.get_attack_id(tech.id)
    print(f"  - {attack_id}: {tech.name}")

# Show stats
print(f"\nNote: This is a large dataset, usually used with filters")

print("\n" + "="*50)
print("Testing get_all_subtechniques...\n")

# Get all subtechniques
subtechniques = manager.get_all_subtechniques()
print(f"✓ Found {len(subtechniques)} total subtechniques")

# Show first 5 with their parents
print(f"\nFirst 5 subtechniques:")
attack_data = manager.get_attack_data("enterprise")
for subtech in subtechniques[:5]:
    attack_id = manager.get_attack_id(subtech.id)
    
    # Get parent technique
    parent_stix_id = attack_data.get_parent_technique_of_subtechnique(subtech.id)
    parent_attack_id = manager.get_attack_id(parent_stix_id) if parent_stix_id else "None"
    
    print(f"  - {attack_id}: {subtech.name}")
    print(f"    Parent: {parent_attack_id}")

print(f"\nTotal techniques: {len(manager.get_all_techniques())}")
print(f"Total subtechniques: {len(subtechniques)}")


print("\n" + "="*50)
print("Testing get_all_parent_techniques...\n")

# Get all parent techniques
parents = manager.get_all_parent_techniques()
print(f"✓ Found {len(parents)} parent techniques")

# Show first 5
print(f"\nFirst 5 parent techniques:")
for tech in parents[:5]:
    attack_id = manager.get_attack_id(tech.id)
    print(f"  - {attack_id}: {tech.name}")
    # Verify no dot in ID
    assert "." not in attack_id, f"ERROR: {attack_id} should not have a dot!"

# Compare counts
all_techs = manager.get_all_techniques()
subtechs = manager.get_all_subtechniques()
print(f"\nBreakdown:")
print(f"  Total techniques: {len(all_techs)}")
print(f"  Parent techniques: {len(parents)}")
print(f"  Subtechniques: {len(subtechs)}")
print(f"  ✓ Sum matches? {len(parents) + len(subtechs) == len(all_techs)}")

print("\n" + "="*50)
print("Testing get_all_groups...\n")

# Get all groups
groups = manager.get_all_groups()
print(f"✓ Found {len(groups)} total APT groups")

# Show first 10
print(f"\nFirst 10 groups:")
for group in groups[:10]:
    attack_id = manager.get_attack_id(group.id)
    aliases = getattr(group, 'aliases', [])
    aliases_str = f" (aka {', '.join(aliases[:2])})" if aliases else ""
    print(f"  - {attack_id}: {group.name}{aliases_str}")

print("\n" + "="*50)
print("Testing get_techniques_by_platform...\n")

# Test different platforms
platforms = ["Windows", "Linux", "macOS", "Cloud"]

for platform in platforms:
    techniques = manager.get_techniques_by_platform(platform)
    print(f"{platform}: {len(techniques)} techniques")

# Show details for Windows
print(f"\nFirst 5 Windows techniques:")
windows_techs = manager.get_techniques_by_platform("Windows")
for tech in windows_techs[:5]:
    attack_id = manager.get_attack_id(tech.id)
    print(f"  - {attack_id}: {tech.name}")


print("\n" + "="*50)
print("Testing get_parent_technique_of_subtechnique...\n")

# Test with a known subtechnique
print("Test: Get parent of T1566.001 (Spearphishing Attachment)")

# First get the subtechnique
subtech = manager.get_technique_by_id("T1566.001")

if subtech:
    print(f"Subtechnique: T1566.001 - {subtech.name}")
    
    # Get its parent
    parent = manager.get_parent_technique_of_subtechnique(subtech.id)
    
    if parent:
        parent_attack_id = manager.get_attack_id(parent.id)
        print(f"✓ Parent: {parent_attack_id} - {parent.name}")
    else:
        print("✗ No parent found (not a subtechnique?)")
else:
    print("✗ Could not find T1566.001")

# Test with a parent technique (should return None)
print("\nTest: Try with parent technique T1566")
parent_tech = manager.get_technique_by_id("T1566")
if parent_tech:
    result = manager.get_parent_technique_of_subtechnique(parent_tech.id)
    if result is None:
        print("✓ Correctly returns None (T1566 is not a subtechnique)")
    else:
        print("✗ Should return None for parent techniques")




print("\n" + "="*50)
print("Testing get_subtechniques_of_technique...\n")

# Test with Phishing (T1566) - known to have subtechniques
print("Test: Get subtechniques of T1566 (Phishing)")

tech = manager.get_technique_by_id("T1566")

if tech:
    print(f"Technique: T1566 - {tech.name}\n")
    
    # Get its subtechniques
    subtechs = manager.get_subtechniques_of_technique(tech.id)
    print(f"✓ Found {len(subtechs)} subtechnique(s)")
    
    if subtechs:
        print(f"\nSubtechniques:")
        for subtech in subtechs:
            subtech_obj = subtech['object'] if isinstance(subtech, dict) else subtech
            attack_id = manager.get_attack_id(subtech_obj.id)
            print(f"  - {attack_id}: {subtech_obj.name}")
    else:
        print("  (No subtechniques)")
else:
    print("✗ Could not find T1566")

# Test with a subtechnique (should return empty)
print("\nTest: Try with subtechnique T1566.001 (should return empty)")
subtech = manager.get_technique_by_id("T1566.001")
if subtech:
    result = manager.get_subtechniques_of_technique(subtech.id)
    if len(result) == 0:
        print("✓ Correctly returns empty list (subtechniques don't have subtechniques)")
    else:
        print(f"✗ Should return empty, got {len(result)}")


print("\n" + "="*50)
print("Testing get_tactics_by_matrix...\n")

# Get the enterprise matrix
matrices = manager.get_all_matrices()

if matrices:
    matrix = matrices[0]
    print(f"Matrix: {matrix.name}")
    matrix_attack_id = manager.get_attack_id(matrix.id)
    print(f"ATT&CK ID: {matrix_attack_id}\n")
    
    # Get tactics in this matrix
    tactics = manager.get_tactics_by_matrix(matrix.id)
    print(f"✓ Found {len(tactics)} tactics in this matrix")
    
    if tactics:
        print(f"\nTactics:")
        for tactic in tactics:
            tactic_attack_id = manager.get_attack_id(tactic.id)
            print(f"  - {tactic_attack_id}: {tactic.name}")
else:
    print("✗ No matrices found")


print("\n" + "="*50)
print("Testing get_tactics_by_technique...\n")

# Test with Phishing (T1566)
print("Test: Get tactics for T1566 (Phishing)")

tech = manager.get_technique_by_id("T1566")

if tech:
    print(f"Technique: T1566 - {tech.name}\n")
    
    # Get associated tactics
    tactics = manager.get_tactics_by_technique(tech.id)
    print(f"✓ Found {len(tactics)} tactic(s)")
    
    if tactics:
        print(f"\nTactics:")
        for tactic in tactics:
            tactic_attack_id = manager.get_attack_id(tactic.id)
            # Clean up tactic name
            tactic_name = tactic.name.replace('x_mitre_shortname', '').strip()
            print(f"  - {tactic_attack_id}: {tactic.name}")
    else:
        print("  (No tactics found)")
else:
    print("✗ Could not find T1566")

# Test with a technique that has multiple tactics
print("\nTest: Find technique with multiple tactics")
all_techs = manager.get_all_techniques()
for tech in all_techs[:50]:  # Check first 50
    tactics = manager.get_tactics_by_technique(tech.id)
    if len(tactics) > 1:
        attack_id = manager.get_attack_id(tech.id)
        print(f"Found: {attack_id} - {tech.name}")
        print(f"  Belongs to {len(tactics)} tactics")
        break


print("\n" + "="*50)
print("Testing get_procedure_examples_by_tactic...\n")

# Test with Initial Access
print("Test: Get procedure examples for 'Initial Access' tactic")

examples = manager.get_procedure_examples_by_tactic("Initial Access")
print(f"✓ Found {len(examples)} procedure example(s)\n")

if examples:
    attack_data = manager.get_attack_data("enterprise")
    print(f"First 5 examples:")
    
    for example in examples[:5]:
        # Handle dict format
        if isinstance(example, dict):
            rel = example.get('relationship') or example.get('object')
        else:
            rel = example
        
        # Get source and target
        if hasattr(rel, 'source_ref') and hasattr(rel, 'target_ref'):
            try:
                source = attack_data.get_object_by_stix_id(rel.source_ref)
                target = attack_data.get_object_by_stix_id(rel.target_ref)
                
                source_name = source.name if hasattr(source, 'name') else "Unknown"
                target_attack_id = manager.get_attack_id(target.id)
                
                print(f"\n  Group: {source_name}")
                print(f"  Technique: {target_attack_id} - {target.name}")
                
                if hasattr(rel, 'description'):
                    desc = rel.description[:100]
                    print(f"  Usage: {desc}...")
            except:
                pass
else:
    print("  (No examples found)")


print("\n" + "="*50)
print("Testing get_revoked_techniques...\n")

# Get revoked techniques
revoked = manager.get_revoked_techniques()
print(f"✓ Found {len(revoked)} revoked technique(s)")

if revoked:
    print(f"\nFirst 5 revoked techniques:")
    for tech in revoked[:5]:
        attack_id = manager.get_attack_id(tech.id)
        print(f"  - {attack_id}: {tech.name}")
        
        # Show why revoked if available
        if hasattr(tech, 'revoked') and tech.revoked:
            print(f"    Status: Revoked")
        
        # Check for x_mitre_deprecated
        if hasattr(tech, 'x_mitre_deprecated') and tech.x_mitre_deprecated:
            print(f"    (Also marked deprecated)")
else:
    print("  (No revoked techniques found)")

# Compare counts
all_techs = manager.get_all_techniques()  # Excludes revoked by default
print(f"\nComparison:")
print(f"  Active techniques: {len(all_techs)}")
print(f"  Revoked techniques: {len(revoked)}")