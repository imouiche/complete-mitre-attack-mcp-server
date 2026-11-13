#!/usr/bin/env python3
"""Test group-related methods"""

from mitre_mcp_server.utils.stix_parser import get_manager

print("🧪 Testing get_groups_by_alias...\n")

manager = get_manager()
manager.load_domain("enterprise")

# Test 1: Find APT29 by various aliases
aliases = ["Cozy Bear", "NOBELIUM", "Midnight Blizzard", "The Dukes"]

for alias in aliases:
    print(f"Test: Find group by alias '{alias}'")
    groups = manager.get_groups_by_alias(alias)
    if groups:
        print(f"  ✓ Found: {groups[0].name}")
        all_aliases = getattr(groups[0], 'aliases', [])
        print(f"  All aliases: {', '.join(all_aliases[:3])}...")
    else:
        print(f"  ✗ Not found")
    print()

# Test 2: Non-existent alias
print("Test: Non-existent alias")
none = manager.get_groups_by_alias("NonExistentAlias123")
print(f"✓ Found {len(none)} groups (should be 0)")

print("\n✅ Test complete!")

print("\n" + "="*50)
print("Testing get_techniques_used_by_group (by STIX ID)...\n")

# Get APT29 first
group = manager.get_group_by_name("APT29")
if group:
    print(f"Group: {group.name}")
    print(f"STIX ID: {group.id}\n")
    
    # Get techniques using STIX ID
    techniques = manager.get_techniques_used_by_group(group.id)
    print(f"✓ Found {len(techniques)} techniques used by this group")
    
    if techniques:
        print(f"\nFirst 3 techniques:")
        for tech in techniques[:3]:
            # Extract the actual STIX object from the dict
            tech_obj = tech['object'] if isinstance(tech, dict) else tech
            
            attack_id = manager.get_attack_id(tech_obj.id)
            print(f"  - {attack_id}: {tech_obj.name}")
    
    # Compare with name-based method
    techniques_by_name = manager.get_group_techniques("APT29")
    print(f"\nComparison with get_group_techniques(name):")
    print(f"  By STIX ID: {len(techniques)} techniques")
    print(f"  By name: {len(techniques_by_name)} techniques")
    print(f"  ✓ Same result? {len(techniques) == len(techniques_by_name)}")
else:
    print("✗ Could not find APT29")



print("\n" + "="*50)
print("Testing get_software_used_by_group...\n")

# Get APT29
group = manager.get_group_by_name("APT29")
if group:
    print(f"Group: {group.name}")
    
    # Get software used by this group
    software = manager.get_software_used_by_group(group.id)
    print(f"✓ Found {len(software)} software/tools used by this group")
    
    if software:
        print(f"\nFirst 5 tools/malware:")
        for sw in software[:5]:
            sw_obj = sw['object'] if isinstance(sw, dict) else sw
            attack_id = manager.get_attack_id(sw_obj.id)
            sw_type = sw_obj.type  # 'malware' or 'tool'
            print(f"  - {attack_id}: {sw_obj.name} ({sw_type})")
else:
    print("✗ Could not find APT29")


print("\n" + "="*50)
print("Testing get_campaigns_attributed_to_group...\n")

# Get APT29
group = manager.get_group_by_name("APT29")
if group:
    print(f"Group: {group.name}")
    
    # Get campaigns attributed to this group
    campaigns = manager.get_campaigns_attributed_to_group(group.id)
    print(f"✓ Found {len(campaigns)} campaign(s) attributed to this group")
    
    if campaigns:
        print(f"\nCampaigns:")
        for campaign in campaigns:
            # Extract the actual STIX object from the dict
            campaign_obj = campaign['object'] if isinstance(campaign, dict) else campaign
            
            attack_id = manager.get_attack_id(campaign_obj.id)
            print(f"  - {attack_id}: {campaign_obj.name}")
            if hasattr(campaign_obj, 'description'):
                desc_preview = campaign_obj.description[:100]
                print(f"    {desc_preview}...")
    else:
        print("  (No campaigns found - this is normal for some groups)")
else:
    print("✗ Could not find APT29")



print("\n" + "="*50)
print("Testing get_techniques_used_by_group_software...\n")

# Get APT29
group = manager.get_group_by_name("APT29")
if group:
    print(f"Group: {group.name}\n")
    
    # Get techniques used by group's software
    techniques = manager.get_techniques_used_by_group_software(group.id)
    print(f"✓ Found {len(techniques)} techniques used by this group's software")
    
    if techniques:
        print(f"\nFirst 5 techniques (via software):")
        for tech in techniques[:5]:
            attack_id = manager.get_attack_id(tech.id)
            print(f"  - {attack_id}: {tech.name}")
    
    # Compare with direct group techniques
    direct_techniques = manager.get_techniques_used_by_group(group.id)
    print(f"\nComparison:")
    print(f"  Direct techniques (group uses): {len(direct_techniques)}")
    print(f"  Indirect techniques (via software): {len(techniques)}")
    print(f"  Note: Indirect may be larger (includes all software capabilities)")
else:
    print("✗ Could not find APT29")


print("\n" + "="*50)
# Test: Find groups using Phishing (T1566)
print("Test: Find groups using T1566 (Phishing)")
tech = manager.get_technique_by_id("T1566")

if tech:
    print(f"Technique: {tech.name}")
    print(f"STIX ID: {tech.id}\n")
    
    # Get groups using this technique
    groups = manager.get_groups_using_technique(tech.id)
    print(f"✓ Found {len(groups)} groups using this technique")
    
    if groups:
        print(f"\nFirst 10 groups:")
        for group in groups[:10]:
            group_obj = group['object'] if isinstance(group, dict) else group
            attack_id = manager.get_attack_id(group_obj.id)
            print(f"  - {attack_id}: {group_obj.name}")
else:
    print("✗ Could not find technique")

print("\n✅ Test complete!")


print("\n" + "="*50)
print("Testing get_groups_using_software...\n")

# Test: Find groups using Cobalt Strike
print("Test: Find groups using Cobalt Strike")
software_list = manager.search_software("Cobalt Strike")

if software_list:
    software = software_list[0]
    print(f"Software: {software.name}")
    attack_id = manager.get_attack_id(software.id)
    print(f"ATT&CK ID: {attack_id}")
    print(f"STIX ID: {software.id}\n")
    
    # Get groups using this software
    groups = manager.get_groups_using_software(software.id)
    print(f"✓ Found {len(groups)} groups using this software")
    
    if groups:
        print(f"\nFirst 10 groups:")
        for group in groups[:10]:
            group_obj = group['object'] if isinstance(group, dict) else group
            group_attack_id = manager.get_attack_id(group_obj.id)
            print(f"  - {group_attack_id}: {group_obj.name}")
else:
    print("✗ Could not find Cobalt Strike")


print("\n" + "="*50)
print("Testing get_groups_attributing_to_campaign...\n")

# First, find a campaign
print("Test: Find groups attributed to a campaign")

# Try to find any campaign
all_campaigns = manager.get_objects_by_content("", "campaign", "enterprise")
print(f"Total campaigns available: {len(all_campaigns)}")

if all_campaigns:
    campaign = all_campaigns[0]
    print(f"\nCampaign: {campaign.name}")
    attack_id = manager.get_attack_id(campaign.id)
    print(f"ATT&CK ID: {attack_id}\n")
    
    # Get groups attributed to this campaign
    groups = manager.get_groups_attributing_to_campaign(campaign.id)
    print(f"✓ Found {len(groups)} group(s) attributed to this campaign")
    
    if groups:
        print(f"\nGroups:")
        for group in groups:
            group_obj = group['object'] if isinstance(group, dict) else group
            group_attack_id = manager.get_attack_id(group_obj.id)
            print(f"  - {group_attack_id}: {group_obj.name}")
    else:
        print("  (No groups attributed - trying another campaign...)")
else:
    print("✗ No campaigns found in dataset")


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