#!/usr/bin/env python3
"""Test campaign-related methods"""

from mitre_mcp_server.utils.stix_parser import get_manager

print("🧪 Testing get_campaigns_using_technique...\n")

manager = get_manager()
manager.load_domain("enterprise")

# Test: Find campaigns using Phishing (T1566)
print("Test: Find campaigns using T1566 (Phishing)")
tech = manager.get_technique_by_id("T1566")

if tech:
    print(f"Technique: {tech.name}")
    print(f"STIX ID: {tech.id}\n")
    
    # Get campaigns using this technique
    campaigns = manager.get_campaigns_using_technique(tech.id)
    print(f"✓ Found {len(campaigns)} campaign(s) using this technique")
    
    if campaigns:
        print(f"\nCampaigns:")
        for campaign in campaigns:
            # Handle dict format
            camp_obj = campaign['object'] if isinstance(campaign, dict) else campaign
            attack_id = manager.get_attack_id(camp_obj.id)
            print(f"  - {attack_id}: {camp_obj.name}")
    else:
        print("  (No campaigns found - this is normal)")
else:
    print("✗ Could not find technique")

print("\n✅ Test complete!")

print("\n" + "="*50)
print("Testing get_techniques_used_by_campaign...\n")

# Get a campaign first
campaigns = manager.get_all_campaigns()

if campaigns:
    campaign = campaigns[0]
    print(f"Campaign: {campaign.name}")
    attack_id = manager.get_attack_id(campaign.id)
    print(f"ATT&CK ID: {attack_id}\n")
    
    # Get techniques used in this campaign
    techniques = manager.get_techniques_used_by_campaign(campaign.id)
    print(f"✓ Found {len(techniques)} technique(s) used in this campaign")
    
    if techniques:
        print(f"\nFirst 5 techniques:")
        for tech in techniques[:5]:
            # Handle dict format
            tech_obj = tech['object'] if isinstance(tech, dict) else tech
            tech_attack_id = manager.get_attack_id(tech_obj.id)
            print(f"  - {tech_attack_id}: {tech_obj.name}")
    else:
        print("  (No techniques found for this campaign)")
else:
    print("✗ No campaigns in dataset")


print("\n" + "="*50)
print("Testing get_campaigns_using_software...\n")

# Find Cobalt Strike
software_list = manager.search_software("Cobalt Strike")

if software_list:
    software = software_list[0]
    print(f"Software: {software.name}")
    attack_id = manager.get_attack_id(software.id)
    print(f"ATT&CK ID: {attack_id}\n")
    
    # Get campaigns using this software
    campaigns = manager.get_campaigns_using_software(software.id)
    print(f"✓ Found {len(campaigns)} campaign(s) using this software")
    
    if campaigns:
        print(f"\nCampaigns:")
        for campaign in campaigns:
            # Handle dict format
            camp_obj = campaign['object'] if isinstance(campaign, dict) else campaign
            camp_attack_id = manager.get_attack_id(camp_obj.id)
            print(f"  - {camp_attack_id}: {camp_obj.name}")
    else:
        print("  (No campaigns found)")
else:
    print("✗ Could not find Cobalt Strike")


print("\n" + "="*50)
print("Testing get_software_used_by_campaign...\n")

# Get a campaign
campaigns = manager.get_all_campaigns()

if campaigns:
    campaign = campaigns[0]
    print(f"Campaign: {campaign.name}")
    attack_id = manager.get_attack_id(campaign.id)
    print(f"ATT&CK ID: {attack_id}\n")
    
    # Get software used in this campaign
    software = manager.get_software_used_by_campaign(campaign.id)
    print(f"✓ Found {len(software)} software used in this campaign")
    
    if software:
        print(f"\nSoftware/Tools:")
        for sw in software:
            # Handle dict format
            sw_obj = sw['object'] if isinstance(sw, dict) else sw
            sw_attack_id = manager.get_attack_id(sw_obj.id)
            print(f"  - {sw_attack_id}: {sw_obj.name} ({sw_obj.type})")
    else:
        print("  (No software found)")
else:
    print("✗ No campaigns in dataset")

print("\n" + "="*50)
print("Testing get_campaigns_by_alias...\n")

# Get all campaigns to see what aliases exist
campaigns = manager.get_all_campaigns()

if campaigns:
    print(f"Total campaigns: {len(campaigns)}\n")
    
    # Show first campaign with aliases
    print("Looking for campaigns with aliases...")
    found_with_alias = False
    
    for campaign in campaigns[:10]:
        if hasattr(campaign, 'aliases') and campaign.aliases:
            print(f"\nCampaign: {campaign.name}")
            print(f"Aliases: {', '.join(campaign.aliases)}")
            
            # Test with first alias
            first_alias = campaign.aliases[0]
            print(f"\nTesting search by alias: '{first_alias}'")
            result = manager.get_campaigns_by_alias(first_alias)
            
            if result:
                print(f"✓ Found {len(result)} campaign(s)")
                print(f"  Name: {result[0].name}")
            
            found_with_alias = True
            break
    
    if not found_with_alias:
        print("No campaigns with aliases found in first 10")
else:
    print("✗ No campaigns in dataset")