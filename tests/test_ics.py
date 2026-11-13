"""Test ICS-specific methods"""

from mitre_mcp_server.utils.stix_parser import get_manager

print("🧪 Testing ICS functions...\n")

manager = get_manager()
manager.load_domain("ics")

print("="*50)
print("Testing get_assets_targeted_by_technique...\n")

# Get ICS techniques
ics_techniques = manager.get_all_techniques("ics")
print(f"Total ICS techniques: {len(ics_techniques)}")

if ics_techniques:
    # Test with first technique that targets assets
    print(f"\nTesting with first ICS technique...")
    tech = ics_techniques[0]
    tech_attack_id = manager.get_attack_id(tech.id, "ics")
    print(f"Technique: {tech_attack_id} - {tech.name}\n")
    
    # Get targeted assets
    assets = manager.get_assets_targeted_by_technique(tech.id, "ics")
    print(f"✓ Found {len(assets)} asset(s) targeted by this technique")
    
    if assets:
        print(f"\nTargeted assets:")
        for asset in assets:
            # Handle dict format
            asset_obj = asset['object'] if isinstance(asset, dict) else asset
            asset_attack_id = manager.get_attack_id(asset_obj.id, "ics")
            print(f"  - {asset_attack_id}: {asset_obj.name}")
    else:
        print("  (No assets found - trying another technique...)")
else:
    print("✗ No ICS techniques found")

print("\n✅ Test complete!")


print("\n" + "="*50)
print("Testing get_techniques_targeting_asset...\n")

# Get ICS assets
assets = manager.get_all_assets("ics")

if assets:
    # Test with first asset
    asset = assets[0]
    asset_attack_id = manager.get_attack_id(asset.id, "ics")
    print(f"Asset: {asset_attack_id} - {asset.name}\n")
    
    # Get techniques targeting this asset
    techniques = manager.get_techniques_targeting_asset(asset.id, "ics")
    print(f"✓ Found {len(techniques)} technique(s) targeting this asset")
    
    if techniques:
        print(f"\nTechniques:")
        for tech in techniques:
            # Handle dict format
            tech_obj = tech['object'] if isinstance(tech, dict) else tech
            tech_attack_id = manager.get_attack_id(tech_obj.id, "ics")
            print(f"  - {tech_attack_id}: {tech_obj.name}")
    else:
        print("  (No techniques found)")
else:
    print("✗ No assets in ICS domain")