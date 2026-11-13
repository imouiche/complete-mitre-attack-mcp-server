"""Test mitigation-related, matrices, campaign, data sources, data components, Assets from ICS, methods"""

from mitre_mcp_server.utils.stix_parser import get_manager

print("🧪 Testing get_all_mitigations...\n")

manager = get_manager()
manager.load_domain("enterprise")

# Get all mitigations
mitigations = manager.get_all_mitigations()
print(f"✓ Found {len(mitigations)} total mitigations")

# Show first 10
print(f"\nFirst 10 mitigations:")
for mitigation in mitigations[:10]:
    attack_id = manager.get_attack_id(mitigation.id)
    print(f"  - {attack_id}: {mitigation.name}")
    if hasattr(mitigation, 'description'):
        desc_preview = mitigation.description[:80]
        print(f"    {desc_preview}...")

print("\n✅ Test complete!")

print("\n" + "="*50)
print("Testing get_all_matrices...\n")

# Get all matrices
matrices = manager.get_all_matrices("enterprise")
print(f"✓ Found {len(matrices)} matrix/matrices in enterprise domain")

if matrices:
    for matrix in matrices:
        attack_id = manager.get_attack_id(matrix.id)
        print(f"\nMatrix: {matrix.name}")
        print(f"  ATT&CK ID: {attack_id}")
        if hasattr(matrix, 'description'):
            desc = matrix.description[:100]
            print(f"  Description: {desc}...")


print("\n" + "="*50)
print("Testing get_all_campaigns...\n")

# Get all campaigns
campaigns = manager.get_all_campaigns()
print(f"✓ Found {len(campaigns)} total campaigns")

if campaigns:
    print(f"\nFirst 5 campaigns:")
    for campaign in campaigns[:5]:
        attack_id = manager.get_attack_id(campaign.id)
        print(f"  - {attack_id}: {campaign.name}")
        if hasattr(campaign, 'description'):
            desc_preview = campaign.description[:80]
            print(f"    {desc_preview}...")
else:
    print("  (No campaigns in dataset)")


print("\n" + "="*50)
print("Testing get_all_datasources...\n")

# Get all data sources
datasources = manager.get_all_datasources()
print(f"✓ Found {len(datasources)} total data sources")

if datasources:
    print(f"\nFirst 10 data sources:")
    for ds in datasources[:10]:
        attack_id = manager.get_attack_id(ds.id)
        print(f"  - {attack_id}: {ds.name}")
else:
    print("  (No data sources in dataset)")


print("\n" + "="*50)
print("Testing get_all_datacomponents...\n")

# Get all data components
components = manager.get_all_datacomponents()
print(f"✓ Found {len(components)} total data components")

if components:
    print(f"\nFirst 5 data components with their data sources:")
    attack_data = manager.get_attack_data("enterprise")
    
    for comp in components[:5]:
        comp_attack_id = manager.get_attack_id(comp.id)
        print(f"  - {comp_attack_id}: {comp.name}")
        
        # Get parent data source (with error handling)
        if hasattr(comp, 'x_mitre_data_source_ref') and comp.x_mitre_data_source_ref:
            try:
                datasource = attack_data.get_object_by_stix_id(comp.x_mitre_data_source_ref)
                ds_attack_id = manager.get_attack_id(datasource.id)
                print(f"    Data Source: {ds_attack_id} - {datasource.name}")
            except (ValueError, AttributeError) as e:
                print(f"    Data Source: (reference not found)")
        else:
            print(f"    Data Source: (no reference)")
else:
    print("  (No data components in dataset)")


print("\n" + "="*50)
print("Testing get_all_assets (ICS domain)...\n")

# Load ICS domain
manager.load_domain("ics")

# Get all assets
assets = manager.get_all_assets("ics")
print(f"✓ Found {len(assets)} total assets in ICS domain")

if assets:
    print(f"\nAll ICS assets:")
    for asset in assets:
        attack_id = manager.get_attack_id(asset.id, "ics")
        print(f"  - {attack_id}: {asset.name}")
        if hasattr(asset, 'description'):
            desc_preview = asset.description[:80]
            print(f"    {desc_preview}...")
else:
    print("  (No assets in ICS dataset)")

print("\n" + "="*50)
print("Testing get_techniques_mitigated_by_mitigation...\n")

# Find User Training mitigation (M1017)
mitigations = manager.get_all_mitigations()
user_training = None

for mitigation in mitigations:
    if "User Training" in mitigation.name:
        user_training = mitigation
        break

if user_training:
    attack_id = manager.get_attack_id(user_training.id)
    print(f"Mitigation: {attack_id} - {user_training.name}\n")
    
    # Get techniques mitigated by it
    techniques = manager.get_techniques_mitigated_by_mitigation(user_training.id)
    print(f"✓ This mitigation addresses {len(techniques)} technique(s)")
    
    if techniques:
        print(f"\nFirst 10 techniques mitigated:")
        for tech in techniques[:10]:
            # Handle dict format
            tech_obj = tech['object'] if isinstance(tech, dict) else tech
            tech_attack_id = manager.get_attack_id(tech_obj.id)
            print(f"  - {tech_attack_id}: {tech_obj.name}")
else:
    print("✗ Could not find User Training mitigation")


print("\n" + "="*50)
print("Testing get_mitigations_mitigating_technique...\n")

# Test with Phishing (T1566)
print("Test: Find mitigations for T1566 (Phishing)")

tech = manager.get_technique_by_id("T1566")

if tech:
    print(f"Technique: T1566 - {tech.name}\n")
    
    # Get mitigations for this technique
    mitigations = manager.get_mitigations_mitigating_technique(tech.id)
    print(f"✓ Found {len(mitigations)} mitigation(s) for this technique")
    
    if mitigations:
        print(f"\nMitigations:")
        for mitigation in mitigations:
            # Handle dict format
            mit_obj = mitigation['object'] if isinstance(mitigation, dict) else mitigation
            mit_attack_id = manager.get_attack_id(mit_obj.id)
            print(f"  - {mit_attack_id}: {mit_obj.name}")
    else:
        print("  (No mitigations found)")
else:
    print("✗ Could not find T1566")