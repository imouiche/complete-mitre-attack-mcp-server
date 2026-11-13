#!/usr/bin/env python3
"""Test detection-related methods"""

from mitre_mcp_server.utils.stix_parser import get_manager

print("🧪 Testing get_datacomponents_detecting_technique...\n")

manager = get_manager()
manager.load_domain("enterprise")

# Test with Process Injection (T1055)
print("Test: Find data components that detect T1055 (Process Injection)")

tech = manager.get_technique_by_id("T1055")

if tech:
    print(f"Technique: T1055 - {tech.name}\n")
    
    # Get data components
    components = manager.get_datacomponents_detecting_technique(tech.id)
    print(f"✓ Found {len(components)} data component(s) for detection")
    
    if components:
        attack_data = manager.get_attack_data("enterprise")
        print(f"\nData components:")
        
        for item in components[:5]:  # Show first 5
            # Extract data component object
            comp_obj = item['object'] if isinstance(item, dict) else item
            
            # Get parent data source
            if hasattr(comp_obj, 'x_mitre_data_source_ref') and comp_obj.x_mitre_data_source_ref:
                try:
                    datasource = attack_data.get_object_by_stix_id(comp_obj.x_mitre_data_source_ref)
                    ds_attack_id = manager.get_attack_id(datasource.id)
                    print(f"  - Data Source: {ds_attack_id} - {datasource.name}")
                    print(f"    Component: {comp_obj.name}")
                except:
                    print(f"  - Component: {comp_obj.name} (source N/A)")
            else:
                print(f"  - Component: {comp_obj.name}")
    else:
        print("  (No data components found)")
else:
    print("✗ Could not find T1055")

print("\n✅ Test complete!")


print("\n" + "="*50)
print("Testing get_techniques_detected_by_datacomponent...\n")

# Find "Process Creation" data component
components = manager.get_all_datacomponents()
proc_creation = None

for comp in components:
    if "Process Creation" in comp.name:
        proc_creation = comp
        break

if proc_creation:
    attack_data = manager.get_attack_data("enterprise")
    
    # Get parent data source info
    if hasattr(proc_creation, 'x_mitre_data_source_ref') and proc_creation.x_mitre_data_source_ref:
        try:
            datasource = attack_data.get_object_by_stix_id(proc_creation.x_mitre_data_source_ref)
            print(f"Data Source: {datasource.name}")
        except:
            pass
    
    print(f"Data Component: {proc_creation.name}\n")
    
    # Get techniques detected by it
    techniques = manager.get_techniques_detected_by_datacomponent(proc_creation.id)
    print(f"✓ Can detect {len(techniques)} technique(s)")
    
    if techniques:
        print(f"\nFirst 10 techniques:")
        for tech in techniques[:10]:
            # Handle dict format
            tech_obj = tech['object'] if isinstance(tech, dict) else tech
            tech_attack_id = manager.get_attack_id(tech_obj.id)
            print(f"  - {tech_attack_id}: {tech_obj.name}")
else:
    print("✗ Could not find Process Creation data component")



print("\n" + "="*50)
print("Testing get_procedure_examples_by_technique...\n")

# Test with Phishing (T1566)
print("Test: Get procedure examples for T1566 (Phishing)")

tech = manager.get_technique_by_id("T1566")

if tech:
    print(f"Technique: T1566 - {tech.name}\n")
    
    # Get procedure examples
    examples = manager.get_procedure_examples_by_technique(tech.id)
    print(f"✓ Found {len(examples)} procedure example(s)")
    
    if examples:
        print(f"\nFirst 5 procedure examples:")
        attack_data = manager.get_attack_data("enterprise")
        
        for example in examples[:5]:
            # Handle dict format with relationships
            if isinstance(example, dict):
                rel = example.get('relationship') or example.get('object')
            else:
                rel = example
            
            # Get the source (group/software)
            if hasattr(rel, 'source_ref'):
                try:
                    source = attack_data.get_object_by_stix_id(rel.source_ref)
                    source_name = source.name if hasattr(source, 'name') else "Unknown"
                    print(f"\n  Group/Software: {source_name}")
                    
                    # Show description if available
                    if hasattr(rel, 'description'):
                        desc_preview = rel.description[:150]
                        print(f"  Usage: {desc_preview}...")
                except:
                    print(f"  (Could not get source info)")
    else:
        print("  (No procedure examples found)")
else:
    print("✗ Could not find T1566")
