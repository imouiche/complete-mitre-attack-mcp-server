
#!/usr/bin/env python3
"""Test ATT&CK Navigator layer generation"""

from mitre_mcp_server.utils.stix_parser import get_manager
import json

print("🧪 Testing generate_layer...\n")

manager = get_manager()
manager.load_domain("enterprise")

# Test 1: Generate layer for APT29
print("Test 1: Generate layer for G0016 (APT29)")
try:
    layer = manager.generate_layer("G0016", score=100)
    print(f"✓ Layer generated successfully")
    
    # Access techniques correctly
    techniques = layer.get('techniques', [])
    print(f"  Techniques in layer: {len(techniques)}")
    print(f"  Layer name: {layer.get('name', 'Unknown')}")
    
    # Show first 3 techniques
    if techniques:
        print(f"\n  First 3 techniques:")
        for tech in techniques[:3]:
            print(f"    - {tech.get('techniqueID', 'N/A')}: score={tech.get('score', 0)}")
    
    # Optionally save to file
    # with open('apt29_layer.json', 'w') as f:
    #     json.dump(layer, f, indent=2)
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()

# Test 2: Try with technique ID (should fail)
print("\nTest 2: Try with technique ID T1566 (should fail)")
try:
    layer = manager.generate_layer("T1566", score=50)
    print(f"✗ Should have raised ValueError")
except ValueError as e:
    print(f"✓ Correctly rejected: {str(e)[:80]}...")

# Test 3: Generate layer for mitigation
print("\nTest 3: Generate layer for M1017 (User Training)")
try:
    layer = manager.generate_layer("M1017", score=75)
    print(f"✓ Layer generated successfully")
    
    techniques = layer.get('techniques', [])
    print(f"  Techniques mitigated: {len(techniques)}")
    
except Exception as e:
    print(f"✗ Error: {e}")

print("\n✅ Test complete!")

print("\n" + "="*50)
print("Testing get_layer_metadata...\n")

# Test different domains
for domain in ["enterprise", "mobile", "ics"]:
    metadata = manager.get_layer_metadata(domain)
    print(f"{domain.capitalize()}:")
    print(f"  Domain: {metadata['domain']}")
    print(f"  Platforms: {metadata['filters']['platforms']}")
    print(f"  Navigator version: {metadata['versions']['navigator']}")

# Test invalid domain (should default to enterprise)
print("\nInvalid domain test:")
metadata = manager.get_layer_metadata("invalid")
print(f"  Defaulted to: {metadata['domain']}")