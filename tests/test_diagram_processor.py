"""
Test script for the Vision Agent - Architecture Diagram Processor.

This script tests the diagram processor with:
1. JSON bypass mode (for testing without API calls)
2. Error handling for non-existent files
3. Output validation against ArchitectureSchema
4. Image processing (when valid image is available)
"""

import json
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.diagram_processor import (
    process_architecture_diagram,
    validate_architecture_output,
    VISION_PROMPT,
)
from tools.models import ArchitectureSchema


def test_json_bypass_mode():
    """Test processing with JSON file (bypass mode for testing)."""
    print("\n" + "=" * 60)
    print("Test 1: JSON Bypass Mode")
    print("=" * 60)
    
    json_path = "data/test_arch.json"
    
    if not Path(json_path).exists():
        print(f"[SKIP] Test file not found: {json_path}")
        return False
    
    result = process_architecture_diagram(None, json_path)
    is_valid, schema, error = validate_architecture_output(result)
    
    if not is_valid:
        print(f"[FAIL] Validation failed: {error}")
        return False
    
    print(f"[PASS] JSON bypass mode successful")
    print(f"  - Project: {schema.project_name}")
    print(f"  - Components: {len(schema.components)}")
    print(f"  - Data Flows: {len(schema.data_flows)}")
    print(f"  - Trust Boundaries: {len(schema.trust_boundaries)}")
    
    # Print component details
    print("\n  Components:")
    for comp in schema.components[:5]:  # First 5
        print(f"    - {comp.name} ({comp.type})")
    if len(schema.components) > 5:
        print(f"    ... and {len(schema.components) - 5} more")
    
    # Print data flow details
    print("\n  Data Flows:")
    for flow in schema.data_flows[:5]:  # First 5
        print(f"    - {flow.source} -> {flow.destination} [{flow.protocol}]")
    if len(schema.data_flows) > 5:
        print(f"    ... and {len(schema.data_flows) - 5} more")
    
    # Print trust boundaries
    print("\n  Trust Boundaries:")
    for boundary in schema.trust_boundaries:
        print(f"    - {boundary}")
    
    return True


def test_nonexistent_file():
    """Test error handling with non-existent file."""
    print("\n" + "=" * 60)
    print("Test 2: Non-existent File Error Handling")
    print("=" * 60)
    
    result = process_architecture_diagram(None, "nonexistent_file.png")
    data = json.loads(result)
    
    if "error" in data:
        print(f"[PASS] Correctly returned error: {data['error']}")
        return True
    else:
        print("[FAIL] Should have returned an error")
        return False


def test_invalid_json_file():
    """Test error handling with invalid JSON file."""
    print("\n" + "=" * 60)
    print("Test 3: Invalid JSON File Error Handling")
    print("=" * 60)
    
    # Create a temporary invalid JSON file
    invalid_json_path = "data/invalid_test.json"
    Path("data").mkdir(exist_ok=True)
    
    with open(invalid_json_path, "w") as f:
        f.write("{ invalid json content")
    
    try:
        result = process_architecture_diagram(None, invalid_json_path)
        data = json.loads(result)
        
        if "error" in data:
            print(f"[PASS] Correctly returned error: {data['error']}")
            return True
        else:
            print("[FAIL] Should have returned an error for invalid JSON")
            return False
    finally:
        # Clean up
        if Path(invalid_json_path).exists():
            os.remove(invalid_json_path)


def test_schema_validation():
    """Test that output correctly validates against ArchitectureSchema."""
    print("\n" + "=" * 60)
    print("Test 4: Schema Validation")
    print("=" * 60)
    
    # Test valid data
    valid_json = json.dumps({
        "project_name": "Test Project",
        "description": "A test architecture",
        "components": [
            {"name": "Web Server", "type": "Server"},
            {"name": "Database", "type": "Database"}
        ],
        "data_flows": [
            {"source": "Web Server", "destination": "Database", "protocol": "TCP/5432"}
        ],
        "trust_boundaries": ["Internal", "External"]
    })
    
    is_valid, schema, error = validate_architecture_output(valid_json)
    
    if not is_valid:
        print(f"[FAIL] Valid data rejected: {error}")
        return False
    
    print("[PASS] Valid schema accepted")
    
    # Test error response detection
    error_json = json.dumps({"error": "Test error message"})
    is_valid, schema, error = validate_architecture_output(error_json)
    
    if is_valid:
        print("[FAIL] Error response should not be valid")
        return False
    
    print("[PASS] Error response correctly detected")
    
    return True


def test_vision_prompt_exists():
    """Test that vision prompt is properly defined."""
    print("\n" + "=" * 60)
    print("Test 5: Vision Prompt Configuration")
    print("=" * 60)
    
    if not VISION_PROMPT:
        print("[FAIL] VISION_PROMPT is empty")
        return False
    
    # Check for key instructions
    required_keywords = [
        "components",
        "data flows",
        "trust boundaries",
        "JSON",
        "DO NOT"
    ]
    
    missing = [kw for kw in required_keywords if kw.lower() not in VISION_PROMPT.lower()]
    
    if missing:
        print(f"[FAIL] Missing keywords in prompt: {missing}")
        return False
    
    print(f"[PASS] Vision prompt configured ({len(VISION_PROMPT)} chars)")
    print(f"  - Contains component extraction instructions")
    print(f"  - Contains data flow extraction instructions")
    print(f"  - Contains trust boundary extraction instructions")
    print(f"  - Contains JSON output instructions")
    print(f"  - Contains negative instructions (DO NOT)")
    
    return True


def test_image_processing():
    """Test processing with actual image file (if available)."""
    print("\n" + "=" * 60)
    print("Test 6: Image Processing (Optional)")
    print("=" * 60)
    
    # Check for test image
    test_images = [
        "data/test_arch.png",
        "data/architecture.png",
        "data/diagram.png",
    ]
    
    image_path = None
    for path in test_images:
        if Path(path).exists():
            image_path = path
            break
    
    if not image_path:
        print("[SKIP] No test image found. Create one of:")
        for path in test_images:
            print(f"  - {path}")
        return None  # Skip, not fail
    
    # Check for API key
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key == "your_gemini_api_key_here":
        print("[SKIP] GEMINI_API_KEY not configured")
        return None
    
    print(f"Processing image: {image_path}")
    result = process_architecture_diagram(None, image_path)
    is_valid, schema, error = validate_architecture_output(result)
    
    if not is_valid:
        print(f"[FAIL] Image processing failed: {error}")
        return False
    
    print(f"[PASS] Image processing successful")
    print(f"  - Project: {schema.project_name}")
    print(f"  - Components: {len(schema.components)}")
    print(f"  - Data Flows: {len(schema.data_flows)}")
    print(f"  - Trust Boundaries: {len(schema.trust_boundaries)}")
    
    return True


def run_all_tests():
    """Run all diagram processor tests."""
    print("\n" + "=" * 60)
    print("Vision Agent - Diagram Processor Tests")
    print("=" * 60)
    
    results = {
        "json_bypass": test_json_bypass_mode(),
        "nonexistent_file": test_nonexistent_file(),
        "invalid_json": test_invalid_json_file(),
        "schema_validation": test_schema_validation(),
        "vision_prompt": test_vision_prompt_exists(),
        "image_processing": test_image_processing(),
    }
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v is None)
    
    for name, result in results.items():
        status = "[PASS]" if result is True else "[FAIL]" if result is False else "[SKIP]"
        print(f"  {status} {name}")
    
    print(f"\nResults: {passed} passed, {failed} failed, {skipped} skipped")
    
    if failed > 0:
        print("\nSome tests failed!")
        return False
    
    print("\nAll tests passed!")
    return True


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
