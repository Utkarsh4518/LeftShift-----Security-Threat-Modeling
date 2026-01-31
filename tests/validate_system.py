"""
System Validation Script for Left<<Shift Threat Modeling System.

This script validates the complete architecture including:
1. All Pydantic models
2. Vision Agent (Diagram Processor)
3. Import chain integrity
4. Environment configuration
"""

import json
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def validate_imports():
    """Validate all module imports work correctly."""
    print("\n" + "=" * 60)
    print("Step 1: Validating Module Imports")
    print("=" * 60)
    
    errors = []
    
    # Test models import
    try:
        from tools.models import (
            Component,
            DataFlow,
            ArchitectureSchema,
            MitigationStrategy,
            ThreatRecord,
            CVE,
            ArchitecturalThreat,
            ArchitecturalWeakness,
            AttackPathStep,
            AttackPath,
            ThreatSearchResults,
            AttackPathList,
        )
        print("  [OK] tools.models - All 12 models imported")
    except ImportError as e:
        errors.append(f"tools.models: {e}")
        print(f"  [FAIL] tools.models: {e}")
    
    # Test diagram processor import
    try:
        from tools.diagram_processor import (
            process_architecture_diagram,
            validate_architecture_output,
            VISION_PROMPT,
        )
        print("  [OK] tools.diagram_processor - All functions imported")
    except ImportError as e:
        errors.append(f"tools.diagram_processor: {e}")
        print(f"  [FAIL] tools.diagram_processor: {e}")
    
    return len(errors) == 0, errors


def validate_models():
    """Validate all Pydantic models can be instantiated."""
    print("\n" + "=" * 60)
    print("Step 2: Validating Pydantic Models")
    print("=" * 60)
    
    from tools.models import (
        Component,
        DataFlow,
        ArchitectureSchema,
        MitigationStrategy,
        ThreatRecord,
        ArchitecturalThreat,
        ArchitecturalWeakness,
        AttackPathStep,
        AttackPath,
        ThreatSearchResults,
        AttackPathList,
    )
    
    errors = []
    
    # Test each model
    models_to_test = [
        ("Component", lambda: Component(name="Test", type="Server")),
        ("DataFlow", lambda: DataFlow(source="A", destination="B", protocol="HTTPS")),
        ("ArchitectureSchema", lambda: ArchitectureSchema(description="Test")),
        ("MitigationStrategy", lambda: MitigationStrategy(primary_fix="Update")),
        ("ThreatRecord", lambda: ThreatRecord(
            cve_id="CVE-2024-1234",
            summary="Test",
            severity="HIGH",
            affected_products="Test",
            source="NVD"
        )),
        ("ArchitecturalThreat", lambda: ArchitecturalThreat(
            threat_id="T-001",
            category="Spoofing",
            description="Test",
            affected_component="Auth",
            severity="High"
        )),
        ("ArchitecturalWeakness", lambda: ArchitecturalWeakness(
            weakness_id="W-001",
            title="Test",
            description="Test",
            impact="Test",
            mitigation="Test"
        )),
        ("AttackPathStep", lambda: AttackPathStep(
            step_number=1,
            action="Test",
            target_component="Server",
            technique="T1234",
            outcome="Access"
        )),
        ("AttackPath", lambda: AttackPath(
            path_id="AP-01",
            name="Test",
            description="Test",
            impact="High",
            likelihood="Medium"
        )),
        ("ThreatSearchResults", lambda: ThreatSearchResults()),
        ("AttackPathList", lambda: AttackPathList()),
    ]
    
    for name, factory in models_to_test:
        try:
            instance = factory()
            # Test serialization
            _ = instance.model_dump()
            _ = instance.model_dump_json()
            print(f"  [OK] {name}")
        except Exception as e:
            errors.append(f"{name}: {e}")
            print(f"  [FAIL] {name}: {e}")
    
    return len(errors) == 0, errors


def validate_diagram_processor():
    """Validate diagram processor functionality."""
    print("\n" + "=" * 60)
    print("Step 3: Validating Diagram Processor")
    print("=" * 60)
    
    from tools.diagram_processor import (
        process_architecture_diagram,
        validate_architecture_output,
    )
    
    errors = []
    
    # Test JSON bypass mode
    json_path = "data/test_arch.json"
    if Path(json_path).exists():
        result = process_architecture_diagram(None, json_path)
        is_valid, schema, error = validate_architecture_output(result)
        if is_valid:
            print(f"  [OK] JSON bypass mode - {len(schema.components)} components")
        else:
            errors.append(f"JSON bypass: {error}")
            print(f"  [FAIL] JSON bypass: {error}")
    else:
        print(f"  [SKIP] JSON bypass - test file not found")
    
    # Test error handling
    result = process_architecture_diagram(None, "nonexistent.png")
    data = json.loads(result)
    if "error" in data:
        print("  [OK] Error handling - correctly returns error dict")
    else:
        errors.append("Error handling failed")
        print("  [FAIL] Error handling - should return error dict")
    
    return len(errors) == 0, errors


def validate_environment():
    """Validate environment configuration."""
    print("\n" + "=" * 60)
    print("Step 4: Validating Environment")
    print("=" * 60)
    
    warnings = []
    
    # Check .env file
    if Path(".env").exists():
        print("  [OK] .env file exists")
    else:
        warnings.append(".env file not found")
        print("  [WARN] .env file not found")
    
    # Check API key (don't reveal value)
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key and api_key != "your_gemini_api_key_here":
        print("  [OK] GEMINI_API_KEY is configured")
    else:
        warnings.append("GEMINI_API_KEY not configured")
        print("  [WARN] GEMINI_API_KEY not configured (required for image processing)")
    
    # Check virtual environment
    if "venv" in sys.prefix.lower() or ".venv" in sys.prefix.lower():
        print("  [OK] Running in virtual environment")
    else:
        warnings.append("Not in virtual environment")
        print("  [WARN] Not running in virtual environment")
    
    return True, warnings  # Warnings don't fail validation


def validate_project_structure():
    """Validate project directory structure."""
    print("\n" + "=" * 60)
    print("Step 5: Validating Project Structure")
    print("=" * 60)
    
    required_files = [
        "README.md",
        "requirements.txt",
        ".gitignore",
        "tools/__init__.py",
        "tools/models.py",
        "tools/diagram_processor.py",
        "tests/__init__.py",
        "tests/test_models.py",
        "tests/test_diagram_processor.py",
        "data/test_arch.json",
    ]
    
    missing = []
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"  [OK] {file_path}")
        else:
            missing.append(file_path)
            print(f"  [MISSING] {file_path}")
    
    return len(missing) == 0, missing


def run_full_validation():
    """Run complete system validation."""
    print("\n" + "=" * 60)
    print("LEFT<<SHIFT - SYSTEM VALIDATION")
    print("=" * 60)
    
    results = {}
    
    # Run all validation steps
    results["imports"] = validate_imports()
    results["models"] = validate_models()
    results["diagram_processor"] = validate_diagram_processor()
    results["environment"] = validate_environment()
    results["structure"] = validate_project_structure()
    
    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for name, (passed, issues) in results.items():
        status = "PASS" if passed else "FAIL"
        if not passed and name != "environment":  # Environment warnings don't fail
            all_passed = False
        
        issue_count = len(issues) if issues else 0
        print(f"  [{status}] {name}: {issue_count} issues")
        
        if issues and not passed:
            for issue in issues[:3]:  # Show first 3 issues
                print(f"        - {issue}")
    
    print("\n" + "=" * 60)
    if all_passed:
        print("SYSTEM VALIDATION PASSED")
        print("Left<<Shift is ready for Phase 3 (Architecture Understanding)")
    else:
        print("SYSTEM VALIDATION FAILED")
        print("Please fix the issues above before proceeding")
    print("=" * 60 + "\n")
    
    return all_passed


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    
    success = run_full_validation()
    sys.exit(0 if success else 1)
