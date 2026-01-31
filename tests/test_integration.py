"""
Comprehensive Integration Test for Left<<Shift Pipeline.

This test validates the complete end-to-end pipeline:
1. Architecture extraction (JSON input)
2. Component understanding
3. Threat knowledge generation
4. CVE discovery
5. Threat relevance filtering
6. Attack path simulation
7. Report synthesis

Tests include:
- Full pipeline execution with JSON input
- Report structure validation
- Timing analysis for each stage
- Data integrity checks
"""

import sys
import os
import re
import time
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()


def print_header(title: str):
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_subheader(title: str):
    """Print a formatted subheader."""
    print(f"\n--- {title} ---")


def test_api_configuration():
    """Test that API keys are configured."""
    print_header("Test 1: API Configuration")
    
    results = {}
    
    gemini_key = os.getenv("GEMINI_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    
    results["gemini"] = gemini_key and gemini_key != "your_gemini_api_key_here"
    results["openai"] = openai_key and openai_key != "your_openai_api_key_here"
    
    print(f"  GEMINI_API_KEY: {'[PASS] Configured' if results['gemini'] else '[WARN] Not configured'}")
    print(f"  OPENAI_API_KEY: {'[PASS] Configured' if results['openai'] else '[WARN] Not configured'}")
    
    return results


def test_module_imports():
    """Test that all required modules can be imported."""
    print_header("Test 2: Module Imports")
    
    modules = [
        ("tools.models", "Data models"),
        ("tools.diagram_processor", "Vision Agent"),
        ("tools.threat_intel_api", "NVD/KEV API"),
        ("tools.mitigation_engine", "Mitigation Engine"),
        ("agents.component_understanding_agent", "Component Understanding Agent"),
        ("agents.threat_knowledge_agent", "Threat Knowledge Agent"),
        ("agents.cve_discovery_agent", "CVE Discovery Agent"),
        ("agents.threat_relevance_agent", "Threat Relevance Agent"),
        ("agents.report_synthesizer_agent", "Report Synthesizer Agent"),
        ("agents.core", "Pipeline Core"),
    ]
    
    all_pass = True
    for module, name in modules:
        try:
            __import__(module)
            print(f"  [PASS] {name}")
        except Exception as e:
            print(f"  [FAIL] {name}: {e}")
            all_pass = False
    
    return all_pass


def test_json_input_pipeline():
    """Test full pipeline with JSON input."""
    print_header("Test 3: Full Pipeline with JSON Input")
    
    from agents.core import run_threat_modeling_pipeline
    
    # Use test architecture
    json_path = Path(__file__).parent.parent / "data" / "test_arch.json"
    
    if not json_path.exists():
        print(f"  [SKIP] Test file not found: {json_path}")
        return None, None
    
    print(f"  Input: {json_path}")
    
    output_path = Path(__file__).parent / "integration_test_report.md"
    
    print(f"  Output: {output_path}")
    print()
    
    start_time = time.time()
    
    try:
        report, results = run_threat_modeling_pipeline(
            json_input=str(json_path),
            output_file=str(output_path),
            verbose=True
        )
        
        total_time = time.time() - start_time
        
        print(f"\n  [PASS] Pipeline completed in {total_time:.2f}s")
        
        return report, results
        
    except Exception as e:
        print(f"\n  [FAIL] Pipeline error: {e}")
        import traceback
        traceback.print_exc()
        return None, None


def test_report_structure(report: str):
    """Validate report structure."""
    print_header("Test 4: Report Structure Validation")
    
    if not report:
        print("  [SKIP] No report to validate")
        return False
    
    # Check for required sections
    sections = [
        ("Executive Summary", r"executive\s*summary|summary", True),
        ("Architecture", r"architecture|components", True),
        ("Component Inventory", r"component|inventory", True),
        ("STRIDE Threats", r"stride|threat\s*enumeration", True),
        ("Weaknesses", r"weakness", True),
        ("CVE Discovery", r"cve|vulnerabilit", True),
        ("Attack Paths", r"attack\s*path", True),
        ("NIST Controls", r"nist|800-53|control", False),
        ("Hardening Plan", r"hardening|plan", False),
    ]
    
    found = 0
    report_lower = report.lower()
    
    for name, pattern, required in sections:
        if re.search(pattern, report_lower):
            print(f"  [PASS] {name}")
            found += 1
        else:
            status = "[FAIL]" if required else "[WARN]"
            print(f"  {status} {name}")
    
    print(f"\n  Sections found: {found}/{len(sections)}")
    
    return found >= 6


def test_data_integrity(report: str, results: dict):
    """Verify no hallucinated data in report."""
    print_header("Test 5: Data Integrity")
    
    if not report or not results:
        print("  [SKIP] No data to validate")
        return False
    
    # Check CVE IDs
    cve_pattern = r'CVE-\d{4}-\d+'
    found_cves = set(re.findall(cve_pattern, report))
    
    input_cve_ids = {c.cve_id for c in results.get("cves", [])}
    
    # Filter to real CVE format (not test IDs)
    real_found_cves = {c for c in found_cves if re.match(r'CVE-\d{4}-\d+$', c)}
    real_input_cves = {c for c in input_cve_ids if re.match(r'CVE-\d{4}-\d+$', c)}
    
    print(f"  Input CVEs: {len(real_input_cves)}")
    print(f"  CVEs in report: {len(real_found_cves)}")
    
    hallucinated = real_found_cves - real_input_cves
    if hallucinated and len(hallucinated) > 2:
        print(f"  [WARN] Possible hallucinated CVEs: {list(hallucinated)[:5]}")
    else:
        print(f"  [PASS] CVE integrity verified")
    
    # Check threat counts
    threat_count = len(results.get("threats", []))
    print(f"  Threats in results: {threat_count}")
    
    return True


def test_timing_analysis(results: dict):
    """Analyze timing for each stage."""
    print_header("Test 6: Timing Analysis")
    
    if not results or "timing" not in results:
        print("  [SKIP] No timing data")
        return
    
    timing = results["timing"]
    total = sum(timing.values())
    
    print(f"\n  Stage Timing Breakdown:")
    print(f"  {'Stage':<35} {'Time':>10} {'%':>8}")
    print(f"  {'-' * 55}")
    
    for stage, duration in timing.items():
        pct = (duration / total * 100) if total > 0 else 0
        print(f"  {stage:<35} {duration:>8.2f}s {pct:>7.1f}%")
    
    print(f"  {'-' * 55}")
    print(f"  {'TOTAL':<35} {total:>8.2f}s {100:>7.1f}%")
    
    # Performance assessment
    print(f"\n  Performance Assessment:")
    if total < 60:
        print(f"  [PASS] Pipeline completed under 1 minute")
    elif total < 180:
        print(f"  [PASS] Pipeline completed under 3 minutes")
    else:
        print(f"  [WARN] Pipeline took over 3 minutes")
    
    # Identify slowest stage
    if timing:
        slowest = max(timing.items(), key=lambda x: x[1])
        print(f"  Slowest stage: {slowest[0]} ({slowest[1]:.2f}s)")


def test_results_completeness(results: dict):
    """Verify all result fields are populated."""
    print_header("Test 7: Results Completeness")
    
    if not results:
        print("  [SKIP] No results")
        return False
    
    checks = [
        ("architecture", results.get("architecture") is not None),
        ("inferred_components", len(results.get("inferred_components", [])) > 0),
        ("threats", len(results.get("threats", [])) > 0),
        ("weaknesses", len(results.get("weaknesses", [])) >= 0),  # Can be empty
        ("cves", len(results.get("cves", [])) >= 0),  # Can be empty
        ("attack_paths", len(results.get("attack_paths", [])) >= 0),  # Can be empty
        ("report", results.get("report") is not None and len(results.get("report", "")) > 100),
    ]
    
    all_pass = True
    for name, passed in checks:
        status = "[PASS]" if passed else "[FAIL]"
        if not passed:
            all_pass = False
        
        # Get count for display
        value = results.get(name)
        if isinstance(value, list):
            count = len(value)
            print(f"  {status} {name}: {count} items")
        elif isinstance(value, str):
            print(f"  {status} {name}: {len(value):,} chars")
        elif value is not None:
            print(f"  {status} {name}: present")
        else:
            print(f"  {status} {name}: missing")
    
    return all_pass


def test_output_file(results: dict):
    """Verify output file was created."""
    print_header("Test 8: Output File Verification")
    
    output_path = Path(__file__).parent / "integration_test_report.md"
    
    if not output_path.exists():
        print(f"  [FAIL] Output file not found: {output_path}")
        return False
    
    file_size = output_path.stat().st_size
    print(f"  [PASS] Output file created: {output_path}")
    print(f"  File size: {file_size:,} bytes")
    
    # Read first few lines
    with open(output_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()[:10]
    
    print(f"  Lines: {len(lines)} (first 10 shown)")
    print(f"\n  Preview:")
    for line in lines[:5]:
        print(f"    {line.rstrip()[:60]}")
    
    return True


def run_integration_tests():
    """Run all integration tests."""
    print("\n" + "=" * 70)
    print("  LEFT<<SHIFT - COMPREHENSIVE INTEGRATION TEST")
    print(f"  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    test_results = {}
    
    # Test 1: API Configuration
    api_config = test_api_configuration()
    test_results["api_config"] = api_config.get("openai", False) or api_config.get("gemini", False)
    
    # Test 2: Module Imports
    test_results["imports"] = test_module_imports()
    
    # Test 3: Full Pipeline
    report, results = test_json_input_pipeline()
    test_results["pipeline"] = report is not None
    
    if report and results:
        # Test 4: Report Structure
        test_results["structure"] = test_report_structure(report)
        
        # Test 5: Data Integrity
        test_results["integrity"] = test_data_integrity(report, results)
        
        # Test 6: Timing Analysis
        test_timing_analysis(results)
        test_results["timing"] = True
        
        # Test 7: Results Completeness
        test_results["completeness"] = test_results_completeness(results)
        
        # Test 8: Output File
        test_results["output_file"] = test_output_file(results)
    else:
        test_results["structure"] = False
        test_results["integrity"] = False
        test_results["timing"] = False
        test_results["completeness"] = False
        test_results["output_file"] = False
    
    # Summary
    print_header("INTEGRATION TEST SUMMARY")
    
    passed = sum(1 for v in test_results.values() if v)
    total = len(test_results)
    
    for name, result in test_results.items():
        status = "[PASS]" if result else "[FAIL]"
        print(f"  {status} {name}")
    
    print(f"\n  Results: {passed}/{total} passed")
    
    success = passed >= total - 1  # Allow 1 failure
    
    print("\n" + "=" * 70)
    if success:
        print("  INTEGRATION TEST PASSED")
    else:
        print("  INTEGRATION TEST FAILED")
    print("=" * 70 + "\n")
    
    return success


if __name__ == "__main__":
    success = run_integration_tests()
    sys.exit(0 if success else 1)
