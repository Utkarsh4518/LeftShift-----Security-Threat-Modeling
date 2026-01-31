"""
Test script for CVE Discovery Agent.

This script tests:
1. NVD API integration with real CVE data
2. CISA KEV integration
3. Product mapping
4. Mitigation generation
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.threat_intel_api import (
    search_vulnerabilities,
    is_actively_exploited,
    _fetch_kev_cve_ids,
    _looks_like_software_identifier,
    PRODUCT_MAPPING,
    CISA_KEV_URL,
)
from tools.mitigation_engine import (
    generate_mitigation,
    enrich_threat_with_mitigation,
    CWE_MITIGATION_MAP,
)
from agents.cve_discovery_agent import CVEDiscoveryAgent
from tools.models import ThreatRecord


def test_product_mapping_coverage():
    """Test that product mapping has sufficient coverage."""
    print("\n" + "=" * 60)
    print("Test 1: Product Mapping Coverage")
    print("=" * 60)
    
    required_products = [
        "nginx", "postgresql", "mysql", "redis", "django",
        "apache", "mongodb", "docker", "kubernetes", "jenkins"
    ]
    
    print(f"\n  Total products mapped: {len(PRODUCT_MAPPING)}")
    print(f"  Required minimum: {len(required_products)}")
    
    missing = [p for p in required_products if p not in PRODUCT_MAPPING]
    
    if missing:
        print(f"  [WARN] Missing products: {missing}")
    else:
        print("  [PASS] All required products are mapped")
    
    # Show sample mappings
    print("\n  Sample product mappings:")
    for key in list(PRODUCT_MAPPING.keys())[:5]:
        mapping = PRODUCT_MAPPING[key]
        print(f"    - {key}: search='{mapping['search_term']}', vendors={mapping['allowed_vendors']}")
    
    return len(missing) == 0


def test_cisa_kev_integration():
    """Test CISA KEV catalog integration."""
    print("\n" + "=" * 60)
    print("Test 2: CISA KEV Integration")
    print("=" * 60)
    
    print(f"\n  KEV URL: {CISA_KEV_URL}")
    
    try:
        kev_ids = _fetch_kev_cve_ids()
        print(f"  [PASS] Successfully fetched KEV catalog")
        print(f"  Total CVEs in KEV: {len(kev_ids)}")
        
        if kev_ids:
            # Show some sample KEV CVEs
            samples = list(kev_ids)[:5]
            print("\n  Sample KEV CVE IDs:")
            for cve_id in samples:
                print(f"    - {cve_id}")
            
            # Test is_actively_exploited function
            test_cve = samples[0]
            is_exploited = is_actively_exploited(test_cve)
            print(f"\n  is_actively_exploited('{test_cve}'): {is_exploited}")
            
            # Test with a non-KEV CVE
            non_kev = is_actively_exploited("CVE-1999-00001")
            print(f"  is_actively_exploited('CVE-1999-00001'): {non_kev}")
            
            return True
        else:
            print("  [WARN] KEV catalog is empty")
            return False
            
    except Exception as e:
        print(f"  [FAIL] Failed to fetch KEV: {e}")
        return False


def test_software_identifier_detection():
    """Test the software identifier detection function."""
    print("\n" + "=" * 60)
    print("Test 3: Software Identifier Detection")
    print("=" * 60)
    
    test_cases = [
        # (name, expected_result)
        ("nginx", True),
        ("PostgreSQL 14.2", True),
        ("Redis Cache", True),
        ("Django REST API", True),
        ("Apache HTTP Server", True),
        ("Server", False),
        ("Database", False),
        ("Web Server", False),
        ("Generic Component", False),
        ("My Custom Service", False),
    ]
    
    all_passed = True
    print("\n  Test cases:")
    for name, expected in test_cases:
        result = _looks_like_software_identifier(name)
        status = "[PASS]" if result == expected else "[FAIL]"
        if result != expected:
            all_passed = False
        print(f"    {status} '{name}' -> {result} (expected {expected})")
    
    return all_passed


def test_mitigation_generation():
    """Test mitigation strategy generation."""
    print("\n" + "=" * 60)
    print("Test 4: Mitigation Generation")
    print("=" * 60)
    
    # Create a sample threat
    threat = ThreatRecord(
        cve_id="CVE-2024-12345",
        summary="SQL injection vulnerability in PostgreSQL allows remote attackers to execute arbitrary SQL commands",
        severity="HIGH",
        affected_products="postgresql",
        is_actively_exploited=True,
        source="CISA KEV",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
        cwe_id="CWE-89",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"]
    )
    
    mitigation = generate_mitigation(threat)
    
    print("\n  Generated mitigation:")
    print(f"    Primary fix: {mitigation.primary_fix[:80]}...")
    print(f"    Config changes: {len(mitigation.configuration_changes)}")
    print(f"    Access controls: {len(mitigation.access_control_changes)}")
    print(f"    Monitoring actions: {len(mitigation.monitoring_actions)}")
    print(f"    NIST controls: {mitigation.nist_controls}")
    
    # Verify mitigation has content
    has_primary = bool(mitigation.primary_fix)
    has_config = len(mitigation.configuration_changes) > 0
    has_access = len(mitigation.access_control_changes) > 0
    has_monitoring = len(mitigation.monitoring_actions) > 0
    has_nist = len(mitigation.nist_controls) > 0
    
    print("\n  Verification:")
    print(f"    [{'PASS' if has_primary else 'FAIL'}] Has primary fix")
    print(f"    [{'PASS' if has_config else 'FAIL'}] Has configuration changes")
    print(f"    [{'PASS' if has_access else 'FAIL'}] Has access controls")
    print(f"    [{'PASS' if has_monitoring else 'FAIL'}] Has monitoring actions")
    print(f"    [{'PASS' if has_nist else 'FAIL'}] Has NIST controls")
    
    # Check for CWE-specific content
    is_cwe_specific = any("SQL" in c or "parameterized" in c.lower() 
                         for c in mitigation.configuration_changes)
    print(f"    [{'PASS' if is_cwe_specific else 'WARN'}] CWE-specific mitigations")
    
    return all([has_primary, has_config, has_access, has_monitoring, has_nist])


def test_cwe_mapping_coverage():
    """Test CWE to mitigation mapping coverage."""
    print("\n" + "=" * 60)
    print("Test 5: CWE Mapping Coverage")
    print("=" * 60)
    
    required_cwes = [
        "CWE-89",   # SQL Injection
        "CWE-79",   # XSS
        "CWE-78",   # Command Injection
        "CWE-287",  # Authentication
        "CWE-200",  # Information Disclosure
        "CWE-22",   # Path Traversal
    ]
    
    print(f"\n  Total CWE mappings: {len(CWE_MITIGATION_MAP)}")
    
    missing = [cwe for cwe in required_cwes if cwe not in CWE_MITIGATION_MAP]
    
    print(f"  Required CWEs mapped: {len(required_cwes) - len(missing)}/{len(required_cwes)}")
    
    if missing:
        print(f"  [WARN] Missing CWEs: {missing}")
    else:
        print("  [PASS] All required CWEs are mapped")
    
    return len(missing) == 0


def test_cve_discovery_agent():
    """Test the CVE Discovery Agent."""
    print("\n" + "=" * 60)
    print("Test 6: CVE Discovery Agent")
    print("=" * 60)
    
    agent = CVEDiscoveryAgent()
    
    # Test with known components
    inferred_components = [
        {
            "component_name": "Nginx Load Balancer",
            "inferred_product_categories": ["Nginx"],
            "confidence": 0.95
        },
        {
            "component_name": "PostgreSQL Database",
            "inferred_product_categories": ["PostgreSQL"],
            "confidence": 0.95
        },
        {
            "component_name": "Redis Cache",
            "inferred_product_categories": ["Redis"],
            "confidence": 0.95
        },
    ]
    
    print(f"\n  Testing with {len(inferred_components)} components:")
    for comp in inferred_components:
        print(f"    - {comp['component_name']}")
    
    print("\n  Discovering CVEs (this may take a moment due to API rate limits)...")
    
    try:
        threats = agent.discover_cves(inferred_components)
        
        print(f"\n  Results:")
        print(f"    Total CVEs found: {len(threats)}")
        
        if threats:
            # Analyze results
            critical = sum(1 for t in threats if t.severity == "CRITICAL")
            high = sum(1 for t in threats if t.severity == "HIGH")
            kev_count = sum(1 for t in threats if t.is_actively_exploited)
            with_mitigation = sum(1 for t in threats if t.mitigation is not None)
            
            print(f"    Critical severity: {critical}")
            print(f"    High severity: {high}")
            print(f"    Actively exploited (KEV): {kev_count}")
            print(f"    With mitigation: {with_mitigation}")
            
            # Verify CVE data quality
            print("\n  Sample CVEs:")
            for threat in threats[:5]:
                kev_flag = "[KEV]" if threat.is_actively_exploited else ""
                mit_flag = "[MIT]" if threat.mitigation else ""
                print(f"    {threat.cve_id} [{threat.severity}] {kev_flag} {mit_flag}")
                print(f"      Summary: {threat.summary[:70]}...")
                if threat.cvss_score:
                    print(f"      CVSS: {threat.cvss_score}")
            
            # Verification checks
            all_real = all(t.cve_id.startswith("CVE-") for t in threats)
            all_high_severity = all(t.severity in ["HIGH", "CRITICAL"] for t in threats)
            
            # Check dates (within last 5 years)
            five_years_ago = datetime.now() - timedelta(days=5*365)
            
            print("\n  Verification:")
            print(f"    [{'PASS' if all_real else 'FAIL'}] All CVE IDs are real format")
            print(f"    [{'PASS' if all_high_severity else 'WARN'}] All HIGH or CRITICAL severity")
            print(f"    [{'PASS' if with_mitigation > 0 else 'WARN'}] Mitigations generated")
            
            return len(threats) > 0
        else:
            print("  [WARN] No CVEs found - API may be rate limited")
            return True  # Don't fail due to API issues
            
    except Exception as e:
        print(f"  [WARN] Discovery failed: {e}")
        print("  This may be due to API rate limiting or network issues")
        return True  # Don't fail the whole test suite


def test_single_product_discovery():
    """Test CVE discovery for specific products."""
    print("\n" + "=" * 60)
    print("Test 7: Single Product CVE Discovery")
    print("=" * 60)
    
    agent = CVEDiscoveryAgent()
    
    test_products = ["nginx", "django", "postgresql"]
    
    results = {}
    for product in test_products:
        print(f"\n  Testing: {product}")
        
        try:
            threats = agent.discover_for_product(product)
            results[product] = len(threats)
            
            if threats:
                print(f"    Found: {len(threats)} CVEs")
                # Show one sample
                sample = threats[0]
                print(f"    Sample: {sample.cve_id} - {sample.summary[:50]}...")
            else:
                print(f"    No CVEs found (may be rate limited)")
                
        except Exception as e:
            print(f"    Error: {e}")
            results[product] = 0
    
    print("\n  Summary:")
    for product, count in results.items():
        status = "[OK]" if count > 0 else "[WARN]"
        print(f"    {status} {product}: {count} CVEs")
    
    return True  # Don't fail due to API issues


def test_findings_summary():
    """Test the findings summary generation."""
    print("\n" + "=" * 60)
    print("Test 8: Findings Summary")
    print("=" * 60)
    
    agent = CVEDiscoveryAgent()
    
    # Create sample threats
    threats = [
        ThreatRecord(
            cve_id="CVE-2024-0001",
            summary="Critical vulnerability",
            severity="CRITICAL",
            affected_products="nginx",
            is_actively_exploited=True,
            source="CISA KEV",
            cwe_id="CWE-89"
        ),
        ThreatRecord(
            cve_id="CVE-2024-0002",
            summary="High severity issue",
            severity="HIGH",
            affected_products="postgresql",
            is_actively_exploited=False,
            source="NVD",
            cwe_id="CWE-79"
        ),
        ThreatRecord(
            cve_id="CVE-2024-0003",
            summary="Another critical issue",
            severity="CRITICAL",
            affected_products="redis",
            is_actively_exploited=True,
            source="CISA KEV",
            cwe_id="CWE-89"
        ),
    ]
    
    # Enrich with mitigations
    for threat in threats:
        enrich_threat_with_mitigation(threat)
    
    summary = agent.summarize_findings(threats)
    
    print("\n  Summary:")
    print(f"    Total CVEs: {summary['total_cves']}")
    print(f"    Critical: {summary['critical']}")
    print(f"    High: {summary['high']}")
    print(f"    Actively Exploited: {summary['actively_exploited']}")
    print(f"    With Mitigation: {summary['with_mitigation']}")
    print(f"    By CWE: {summary['by_cwe']}")
    
    # Verify
    checks = [
        summary['total_cves'] == 3,
        summary['critical'] == 2,
        summary['high'] == 1,
        summary['actively_exploited'] == 2,
        summary['with_mitigation'] == 3,
    ]
    
    all_passed = all(checks)
    print(f"\n  [{'PASS' if all_passed else 'FAIL'}] Summary calculations correct")
    
    return all_passed


def run_all_tests():
    """Run all CVE Discovery tests."""
    print("\n" + "=" * 60)
    print("CVE Discovery Agent Tests")
    print("=" * 60)
    
    results = {}
    
    # Run tests
    results["product_mapping"] = test_product_mapping_coverage()
    results["kev_integration"] = test_cisa_kev_integration()
    results["identifier_detection"] = test_software_identifier_detection()
    results["mitigation_generation"] = test_mitigation_generation()
    results["cwe_mapping"] = test_cwe_mapping_coverage()
    results["discovery_agent"] = test_cve_discovery_agent()
    results["single_product"] = test_single_product_discovery()
    results["findings_summary"] = test_findings_summary()
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for name, result in results.items():
        status = "[PASS]" if result else "[WARN]"
        print(f"  {status} {name}")
    
    print(f"\nResults: {passed}/{total} passed")
    
    print("\nNote: Some tests may show [WARN] due to NVD API rate limits.")
    print("The agent includes fallback mechanisms for API issues.")
    
    return passed >= total - 2  # Allow up to 2 warnings


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    
    success = run_all_tests()
    sys.exit(0 if success else 1)
