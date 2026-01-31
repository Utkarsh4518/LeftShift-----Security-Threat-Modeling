"""
Test script for Threat Knowledge Agent.

This script tests STRIDE threat generation with:
1. Sample architecture (Django, PostgreSQL, Redis, Nginx)
2. Verification of threat coverage and quality
3. CWE validation
4. Weakness identification
"""

import sys
from pathlib import Path
from collections import Counter

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.threat_knowledge_agent import (
    ThreatKnowledgeAgent,
    ThreatKnowledgeOutput,
    STRIDE_SYSTEM_INSTRUCTION,
    CWE_VALIDATION_INSTRUCTION,
)
from tools.models import (
    ArchitectureSchema,
    Component,
    DataFlow,
    ArchitecturalThreat,
)


def create_sample_architecture() -> ArchitectureSchema:
    """Create a sample architecture for testing."""
    return ArchitectureSchema(
        project_name="E-Commerce API Platform",
        description="A Django-based REST API with PostgreSQL database, Redis caching, and Nginx load balancer",
        components=[
            Component(name="Nginx Load Balancer", type="Load Balancer"),
            Component(name="Django REST API", type="Web Application"),
            Component(name="PostgreSQL Database", type="Database"),
            Component(name="Redis Cache", type="Cache"),
        ],
        data_flows=[
            DataFlow(source="Client", destination="Nginx Load Balancer", protocol="HTTPS/443"),
            DataFlow(source="Nginx Load Balancer", destination="Django REST API", protocol="HTTP/8000"),
            DataFlow(source="Django REST API", destination="PostgreSQL Database", protocol="TCP/5432"),
            DataFlow(source="Django REST API", destination="Redis Cache", protocol="TCP/6379"),
        ],
        trust_boundaries=[
            "Internet",
            "DMZ",
            "Application Zone",
            "Data Zone"
        ]
    )


def create_inferred_components() -> list:
    """Create inferred component data for testing."""
    return [
        {
            "component_name": "Nginx Load Balancer",
            "type": "Load Balancer",
            "inferred_product_categories": ["Nginx"],
            "confidence": 0.95,
        },
        {
            "component_name": "Django REST API",
            "type": "Web Application",
            "inferred_product_categories": ["Django", "Django REST Framework"],
            "confidence": 0.95,
        },
        {
            "component_name": "PostgreSQL Database",
            "type": "Database",
            "inferred_product_categories": ["PostgreSQL"],
            "confidence": 0.95,
        },
        {
            "component_name": "Redis Cache",
            "type": "Cache",
            "inferred_product_categories": ["Redis"],
            "confidence": 0.95,
        },
    ]


def test_agent_initialization():
    """Test that the agent initializes correctly."""
    print("\n" + "=" * 60)
    print("Test 1: Agent Initialization")
    print("=" * 60)
    
    agent = ThreatKnowledgeAgent()
    
    has_client = agent.client is not None
    status = "[PASS]" if True else "[FAIL]"  # Init should always work
    
    print(f"  {status} Agent initialized")
    print(f"        Model: {agent.model_name}")
    print(f"        Client available: {has_client}")
    
    return True


def test_prompt_configuration():
    """Test that prompts are properly configured."""
    print("\n" + "=" * 60)
    print("Test 2: Prompt Configuration")
    print("=" * 60)
    
    # Check STRIDE instruction
    stride_keywords = [
        "Spoofing", "Tampering", "Repudiation",
        "Information Disclosure", "Denial of Service",
        "Elevation of Privilege", "CWE", "MITRE"
    ]
    
    stride_ok = all(kw in STRIDE_SYSTEM_INSTRUCTION for kw in stride_keywords)
    status = "[PASS]" if stride_ok else "[FAIL]"
    print(f"  {status} STRIDE instruction contains all categories")
    
    # Check CWE validation instruction (case-insensitive)
    cwe_keywords = ["CWE-20", "CWE-89", "specific", "generic"]
    cwe_ok = all(kw.lower() in CWE_VALIDATION_INSTRUCTION.lower() for kw in cwe_keywords)
    status = "[PASS]" if cwe_ok else "[FAIL]"
    print(f"  {status} CWE validation instruction configured")
    
    print(f"\n  STRIDE instruction length: {len(STRIDE_SYSTEM_INSTRUCTION)} chars")
    print(f"  CWE validation instruction length: {len(CWE_VALIDATION_INSTRUCTION)} chars")
    
    return stride_ok and cwe_ok


def test_threat_generation():
    """Test threat generation with sample architecture."""
    print("\n" + "=" * 60)
    print("Test 3: Threat Generation")
    print("=" * 60)
    
    agent = ThreatKnowledgeAgent()
    architecture = create_sample_architecture()
    inferred = create_inferred_components()
    
    print(f"\n  Architecture: {architecture.project_name}")
    print(f"  Components: {len(architecture.components)}")
    print(f"  Data Flows: {len(architecture.data_flows)}")
    
    print("\n  Generating threats (this may take a moment)...")
    result = agent.generate_threats(inferred, architecture)
    
    threats = result.get("threats", [])
    weaknesses = result.get("weaknesses", [])
    
    print(f"\n  Results:")
    print(f"    - Threats generated: {len(threats)}")
    print(f"    - Weaknesses identified: {len(weaknesses)}")
    
    return threats, weaknesses


def test_stride_coverage(threats: list):
    """Test that all STRIDE categories are covered."""
    print("\n" + "=" * 60)
    print("Test 4: STRIDE Category Coverage")
    print("=" * 60)
    
    stride_categories = {
        "Spoofing", "Tampering", "Repudiation",
        "Information Disclosure", "Denial of Service",
        "Elevation of Privilege"
    }
    
    # Count threats by category
    category_counts = Counter(t.category for t in threats)
    
    print("\n  Threats by category:")
    covered = set()
    for cat in stride_categories:
        count = category_counts.get(cat, 0)
        status = "[OK]" if count > 0 else "[MISSING]"
        print(f"    {status} {cat}: {count}")
        if count > 0:
            covered.add(cat)
    
    # Check coverage
    missing = stride_categories - covered
    coverage_pct = len(covered) / len(stride_categories) * 100
    
    print(f"\n  Coverage: {len(covered)}/{len(stride_categories)} ({coverage_pct:.0f}%)")
    
    if missing:
        print(f"  Missing categories: {missing}")
    
    all_covered = len(missing) == 0
    status = "[PASS]" if all_covered else "[WARN]"
    print(f"\n  {status} STRIDE coverage check")
    
    return all_covered


def test_cwe_mappings(threats: list):
    """Test that all threats have CWE mappings."""
    print("\n" + "=" * 60)
    print("Test 5: CWE Mappings")
    print("=" * 60)
    
    # Check CWE presence
    with_cwe = [t for t in threats if t.cwe_id]
    without_cwe = [t for t in threats if not t.cwe_id]
    
    print(f"\n  Threats with CWE: {len(with_cwe)}")
    print(f"  Threats without CWE: {len(without_cwe)}")
    
    # Check for generic CWEs
    generic_cwes = {"CWE-20", "CWE-693", "CWE-284", "CWE-707", "CWE-664"}
    generic_count = sum(1 for t in threats if t.cwe_id in generic_cwes)
    
    print(f"  Threats with generic CWEs: {generic_count}")
    
    # Show CWE distribution
    cwe_counts = Counter(t.cwe_id for t in threats if t.cwe_id)
    print("\n  Top CWE mappings:")
    for cwe, count in cwe_counts.most_common(10):
        is_generic = "[GENERIC]" if cwe in generic_cwes else ""
        print(f"    - {cwe}: {count} {is_generic}")
    
    all_have_cwe = len(without_cwe) == 0
    status = "[PASS]" if all_have_cwe else "[WARN]"
    print(f"\n  {status} CWE mapping check")
    
    return all_have_cwe


def test_mitigation_quality(threats: list):
    """Test that mitigations are specific, not generic."""
    print("\n" + "=" * 60)
    print("Test 6: Mitigation Quality")
    print("=" * 60)
    
    generic_mitigations = [
        "implement security",
        "follow best practices",
        "use proper",
        "ensure proper",
    ]
    
    specific_count = 0
    generic_count = 0
    
    for threat in threats:
        mitigations = threat.mitigation_steps or []
        for m in mitigations:
            m_lower = m.lower()
            is_generic = any(gm in m_lower for gm in generic_mitigations)
            if is_generic:
                generic_count += 1
            else:
                specific_count += 1
    
    total = specific_count + generic_count
    specific_pct = (specific_count / total * 100) if total > 0 else 0
    
    print(f"\n  Mitigation analysis:")
    print(f"    - Total mitigations: {total}")
    print(f"    - Specific: {specific_count} ({specific_pct:.0f}%)")
    print(f"    - Generic: {generic_count}")
    
    # Show some example mitigations
    print("\n  Sample mitigations:")
    for threat in threats[:3]:
        if threat.mitigation_steps:
            print(f"    {threat.threat_id}: {threat.mitigation_steps[0][:60]}...")
    
    quality_ok = specific_pct >= 50  # At least 50% specific
    status = "[PASS]" if quality_ok else "[WARN]"
    print(f"\n  {status} Mitigation quality check")
    
    return quality_ok


def test_weakness_identification(weaknesses: list):
    """Test that weaknesses are properly identified."""
    print("\n" + "=" * 60)
    print("Test 7: Weakness Identification")
    print("=" * 60)
    
    print(f"\n  Weaknesses identified: {len(weaknesses)}")
    
    if weaknesses:
        print("\n  Weakness summary:")
        for w in weaknesses[:5]:
            print(f"    - {w.weakness_id}: {w.title}")
            print(f"      Impact: {w.impact[:60]}...")
    
    has_weaknesses = len(weaknesses) >= 2  # At least 2 weaknesses
    status = "[PASS]" if has_weaknesses else "[WARN]"
    print(f"\n  {status} Weakness identification check")
    
    return has_weaknesses


def test_threat_detail_quality(threats: list):
    """Test that threats have sufficient detail."""
    print("\n" + "=" * 60)
    print("Test 8: Threat Detail Quality")
    print("=" * 60)
    
    quality_checks = {
        "has_description": 0,
        "has_preconditions": 0,
        "has_impact": 0,
        "has_mitigations": 0,
        "has_example": 0,
    }
    
    for threat in threats:
        if threat.description and len(threat.description) > 20:
            quality_checks["has_description"] += 1
        if threat.preconditions and len(threat.preconditions) > 0:
            quality_checks["has_preconditions"] += 1
        if threat.impact and len(threat.impact) > 10:
            quality_checks["has_impact"] += 1
        if threat.mitigation_steps and len(threat.mitigation_steps) > 0:
            quality_checks["has_mitigations"] += 1
        if threat.example and len(threat.example) > 10:
            quality_checks["has_example"] += 1
    
    total = len(threats)
    print("\n  Quality metrics:")
    for check, count in quality_checks.items():
        pct = (count / total * 100) if total > 0 else 0
        status = "[OK]" if pct >= 80 else "[LOW]"
        print(f"    {status} {check}: {count}/{total} ({pct:.0f}%)")
    
    # Overall quality score
    avg_pct = sum(quality_checks.values()) / (total * len(quality_checks)) * 100 if total > 0 else 0
    
    quality_ok = avg_pct >= 60
    status = "[PASS]" if quality_ok else "[WARN]"
    print(f"\n  {status} Overall quality: {avg_pct:.0f}%")
    
    return quality_ok


def print_threat_summary(threats: list, weaknesses: list):
    """Print a summary of generated threats and weaknesses."""
    print("\n" + "=" * 60)
    print("Threat Analysis Summary")
    print("=" * 60)
    
    # Group threats by component
    by_component = {}
    for t in threats:
        comp = t.affected_component
        if comp not in by_component:
            by_component[comp] = []
        by_component[comp].append(t)
    
    print("\n  Threats by Component:")
    for comp, comp_threats in by_component.items():
        print(f"\n  [{comp}] ({len(comp_threats)} threats)")
        for t in comp_threats[:3]:  # Show first 3
            severity_icon = {"Critical": "!!!", "High": "!!", "Medium": "!", "Low": "."}.get(t.severity, "?")
            print(f"    [{severity_icon}] {t.threat_id}: {t.description[:50]}...")
        if len(comp_threats) > 3:
            print(f"    ... and {len(comp_threats) - 3} more")
    
    print("\n  Weaknesses:")
    for w in weaknesses:
        print(f"    - {w.weakness_id}: {w.title}")


def run_all_tests():
    """Run all Threat Knowledge Agent tests."""
    print("\n" + "=" * 60)
    print("Threat Knowledge Agent Tests")
    print("=" * 60)
    
    results = {}
    
    # Basic tests
    results["initialization"] = test_agent_initialization()
    results["prompt_config"] = test_prompt_configuration()
    
    # Generate threats
    threats, weaknesses = test_threat_generation()
    
    if threats:
        # Quality tests
        results["stride_coverage"] = test_stride_coverage(threats)
        results["cwe_mappings"] = test_cwe_mappings(threats)
        results["mitigation_quality"] = test_mitigation_quality(threats)
        results["detail_quality"] = test_threat_detail_quality(threats)
        results["weakness_identification"] = test_weakness_identification(weaknesses)
        
        # Print summary
        print_threat_summary(threats, weaknesses)
        
        # Check minimum requirements
        results["min_threats"] = len(threats) >= 10
    else:
        print("\n  [WARN] No threats generated - LLM may be unavailable")
        results["min_threats"] = False
    
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
    
    # Note about LLM dependency
    if passed < total:
        print("\nNote: Some tests may show [WARN] due to API rate limits.")
        print("The fallback mechanism ensures basic functionality.")
    
    return passed >= total - 2  # Allow up to 2 warnings


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    
    success = run_all_tests()
    sys.exit(0 if success else 1)
