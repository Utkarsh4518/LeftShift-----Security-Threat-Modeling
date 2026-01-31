"""
Test script for Component Understanding Agent.

This script tests:
1. Heuristic detection of known products
2. LLM-based inference for generic labels
3. Context-aware inference
4. Edge case handling
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.component_understanding_agent import (
    ComponentUnderstandingAgent,
    _looks_like_software_identifier,
    get_generic_category,
    GENERIC_LABELS,
    KNOWN_TECH,
)


def test_heuristic_detection():
    """Test the _looks_like_software_identifier function."""
    print("\n" + "=" * 60)
    print("Test 1: Heuristic Detection")
    print("=" * 60)
    
    # Known products - should return True
    known_products = [
        "nginx",
        "PostgreSQL 14.2",
        "Redis Cache",
        "Apache Kafka",
        "MongoDB",
        "Docker",
        "Kubernetes",
        "Django REST API",
        "React Frontend",
        "Spring Boot 3.0",
    ]
    
    print("\n  Known Products (should detect as software):")
    all_passed = True
    for product in known_products:
        result = _looks_like_software_identifier(product)
        status = "[PASS]" if result else "[FAIL]"
        if not result:
            all_passed = False
        print(f"    {status} '{product}' -> {result}")
    
    # Generic labels - should return False
    generic_labels = [
        "Server",
        "Database",
        "Production Server",
        "Web Server",
        "API Gateway",
        "Cache",
        "Message Queue",
        "Load Balancer",
    ]
    
    print("\n  Generic Labels (should NOT detect as software):")
    for label in generic_labels:
        result = _looks_like_software_identifier(label)
        status = "[PASS]" if not result else "[FAIL]"
        if result:
            all_passed = False
        print(f"    {status} '{label}' -> {result}")
    
    return all_passed


def test_version_detection():
    """Test version number detection in component names."""
    print("\n" + "=" * 60)
    print("Test 2: Version Number Detection")
    print("=" * 60)
    
    versioned = [
        ("PostgreSQL 14.2", True),
        ("Redis 7.0", True),
        ("v1.2.3 Release", True),
        ("nginx 1.21.0", True),
        ("MySQL 8.0.33", True),
        ("Server", False),
        ("Database", False),
        ("Production", False),
    ]
    
    all_passed = True
    for name, expected in versioned:
        result = _looks_like_software_identifier(name)
        # For versioned items, we expect True; for non-versioned generic, False
        passed = result == expected
        status = "[PASS]" if passed else "[FAIL]"
        if not passed:
            all_passed = False
        print(f"  {status} '{name}' -> {result} (expected {expected})")
    
    return all_passed


def test_generic_category_mapping():
    """Test mapping from generic labels to technology categories."""
    print("\n" + "=" * 60)
    print("Test 3: Generic Category Mapping")
    print("=" * 60)
    
    test_cases = [
        ("database", ["PostgreSQL", "MySQL", "MongoDB", "Redis"]),
        ("cache", ["Redis", "Memcached", "Hazelcast"]),
        ("message queue", ["RabbitMQ", "Apache Kafka", "Amazon SQS", "Redis"]),
        ("web server", ["Nginx", "Apache HTTP Server", "Caddy"]),
        ("unknown component", None),
    ]
    
    all_passed = True
    for label, expected in test_cases:
        result = get_generic_category(label)
        
        if expected is None:
            passed = result is None
        else:
            passed = result is not None and result[0] == expected[0]
        
        status = "[PASS]" if passed else "[FAIL]"
        if not passed:
            all_passed = False
        
        result_str = result[0] if result else "None"
        print(f"  {status} '{label}' -> {result_str}")
    
    return all_passed


def test_known_products_inference():
    """Test inference with known products."""
    print("\n" + "=" * 60)
    print("Test 4: Known Products Inference")
    print("=" * 60)
    
    agent = ComponentUnderstandingAgent()
    
    known_products = ["nginx", "PostgreSQL 14.2", "Redis Cache"]
    results = agent.infer_components(known_products)
    
    all_passed = True
    print("\n  Results:")
    for result in results:
        name = result["component_name"]
        categories = result["inferred_product_categories"]
        confidence = result["confidence"]
        method = result["detection_method"]
        
        # Known products should have high confidence
        passed = confidence >= 0.9 and method == "heuristic"
        status = "[PASS]" if passed else "[FAIL]"
        if not passed:
            all_passed = False
        
        print(f"  {status} {name}")
        print(f"        Categories: {categories}")
        print(f"        Confidence: {confidence:.2f}")
        print(f"        Method: {method}")
    
    return all_passed


def test_generic_labels_inference():
    """Test inference with generic labels."""
    print("\n" + "=" * 60)
    print("Test 5: Generic Labels Inference")
    print("=" * 60)
    
    agent = ComponentUnderstandingAgent()
    
    generic_labels = ["Production Server", "Database", "Web Server"]
    results = agent.infer_components(generic_labels)
    
    all_passed = True
    print("\n  Results:")
    for result in results:
        name = result["component_name"]
        categories = result["inferred_product_categories"]
        confidence = result["confidence"]
        reasoning = result["reasoning"]
        method = result["detection_method"]
        
        # Generic labels should have inferred categories
        passed = len(categories) > 0 and categories[0] != ""
        status = "[PASS]" if passed else "[FAIL]"
        if not passed:
            all_passed = False
        
        print(f"  {status} {name}")
        print(f"        Inferred: {categories[:3]}")
        print(f"        Confidence: {confidence:.2f}")
        print(f"        Reasoning: {reasoning[:80]}...")
        print(f"        Method: {method}")
    
    return all_passed


def test_mixed_components():
    """Test inference with mixed known and generic components."""
    print("\n" + "=" * 60)
    print("Test 6: Mixed Components (Context-Aware)")
    print("=" * 60)
    
    agent = ComponentUnderstandingAgent()
    
    # Mix of known tech and generic labels
    # Django context should influence Database inference
    mixed = ["Django REST API", "Database", "Nginx Load Balancer", "Cache", "Message Queue"]
    results = agent.infer_components(mixed)
    
    all_passed = True
    print("\n  Results:")
    for result in results:
        name = result["component_name"]
        categories = result["inferred_product_categories"]
        confidence = result["confidence"]
        reasoning = result["reasoning"]
        method = result["detection_method"]
        
        # All should have valid results
        passed = len(categories) > 0
        status = "[PASS]" if passed else "[FAIL]"
        if not passed:
            all_passed = False
        
        print(f"  {status} {name}")
        print(f"        Inferred: {categories[:3]}")
        print(f"        Confidence: {confidence:.2f}")
        print(f"        Method: {method}")
        if "generic" in name.lower() or not _looks_like_software_identifier(name):
            print(f"        Reasoning: {reasoning[:100]}...")
    
    return all_passed


def test_edge_cases():
    """Test edge cases and error handling."""
    print("\n" + "=" * 60)
    print("Test 7: Edge Cases")
    print("=" * 60)
    
    agent = ComponentUnderstandingAgent()
    
    edge_cases = [
        "",                    # Empty string
        "Unknown Component",   # Generic unknown
        "System",              # Very generic
        "   ",                 # Whitespace only
        "X",                   # Single character
        "asdfghjkl",          # Random string
    ]
    
    results = agent.infer_components(edge_cases)
    
    all_passed = True
    print("\n  Results:")
    for result in results:
        name = result["component_name"]
        categories = result["inferred_product_categories"]
        confidence = result["confidence"]
        
        # Should handle gracefully without errors
        status = "[PASS]"  # If we got here without exception, it passed
        
        display_name = f"'{name}'" if name.strip() else "(empty)"
        print(f"  {status} {display_name}")
        print(f"        Categories: {categories}")
        print(f"        Confidence: {confidence:.2f}")
    
    return all_passed


def test_large_batch():
    """Test with a larger batch of components."""
    print("\n" + "=" * 60)
    print("Test 8: Large Batch Processing")
    print("=" * 60)
    
    agent = ComponentUnderstandingAgent()
    
    # Simulate a real architecture
    components = [
        "React Frontend",
        "Next.js SSR",
        "API Gateway",
        "Auth Service",
        "User Service",
        "Order Service",
        "PostgreSQL",
        "Redis Cache",
        "RabbitMQ",
        "Elasticsearch",
        "Load Balancer",
        "Nginx Reverse Proxy",
        "S3 Bucket",
        "CloudFront CDN",
        "External Payment API",
    ]
    
    results = agent.infer_components(components)
    
    print(f"\n  Processed {len(results)} components:")
    
    known_count = sum(1 for r in results if r["confidence"] >= 0.9)
    inferred_count = sum(1 for r in results if 0.5 <= r["confidence"] < 0.9)
    generic_count = sum(1 for r in results if r["confidence"] < 0.5)
    
    print(f"    - Known products (>= 0.9 confidence): {known_count}")
    print(f"    - Inferred products (0.5-0.9 confidence): {inferred_count}")
    print(f"    - Generic/Unknown (< 0.5 confidence): {generic_count}")
    
    print("\n  Component Details:")
    for result in results:
        conf_bar = "=" * int(result["confidence"] * 10)
        conf_bar = conf_bar.ljust(10, "-")
        print(f"    [{conf_bar}] {result['component_name'][:25]:<25} -> {result['inferred_product_categories'][0]}")
    
    return True


def test_sets_coverage():
    """Test that GENERIC_LABELS and KNOWN_TECH sets have sufficient coverage."""
    print("\n" + "=" * 60)
    print("Test 9: Sets Coverage")
    print("=" * 60)
    
    print(f"\n  GENERIC_LABELS: {len(GENERIC_LABELS)} terms")
    print(f"  KNOWN_TECH: {len(KNOWN_TECH)} products")
    
    # Require minimum coverage
    min_generic = 50
    min_known = 50
    
    generic_ok = len(GENERIC_LABELS) >= min_generic
    known_ok = len(KNOWN_TECH) >= min_known
    
    status_generic = "[PASS]" if generic_ok else "[FAIL]"
    status_known = "[PASS]" if known_ok else "[FAIL]"
    
    print(f"\n  {status_generic} GENERIC_LABELS >= {min_generic}: {len(GENERIC_LABELS)}")
    print(f"  {status_known} KNOWN_TECH >= {min_known}: {len(KNOWN_TECH)}")
    
    # Show samples
    print("\n  Sample GENERIC_LABELS:")
    for label in list(GENERIC_LABELS)[:5]:
        print(f"    - {label}")
    
    print("\n  Sample KNOWN_TECH:")
    for tech in list(KNOWN_TECH)[:5]:
        print(f"    - {tech}")
    
    return generic_ok and known_ok


def run_all_tests():
    """Run all Component Understanding Agent tests."""
    print("\n" + "=" * 60)
    print("Component Understanding Agent Tests")
    print("=" * 60)
    
    results = {
        "heuristic_detection": test_heuristic_detection(),
        "version_detection": test_version_detection(),
        "category_mapping": test_generic_category_mapping(),
        "known_products": test_known_products_inference(),
        "generic_labels": test_generic_labels_inference(),
        "mixed_components": test_mixed_components(),
        "edge_cases": test_edge_cases(),
        "large_batch": test_large_batch(),
        "sets_coverage": test_sets_coverage(),
    }
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)
    
    for name, result in results.items():
        status = "[PASS]" if result else "[FAIL]"
        print(f"  {status} {name}")
    
    print(f"\nResults: {passed} passed, {failed} failed")
    
    if failed > 0:
        print("\nSome tests failed!")
        return False
    
    print("\nAll tests passed!")
    return True


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    
    success = run_all_tests()
    sys.exit(0 if success else 1)
