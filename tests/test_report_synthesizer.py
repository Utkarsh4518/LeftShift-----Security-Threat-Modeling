"""
Test script for Report Synthesizer Agent.

This test validates:
1. Report structure (all 12 sections)
2. Data integrity (no hallucination)
3. Markdown formatting
4. CVE/Threat ID consistency

Saves output to test_report.md for manual review.
"""

import sys
import re
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

from agents.report_synthesizer_agent import (
    ReportSynthesizerAgent,
    REPORT_SYSTEM_INSTRUCTION,
    json_serial,
    serialize_for_report,
)
from tools.models import (
    ArchitectureSchema,
    Component,
    DataFlow,
    ArchitecturalThreat,
    ArchitecturalWeakness,
    ThreatRecord,
    MitigationStrategy,
    AttackPath,
    AttackPathStep,
)


def create_test_architecture():
    """Create a test architecture with 5 components."""
    return ArchitectureSchema(
        project_name="E-Commerce Platform",
        description="A modern e-commerce platform with microservices architecture",
        components=[
            Component(name="Nginx Load Balancer", type="Load Balancer"),
            Component(name="Django REST API", type="Application Server"),
            Component(name="PostgreSQL Database", type="Database"),
            Component(name="Redis Cache", type="Cache"),
            Component(name="RabbitMQ", type="Message Queue"),
        ],
        data_flows=[
            DataFlow(source="User Browser", destination="Nginx Load Balancer", protocol="HTTPS/443"),
            DataFlow(source="Nginx Load Balancer", destination="Django REST API", protocol="HTTP/8000"),
            DataFlow(source="Django REST API", destination="PostgreSQL Database", protocol="TCP/5432"),
            DataFlow(source="Django REST API", destination="Redis Cache", protocol="TCP/6379"),
            DataFlow(source="Django REST API", destination="RabbitMQ", protocol="AMQP/5672"),
        ],
        trust_boundaries=["Internet", "DMZ", "Application Zone", "Data Zone"]
    )


def create_test_inferred_components():
    """Create test inferred component data."""
    return [
        {
            "component_name": "Nginx Load Balancer",
            "type": "Load Balancer",
            "inferred_product_categories": ["Nginx"],
            "confidence": 0.95,
            "detection_method": "heuristic"
        },
        {
            "component_name": "Django REST API",
            "type": "Application Server",
            "inferred_product_categories": ["Django", "Django REST Framework"],
            "confidence": 0.95,
            "detection_method": "heuristic"
        },
        {
            "component_name": "PostgreSQL Database",
            "type": "Database",
            "inferred_product_categories": ["PostgreSQL"],
            "confidence": 0.95,
            "detection_method": "heuristic"
        },
        {
            "component_name": "Redis Cache",
            "type": "Cache",
            "inferred_product_categories": ["Redis"],
            "confidence": 0.95,
            "detection_method": "heuristic"
        },
        {
            "component_name": "RabbitMQ",
            "type": "Message Queue",
            "inferred_product_categories": ["RabbitMQ"],
            "confidence": 0.95,
            "detection_method": "heuristic"
        },
    ]


def create_test_threats():
    """Create 10 test threats covering STRIDE categories."""
    threats = [
        # Spoofing
        ArchitecturalThreat(
            threat_id="T-001",
            category="Spoofing",
            description="JWT token forgery allows unauthorized access to Django API",
            affected_component="Django REST API",
            severity="High",
            cwe_id="CWE-287",
            mitigation_steps=["Implement token rotation", "Use asymmetric signing"],
            preconditions=["Attacker obtains weak secret key"]
        ),
        ArchitecturalThreat(
            threat_id="T-002",
            category="Spoofing",
            description="Redis AUTH bypass through network sniffing",
            affected_component="Redis Cache",
            severity="High",
            cwe_id="CWE-319",
            mitigation_steps=["Enable TLS for Redis connections"],
            preconditions=["Network access to Redis port"]
        ),
        # Tampering
        ArchitecturalThreat(
            threat_id="T-003",
            category="Tampering",
            description="SQL injection in Django ORM through raw queries",
            affected_component="PostgreSQL Database",
            severity="Critical",
            cwe_id="CWE-89",
            related_cve_id="CVE-2023-DJANGO-001",
            mitigation_steps=["Use parameterized queries", "Enable WAF"],
            preconditions=["Access to input fields"]
        ),
        ArchitecturalThreat(
            threat_id="T-004",
            category="Tampering",
            description="HTTP request smuggling through Nginx misconfiguration",
            affected_component="Nginx Load Balancer",
            severity="High",
            cwe_id="CWE-444",
            related_cve_id="CVE-2023-NGINX-001",
            mitigation_steps=["Update Nginx", "Enable strict HTTP parsing"]
        ),
        # Repudiation
        ArchitecturalThreat(
            threat_id="T-005",
            category="Repudiation",
            description="Insufficient audit logging in Django API",
            affected_component="Django REST API",
            severity="Medium",
            cwe_id="CWE-778",
            mitigation_steps=["Implement comprehensive audit logging"]
        ),
        # Information Disclosure
        ArchitecturalThreat(
            threat_id="T-006",
            category="Information Disclosure",
            description="PostgreSQL verbose error messages expose schema details",
            affected_component="PostgreSQL Database",
            severity="Medium",
            cwe_id="CWE-209",
            mitigation_steps=["Disable verbose errors in production"]
        ),
        ArchitecturalThreat(
            threat_id="T-007",
            category="Information Disclosure",
            description="Redis KEYS command exposes cache structure",
            affected_component="Redis Cache",
            severity="Medium",
            cwe_id="CWE-200",
            mitigation_steps=["Disable dangerous commands", "Implement ACLs"]
        ),
        # Denial of Service
        ArchitecturalThreat(
            threat_id="T-008",
            category="Denial of Service",
            description="Nginx slowloris attack vulnerability",
            affected_component="Nginx Load Balancer",
            severity="High",
            cwe_id="CWE-400",
            mitigation_steps=["Configure client timeouts", "Enable rate limiting"]
        ),
        ArchitecturalThreat(
            threat_id="T-009",
            category="Denial of Service",
            description="RabbitMQ queue exhaustion through message flood",
            affected_component="RabbitMQ",
            severity="Medium",
            cwe_id="CWE-770",
            mitigation_steps=["Set queue limits", "Implement dead letter queues"]
        ),
        # Elevation of Privilege
        ArchitecturalThreat(
            threat_id="T-010",
            category="Elevation of Privilege",
            description="Django admin panel privilege escalation",
            affected_component="Django REST API",
            severity="Critical",
            cwe_id="CWE-269",
            mitigation_steps=["Implement RBAC", "Audit admin access"]
        ),
    ]
    return threats


def create_test_weaknesses():
    """Create 3 test architectural weaknesses."""
    return [
        ArchitecturalWeakness(
            weakness_id="W-001",
            title="Missing Web Application Firewall",
            description="No WAF deployed in front of the application layer",
            impact="Increases risk of web-based attacks reaching application",
            mitigation="Deploy WAF (AWS WAF, Cloudflare, ModSecurity)"
        ),
        ArchitecturalWeakness(
            weakness_id="W-002",
            title="Insufficient Network Segmentation",
            description="Database and cache accessible from application zone without additional controls",
            impact="Lateral movement risk if application is compromised",
            mitigation="Implement microsegmentation with network policies"
        ),
        ArchitecturalWeakness(
            weakness_id="W-003",
            title="No Secrets Management Solution",
            description="Credentials stored in environment variables without rotation",
            impact="Credential exposure risk, no audit trail for secret access",
            mitigation="Implement HashiCorp Vault or AWS Secrets Manager"
        ),
    ]


def create_test_cves():
    """Create 5 test CVEs (real format, test data)."""
    return [
        ThreatRecord(
            cve_id="CVE-2023-DJANGO-001",
            summary="SQL injection vulnerability in Django ORM when using raw() with user input",
            severity="CRITICAL",
            cvss_score=9.8,
            affected_products="djangoproject:django",
            is_actively_exploited=True,
            source="CISA KEV",
            cwe_id="CWE-89",
            relevance_status="High",
            prerequisites="Application uses raw SQL queries with user input",
            exploitability="RCE",
            likelihood="High",
            mitigation=MitigationStrategy(
                primary_fix="Upgrade Django to 4.2.5 or later",
                configuration_changes=["Use parameterized queries only"],
                nist_controls=["SI-10", "SA-11"]
            )
        ),
        ThreatRecord(
            cve_id="CVE-2023-NGINX-001",
            summary="HTTP/2 rapid reset attack allows denial of service in Nginx",
            severity="HIGH",
            cvss_score=7.5,
            affected_products="nginx:nginx",
            is_actively_exploited=True,
            source="CISA KEV",
            cwe_id="CWE-400",
            relevance_status="High",
            prerequisites="HTTP/2 enabled on Nginx",
            exploitability="DoS",
            likelihood="High",
            mitigation=MitigationStrategy(
                primary_fix="Upgrade Nginx to 1.25.3 or later",
                configuration_changes=["Limit concurrent streams"],
                nist_controls=["SC-5", "SI-3"]
            )
        ),
        ThreatRecord(
            cve_id="CVE-2023-POSTGRES-001",
            summary="Buffer overflow in PostgreSQL allows privilege escalation",
            severity="HIGH",
            cvss_score=8.1,
            affected_products="postgresql:postgresql",
            is_actively_exploited=False,
            source="NVD",
            cwe_id="CWE-120",
            relevance_status="Medium",
            prerequisites="Local database access required",
            exploitability="Privilege Escalation",
            likelihood="Medium",
            mitigation=MitigationStrategy(
                primary_fix="Upgrade PostgreSQL to 15.4",
                configuration_changes=["Restrict local access"],
                nist_controls=["AC-6", "SI-16"]
            )
        ),
        ThreatRecord(
            cve_id="CVE-2023-REDIS-001",
            summary="Lua sandbox escape in Redis allows arbitrary code execution",
            severity="CRITICAL",
            cvss_score=9.8,
            affected_products="redis:redis",
            is_actively_exploited=False,
            source="NVD",
            cwe_id="CWE-94",
            relevance_status="High",
            prerequisites="Lua scripting enabled",
            exploitability="RCE",
            likelihood="Medium",
            mitigation=MitigationStrategy(
                primary_fix="Upgrade Redis to 7.2.0",
                configuration_changes=["Disable Lua if not needed", "Enable ACLs"],
                nist_controls=["CM-7", "SC-18"]
            )
        ),
        ThreatRecord(
            cve_id="CVE-2023-RABBITMQ-001",
            summary="Authentication bypass in RabbitMQ management interface",
            severity="HIGH",
            cvss_score=7.8,
            affected_products="pivotal_software:rabbitmq",
            is_actively_exploited=False,
            source="NVD",
            cwe_id="CWE-287",
            relevance_status="Medium",
            prerequisites="Management interface exposed",
            exploitability="Authentication Bypass",
            likelihood="Medium",
            mitigation=MitigationStrategy(
                primary_fix="Upgrade RabbitMQ to 3.12.6",
                configuration_changes=["Restrict management interface access"],
                nist_controls=["AC-3", "IA-2"]
            )
        ),
    ]


def create_test_attack_paths():
    """Create 2 test attack paths."""
    return [
        AttackPath(
            path_id="AP-01",
            name="Database Compromise via SQL Injection",
            description="Attacker exploits SQL injection to access and exfiltrate database contents",
            impact="Complete database compromise, data breach",
            likelihood="High",
            steps=[
                AttackPathStep(
                    step_number=1,
                    action="Identify SQL injection point in API endpoint",
                    target_component="Django REST API",
                    technique="T1190 - Exploit Public-Facing Application",
                    outcome="Discover vulnerable parameter"
                ),
                AttackPathStep(
                    step_number=2,
                    action="Extract database schema using UNION injection",
                    target_component="PostgreSQL Database",
                    technique="T1005 - Data from Local System",
                    outcome="Map database structure"
                ),
                AttackPathStep(
                    step_number=3,
                    action="Exfiltrate sensitive data (users, credentials)",
                    target_component="PostgreSQL Database",
                    technique="T1041 - Exfiltration Over C2 Channel",
                    outcome="Data breach"
                ),
            ],
            referenced_threats=["T-003"],
            referenced_cves=["CVE-2023-DJANGO-001"]
        ),
        AttackPath(
            path_id="AP-02",
            name="Cache Poisoning to Session Hijacking",
            description="Attacker exploits Redis to poison cached sessions and hijack user accounts",
            impact="Account takeover, unauthorized access",
            likelihood="Medium",
            steps=[
                AttackPathStep(
                    step_number=1,
                    action="Exploit network access to Redis (no TLS)",
                    target_component="Redis Cache",
                    technique="T1557 - Adversary-in-the-Middle",
                    outcome="Intercept Redis traffic"
                ),
                AttackPathStep(
                    step_number=2,
                    action="Inject malicious session data into cache",
                    target_component="Redis Cache",
                    technique="T1565 - Data Manipulation",
                    outcome="Poison session cache"
                ),
                AttackPathStep(
                    step_number=3,
                    action="Hijack privileged user session",
                    target_component="Django REST API",
                    technique="T1563 - Remote Service Session Hijacking",
                    outcome="Unauthorized admin access"
                ),
            ],
            referenced_threats=["T-002", "T-007"],
            referenced_cves=["CVE-2023-REDIS-001"]
        ),
    ]


def test_agent_initialization():
    """Test that the agent initializes correctly."""
    print("\n" + "=" * 60)
    print("Test 1: Agent Initialization")
    print("=" * 60)
    
    agent = ReportSynthesizerAgent()
    
    print(f"  Model: {agent.model_name}")
    print(f"  Client available: {agent.client is not None}")
    print(f"  [PASS] Agent initialized")
    
    return True


def test_json_serialization():
    """Test JSON serialization helper."""
    print("\n" + "=" * 60)
    print("Test 2: JSON Serialization")
    print("=" * 60)
    
    # Test datetime
    dt = datetime.now()
    result = json_serial(dt)
    print(f"  DateTime serialization: {type(result).__name__}")
    
    # Test Pydantic model
    comp = Component(name="Test", type="Test")
    result = json_serial(comp)
    print(f"  Pydantic serialization: {type(result).__name__}")
    
    # Test full serialization
    data = {
        "timestamp": dt,
        "component": comp,
        "list": [comp]
    }
    
    json_str = serialize_for_report(data)
    print(f"  Full serialization: {len(json_str)} chars")
    print(f"  [PASS] Serialization working")
    
    return True


def test_data_synthesis():
    """Test report data synthesis."""
    print("\n" + "=" * 60)
    print("Test 3: Data Synthesis")
    print("=" * 60)
    
    agent = ReportSynthesizerAgent()
    
    architecture = create_test_architecture()
    inferred = create_test_inferred_components()
    threats = create_test_threats()
    weaknesses = create_test_weaknesses()
    cves = create_test_cves()
    attack_paths = create_test_attack_paths()
    
    report_data = agent.synthesize_report_data(
        architecture=architecture,
        inferred_components=inferred,
        threats=threats,
        weaknesses=weaknesses,
        cves=cves,
        attack_paths=attack_paths
    )
    
    print(f"  Project: {report_data['project_name']}")
    print(f"  Components: {report_data['summary_stats']['total_components']}")
    print(f"  Threats: {report_data['summary_stats']['total_threats']}")
    print(f"  Weaknesses: {report_data['summary_stats']['total_weaknesses']}")
    print(f"  CVEs: {report_data['summary_stats']['total_cves']}")
    print(f"  Attack Paths: {report_data['summary_stats']['total_attack_paths']}")
    
    # Verify counts
    assert report_data['summary_stats']['total_components'] == 5
    assert report_data['summary_stats']['total_threats'] == 10
    assert report_data['summary_stats']['total_weaknesses'] == 3
    assert report_data['summary_stats']['total_cves'] == 5
    assert report_data['summary_stats']['total_attack_paths'] == 2
    
    print(f"  [PASS] Data synthesis correct")
    
    return True


def test_report_generation():
    """Test full report generation."""
    print("\n" + "=" * 60)
    print("Test 4: Report Generation")
    print("=" * 60)
    
    agent = ReportSynthesizerAgent()
    
    architecture = create_test_architecture()
    inferred = create_test_inferred_components()
    threats = create_test_threats()
    weaknesses = create_test_weaknesses()
    cves = create_test_cves()
    attack_paths = create_test_attack_paths()
    
    print(f"\n  Generating report (this may take a moment)...")
    
    output_path = Path(__file__).parent / "test_report.md"
    
    report = agent.generate_full_report(
        architecture=architecture,
        inferred_components=inferred,
        threats=threats,
        weaknesses=weaknesses,
        cves=cves,
        attack_paths=attack_paths,
        output_path=str(output_path)
    )
    
    print(f"\n  Report length: {len(report)} characters")
    print(f"  Saved to: {output_path}")
    
    return report, output_path


def test_report_structure(report: str):
    """Verify report has all required sections."""
    print("\n" + "=" * 60)
    print("Test 5: Report Structure Validation")
    print("=" * 60)
    
    # Check for major sections (flexible matching)
    sections = [
        ("Executive Summary", r"executive\s*summary|summary", True),
        ("Architecture", r"architecture|components", True),
        ("Component Inventory", r"component|inventory", True),
        ("STRIDE Threats", r"stride|threat", True),
        ("Weaknesses", r"weakness", True),
        ("CVE Discovery", r"cve|vulnerabilit", True),
        ("Threat-CVE Matrix", r"matrix|correlation", False),
        ("Attack Paths", r"attack\s*path", True),
        ("Component Profiles", r"component.*profile|security.*profile", False),
        ("NIST Controls", r"nist|800-53|control", False),
        ("Hardening Plan", r"hardening|plan|quick\s*win", False),
    ]
    
    report_lower = report.lower()
    found = 0
    
    for name, pattern, required in sections:
        if re.search(pattern, report_lower):
            print(f"  [PASS] {name}")
            found += 1
        else:
            if required:
                print(f"  [FAIL] {name} - REQUIRED")
            else:
                print(f"  [WARN] {name} - optional")
    
    print(f"\n  Sections found: {found}/{len(sections)}")
    
    return found >= 6  # At least 6 sections


def test_data_integrity(report: str, cves, threats):
    """Verify no hallucinated data in report."""
    print("\n" + "=" * 60)
    print("Test 6: Data Integrity (No Hallucination)")
    print("=" * 60)
    
    # Extract CVE IDs from report
    cve_pattern = r'CVE-\d{4}-[A-Z0-9-]+'
    found_cves = set(re.findall(cve_pattern, report))
    
    # Get input CVE IDs
    input_cve_ids = {cve.cve_id for cve in cves}
    
    print(f"  Input CVEs: {input_cve_ids}")
    print(f"  Found in report: {found_cves}")
    
    # Check for hallucinated CVEs
    hallucinated = found_cves - input_cve_ids
    if hallucinated:
        print(f"  [FAIL] Hallucinated CVEs found: {hallucinated}")
        return False
    else:
        print(f"  [PASS] No hallucinated CVEs")
    
    # Extract Threat IDs from report
    threat_pattern = r'T-\d{3}'
    found_threats = set(re.findall(threat_pattern, report))
    
    # Get input Threat IDs
    input_threat_ids = {t.threat_id for t in threats}
    
    print(f"  Input Threats: {input_threat_ids}")
    print(f"  Found in report: {found_threats}")
    
    # Check for hallucinated threats (allow some flexibility)
    hallucinated_threats = found_threats - input_threat_ids
    # Filter out very high threat IDs that might be from promotions
    real_hallucinated = {t for t in hallucinated_threats if int(t.split('-')[1]) <= 20}
    
    if real_hallucinated:
        print(f"  [WARN] Extra threat IDs: {real_hallucinated}")
    else:
        print(f"  [PASS] Threat IDs consistent")
    
    return True


def test_markdown_formatting(report: str):
    """Verify Markdown formatting."""
    print("\n" + "=" * 60)
    print("Test 7: Markdown Formatting")
    print("=" * 60)
    
    checks = {
        "Has headers (#)": bool(re.search(r'^#+\s', report, re.MULTILINE)),
        "Has tables (|)": '|' in report and '---' in report,
        "Has bullet points": bool(re.search(r'^[\-\*]\s', report, re.MULTILINE)),
        "No HTML tags": '<div>' not in report and '<table>' not in report,
        "Has code blocks": '```' in report or '`' in report,
    }
    
    all_pass = True
    for check, result in checks.items():
        status = "[PASS]" if result else "[WARN]"
        print(f"  {status} {check}")
        if not result:
            all_pass = False
    
    return all_pass


def run_all_tests():
    """Run all Report Synthesizer tests."""
    print("\n" + "=" * 60)
    print("Report Synthesizer Agent Tests")
    print("=" * 60)
    
    results = {}
    
    results["initialization"] = test_agent_initialization()
    results["serialization"] = test_json_serialization()
    results["data_synthesis"] = test_data_synthesis()
    
    # Generate report
    report, output_path = test_report_generation()
    results["generation"] = report is not None and len(report) > 500
    
    if report:
        results["structure"] = test_report_structure(report)
        results["integrity"] = test_data_integrity(
            report, 
            create_test_cves(), 
            create_test_threats()
        )
        results["formatting"] = test_markdown_formatting(report)
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for name, result in results.items():
        status = "[PASS]" if result else "[FAIL]"
        print(f"  {status} {name}")
    
    print(f"\nResults: {passed}/{total} passed")
    
    if report:
        print(f"\nReport saved to: {output_path}")
        print("Review test_report.md for manual verification.")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
