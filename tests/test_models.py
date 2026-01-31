"""
Test script for Pydantic models in the Left<<Shift Threat Modeling System.

This script validates that all models can be:
1. Instantiated with sample data
2. Serialized using model_dump()
3. Validated using model_validate()
4. Serialized/deserialized to/from JSON
"""

import json
import sys
sys.path.insert(0, str(__file__).rsplit('\\', 2)[0])

from tools.models import (
    # Architecture Models
    Component,
    DataFlow,
    ArchitectureSchema,
    # Threat Models
    MitigationStrategy,
    ThreatRecord,
    CVE,
    # STRIDE Models
    ArchitecturalThreat,
    ArchitecturalWeakness,
    # Attack Path Models
    AttackPathStep,
    AttackPath,
    # Container Models
    ThreatSearchResults,
    AttackPathList,
)


def test_component():
    """Test Component model."""
    # Create instance
    component = Component(
        name="Primary Database",
        type="Database"
    )
    
    # Test model_dump
    data = component.model_dump()
    assert data["name"] == "Primary Database"
    assert data["type"] == "Database"
    
    # Test model_validate
    validated = Component.model_validate(data)
    assert validated.name == component.name
    
    # Test JSON serialization
    json_str = component.model_dump_json()
    restored = Component.model_validate_json(json_str)
    assert restored.name == component.name
    
    print("[PASS] Component model tests passed")


def test_data_flow():
    """Test DataFlow model."""
    data_flow = DataFlow(
        source="Web Server",
        destination="Primary Database",
        protocol="TCP/5432"
    )
    
    data = data_flow.model_dump()
    assert data["source"] == "Web Server"
    assert data["protocol"] == "TCP/5432"
    
    validated = DataFlow.model_validate(data)
    assert validated.destination == data_flow.destination
    
    json_str = data_flow.model_dump_json()
    restored = DataFlow.model_validate_json(json_str)
    assert restored.protocol == data_flow.protocol
    
    print("[PASS] DataFlow model tests passed")


def test_architecture_schema():
    """Test ArchitectureSchema model."""
    schema = ArchitectureSchema(
        project_name="E-Commerce Platform",
        description="A multi-tier web application with user authentication and payment processing",
        components=[
            Component(name="Web Server", type="Web Server"),
            Component(name="API Gateway", type="API Gateway"),
            Component(name="User Database", type="Database"),
        ],
        data_flows=[
            DataFlow(source="Web Server", destination="API Gateway", protocol="HTTPS"),
            DataFlow(source="API Gateway", destination="User Database", protocol="TCP/5432"),
        ],
        trust_boundaries=["Internet", "DMZ", "Internal Network", "Database Zone"]
    )
    
    data = schema.model_dump()
    assert data["project_name"] == "E-Commerce Platform"
    assert len(data["components"]) == 3
    assert len(data["data_flows"]) == 2
    
    validated = ArchitectureSchema.model_validate(data)
    assert len(validated.trust_boundaries) == 4
    
    json_str = schema.model_dump_json()
    restored = ArchitectureSchema.model_validate_json(json_str)
    assert restored.project_name == schema.project_name
    
    print("[PASS] ArchitectureSchema model tests passed")


def test_mitigation_strategy():
    """Test MitigationStrategy model."""
    mitigation = MitigationStrategy(
        primary_fix="Update to version 2.5.0 or later",
        configuration_changes=["Disable remote debugging", "Enable strict mode"],
        access_control_changes=["Restrict admin access to VPN only"],
        monitoring_actions=["Enable audit logging", "Set up alerting for failed auth attempts"],
        nist_controls=["SI-2", "AC-3", "CM-6"],
        additional_notes=["Review all API endpoints for similar issues"]
    )
    
    data = mitigation.model_dump()
    assert data["primary_fix"] == "Update to version 2.5.0 or later"
    assert "SI-2" in data["nist_controls"]
    
    validated = MitigationStrategy.model_validate(data)
    assert len(validated.configuration_changes) == 2
    
    json_str = mitigation.model_dump_json()
    restored = MitigationStrategy.model_validate_json(json_str)
    assert restored.primary_fix == mitigation.primary_fix
    
    print("[PASS] MitigationStrategy model tests passed")


def test_threat_record():
    """Test ThreatRecord model and CVE alias."""
    mitigation = MitigationStrategy(
        primary_fix="Apply security patch",
        nist_controls=["SI-2"]
    )
    
    threat = ThreatRecord(
        cve_id="CVE-2024-12345",
        summary="SQL injection vulnerability in login form",
        severity="HIGH",
        affected_products="MyApp Web Server v1.0 - v1.5",
        is_actively_exploited=True,
        source="NVD",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=9.1,
        cwe_id="CWE-89",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"],
        mitigation=mitigation,
        relevance_status="Relevant",
        prerequisites="Network access to login endpoint",
        exploitability="Easy",
        likelihood="High",
        justification="Direct match with deployed web server version"
    )
    
    data = threat.model_dump()
    assert data["cve_id"] == "CVE-2024-12345"
    assert data["is_actively_exploited"] is True
    assert data["cvss_score"] == 9.1
    
    validated = ThreatRecord.model_validate(data)
    assert validated.severity == "HIGH"
    
    # Test CVE alias
    cve = CVE(
        cve_id="CVE-2024-99999",
        summary="Test vulnerability",
        severity="MEDIUM",
        affected_products="Test Product",
        source="CISA KEV"
    )
    assert isinstance(cve, ThreatRecord)
    
    json_str = threat.model_dump_json()
    restored = ThreatRecord.model_validate_json(json_str)
    assert restored.cve_id == threat.cve_id
    
    print("[PASS] ThreatRecord (CVE) model tests passed")


def test_architectural_threat():
    """Test ArchitecturalThreat model."""
    threat = ArchitecturalThreat(
        threat_id="T-001",
        category="Spoofing",
        description="Attacker impersonates legitimate user through stolen session token",
        affected_component="Authentication Service",
        affected_asset="Session Management",
        trust_boundary="Internet",
        severity="High",
        mitigation_steps=[
            "Implement secure session token generation",
            "Add session binding to client IP",
            "Implement token rotation"
        ],
        preconditions=["Attacker has network access", "Session tokens are predictable"],
        impact="Unauthorized access to user accounts",
        example="Attacker intercepts session cookie and replays it from different IP",
        cwe_id="CWE-287",
        related_cve_id="CVE-2024-12345"
    )
    
    data = threat.model_dump()
    assert data["threat_id"] == "T-001"
    assert data["category"] == "Spoofing"
    
    validated = ArchitecturalThreat.model_validate(data)
    assert len(validated.mitigation_steps) == 3
    
    json_str = threat.model_dump_json()
    restored = ArchitecturalThreat.model_validate_json(json_str)
    assert restored.threat_id == threat.threat_id
    
    print("[PASS] ArchitecturalThreat model tests passed")


def test_architectural_weakness():
    """Test ArchitecturalWeakness model."""
    weakness = ArchitecturalWeakness(
        weakness_id="W-001",
        title="Missing Input Validation",
        description="User input is not validated before being processed by the database layer",
        impact="SQL injection attacks could compromise database integrity and confidentiality",
        mitigation="Implement parameterized queries and input validation at all entry points"
    )
    
    data = weakness.model_dump()
    assert data["weakness_id"] == "W-001"
    assert "Input Validation" in data["title"]
    
    validated = ArchitecturalWeakness.model_validate(data)
    assert validated.weakness_id == weakness.weakness_id
    
    json_str = weakness.model_dump_json()
    restored = ArchitecturalWeakness.model_validate_json(json_str)
    assert restored.title == weakness.title
    
    print("[PASS] ArchitecturalWeakness model tests passed")


def test_attack_path_step():
    """Test AttackPathStep model."""
    step = AttackPathStep(
        step_number=1,
        action="Perform reconnaissance on target web application",
        target_component="Web Server",
        technique="T1595 - Active Scanning",
        outcome="Identify vulnerable login endpoint"
    )
    
    data = step.model_dump()
    assert data["step_number"] == 1
    assert "T1595" in data["technique"]
    
    validated = AttackPathStep.model_validate(data)
    assert validated.target_component == "Web Server"
    
    json_str = step.model_dump_json()
    restored = AttackPathStep.model_validate_json(json_str)
    assert restored.step_number == step.step_number
    
    print("[PASS] AttackPathStep model tests passed")


def test_attack_path():
    """Test AttackPath model."""
    attack_path = AttackPath(
        path_id="AP-01",
        name="SQL Injection to Database Compromise",
        description="Attacker exploits SQL injection in login form to gain database access",
        impact="Full database compromise including user credentials and sensitive data",
        likelihood="High",
        steps=[
            AttackPathStep(
                step_number=1,
                action="Identify vulnerable input field",
                target_component="Web Server",
                technique="T1190 - Exploit Public-Facing Application",
                outcome="Discover SQL injection vulnerability"
            ),
            AttackPathStep(
                step_number=2,
                action="Extract database schema",
                target_component="Database",
                technique="T1005 - Data from Local System",
                outcome="Map database structure"
            ),
            AttackPathStep(
                step_number=3,
                action="Exfiltrate sensitive data",
                target_component="Database",
                technique="T1041 - Exfiltration Over C2 Channel",
                outcome="Obtain user credentials and PII"
            ),
        ],
        referenced_threats=["T-001", "T-002"],
        referenced_cves=["CVE-2024-12345"]
    )
    
    data = attack_path.model_dump()
    assert data["path_id"] == "AP-01"
    assert len(data["steps"]) == 3
    
    validated = AttackPath.model_validate(data)
    assert validated.likelihood == "High"
    
    json_str = attack_path.model_dump_json()
    restored = AttackPath.model_validate_json(json_str)
    assert restored.path_id == attack_path.path_id
    assert len(restored.steps) == 3
    
    print("[PASS] AttackPath model tests passed")


def test_threat_search_results():
    """Test ThreatSearchResults container model."""
    results = ThreatSearchResults(
        threats=[
            ThreatRecord(
                cve_id="CVE-2024-11111",
                summary="First vulnerability",
                severity="HIGH",
                affected_products="Product A",
                source="NVD"
            ),
            ThreatRecord(
                cve_id="CVE-2024-22222",
                summary="Second vulnerability",
                severity="MEDIUM",
                affected_products="Product B",
                source="CISA KEV"
            ),
        ]
    )
    
    data = results.model_dump()
    assert len(data["threats"]) == 2
    
    validated = ThreatSearchResults.model_validate(data)
    assert validated.threats[0].cve_id == "CVE-2024-11111"
    
    json_str = results.model_dump_json()
    restored = ThreatSearchResults.model_validate_json(json_str)
    assert len(restored.threats) == 2
    
    print("[PASS] ThreatSearchResults model tests passed")


def test_attack_path_list():
    """Test AttackPathList container model."""
    path_list = AttackPathList(
        paths=[
            AttackPath(
                path_id="AP-01",
                name="Attack Path 1",
                description="First attack scenario",
                impact="High impact",
                likelihood="Medium",
                steps=[],
                referenced_threats=[],
                referenced_cves=[]
            ),
            AttackPath(
                path_id="AP-02",
                name="Attack Path 2",
                description="Second attack scenario",
                impact="Medium impact",
                likelihood="Low",
                steps=[],
                referenced_threats=[],
                referenced_cves=[]
            ),
        ]
    )
    
    data = path_list.model_dump()
    assert len(data["paths"]) == 2
    
    validated = AttackPathList.model_validate(data)
    assert validated.paths[0].path_id == "AP-01"
    
    json_str = path_list.model_dump_json()
    restored = AttackPathList.model_validate_json(json_str)
    assert len(restored.paths) == 2
    
    print("[PASS] AttackPathList model tests passed")


def run_all_tests():
    """Run all model tests."""
    print("\n" + "=" * 60)
    print("Running Pydantic Model Tests for Left<<Shift")
    print("=" * 60 + "\n")
    
    try:
        # Architecture Models
        test_component()
        test_data_flow()
        test_architecture_schema()
        
        # Threat Models
        test_mitigation_strategy()
        test_threat_record()
        
        # STRIDE Models
        test_architectural_threat()
        test_architectural_weakness()
        
        # Attack Path Models
        test_attack_path_step()
        test_attack_path()
        
        # Container Models
        test_threat_search_results()
        test_attack_path_list()
        
        print("\n" + "=" * 60)
        print("All tests passed successfully!")
        print("=" * 60 + "\n")
        
    except AssertionError as e:
        print(f"\n[FAIL] Test failed: {e}")
        raise
    except Exception as e:
        print(f"\n[FAIL] Unexpected error: {e}")
        raise


if __name__ == "__main__":
    run_all_tests()
