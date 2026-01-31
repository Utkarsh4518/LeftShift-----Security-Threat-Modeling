"""
Core Pipeline Orchestration for Left<<Shift Threat Modeling System.

This module provides the main orchestration function that coordinates
all agents in the multi-agent threat modeling pipeline.

Pipeline Stages:
1. Architecture Extraction (Vision Agent / JSON Load)
2. Component Understanding (Component Understanding Agent)
3. Threat Knowledge (Threat Knowledge Agent - STRIDE)
4. CVE Discovery (CVE Discovery Agent - NVD/CISA KEV)
5. Threat Relevance (Threat Relevance Agent)
6. Attack Path Simulation (Attack Path Generation)
7. Report Synthesis (Report Synthesizer Agent)
"""

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import models
from tools.models import (
    ArchitectureSchema,
    Component,
    DataFlow,
    ArchitecturalThreat,
    ArchitecturalWeakness,
    ThreatRecord,
    AttackPath,
    AttackPathStep,
)

# Import agents
from tools.diagram_processor import process_architecture_diagram
from agents.component_understanding_agent import ComponentUnderstandingAgent
from agents.threat_knowledge_agent import ThreatKnowledgeAgent
from agents.cve_discovery_agent import CVEDiscoveryAgent
from agents.threat_relevance_agent import ThreatRelevanceAgent
from agents.report_synthesizer_agent import ReportSynthesizerAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger(__name__)

# =============================================================================
# Progress Display Utilities
# =============================================================================

class PipelineTimer:
    """Track timing for pipeline stages."""
    
    def __init__(self):
        self.start_time = None
        self.stage_times: Dict[str, float] = {}
        self.current_stage = None
        self.stage_start = None
    
    def start(self):
        """Start the overall pipeline timer."""
        self.start_time = time.time()
    
    def start_stage(self, stage_name: str):
        """Start timing a stage."""
        self.current_stage = stage_name
        self.stage_start = time.time()
    
    def end_stage(self) -> float:
        """End timing current stage and return duration."""
        if self.stage_start and self.current_stage:
            duration = time.time() - self.stage_start
            self.stage_times[self.current_stage] = duration
            return duration
        return 0.0
    
    def total_time(self) -> float:
        """Get total elapsed time."""
        if self.start_time:
            return time.time() - self.start_time
        return 0.0
    
    def get_summary(self) -> str:
        """Get timing summary."""
        lines = ["\n" + "=" * 60]
        lines.append("  PIPELINE TIMING SUMMARY")
        lines.append("=" * 60)
        
        for stage, duration in self.stage_times.items():
            lines.append(f"  {stage}: {duration:.2f}s")
        
        lines.append("-" * 60)
        lines.append(f"  TOTAL TIME: {self.total_time():.2f}s")
        lines.append("=" * 60)
        
        return "\n".join(lines)


def print_header(title: str):
    """Print a formatted header."""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def print_stage(stage_num: int, stage_name: str):
    """Print stage start."""
    print(f"\n[Stage {stage_num}] {stage_name}")
    print("-" * 50)


def print_result(label: str, value: Any, indent: int = 2):
    """Print a result line."""
    spaces = " " * indent
    print(f"{spaces}-> {label}: {value}")


def print_complete(duration: float):
    """Print stage completion."""
    print(f"  [OK] Complete ({duration:.2f}s)")


# =============================================================================
# Attack Path Generation
# =============================================================================

def generate_attack_paths(
    threats: List[ArchitecturalThreat],
    cves: List[ThreatRecord],
    architecture: ArchitectureSchema
) -> List[AttackPath]:
    """
    Generate realistic attack path simulations following data flows.
    
    Creates attack paths that:
    1. Follow actual data flow paths in the architecture
    2. Chain multiple components realistically
    3. Use MITRE ATT&CK techniques appropriately
    4. Reference actual threats and CVEs from analysis
    """
    attack_paths = []
    
    # Build data flow graph
    flow_graph: Dict[str, List[str]] = {}  # source -> [destinations]
    reverse_flow: Dict[str, List[str]] = {}  # dest -> [sources]
    
    for flow in architecture.data_flows:
        if flow.source not in flow_graph:
            flow_graph[flow.source] = []
        flow_graph[flow.source].append(flow.destination)
        
        if flow.destination not in reverse_flow:
            reverse_flow[flow.destination] = []
        reverse_flow[flow.destination].append(flow.source)
    
    # Identify component types
    entry_points = []  # Components reachable from external
    databases = []
    auth_components = []
    
    for comp in architecture.components:
        name_lower = comp.name.lower()
        type_lower = comp.type.lower()
        
        # Entry points: browsers, mobile, public routes, load balancers
        if any(x in name_lower or x in type_lower for x in ['browser', 'mobile', 'client', 'public', 'ingress', 'load balancer', 'cdn', 'frontend', 'web']):
            entry_points.append(comp.name)
        
        # Databases
        if any(x in name_lower or x in type_lower for x in ['database', 'db', 'mysql', 'postgres', 'mongo', 'redis', 'elasticsearch', 'mariadb', 'couchdb']):
            databases.append(comp.name)
        
        # Auth
        if any(x in name_lower or x in type_lower for x in ['auth', 'identity', 'sso', 'oauth', 'login']):
            auth_components.append(comp.name)
    
    # Group threats and CVEs by component
    component_threats: Dict[str, List[ArchitecturalThreat]] = {}
    for threat in threats:
        comp = threat.affected_component
        if comp not in component_threats:
            component_threats[comp] = []
        component_threats[comp].append(threat)
    
    component_cves: Dict[str, List[ThreatRecord]] = {}
    for cve in cves:
        # Match CVE to component by product name
        for comp in architecture.components:
            if any(x.lower() in comp.name.lower() for x in cve.affected_products.split()):
                if comp.name not in component_cves:
                    component_cves[comp.name] = []
                component_cves[comp.name].append(cve)
    
    path_id = 1
    
    # ==========================================================================
    # PATH 1: External Attacker -> Web/API -> Backend -> Database (Data Breach)
    # ==========================================================================
    if entry_points and databases:
        steps = []
        step_num = 1
        referenced_threats = []
        referenced_cves = []
        
        # Find path from entry to database
        entry = entry_points[0]
        target_db = databases[0]
        
        # Step 1: Reconnaissance
        steps.append(AttackPathStep(
            step_number=step_num,
            action="Perform reconnaissance on public-facing services, enumerate endpoints and technologies",
            target_component=entry,
            technique="T1595 - Active Scanning / T1592 - Gather Victim Host Information",
            outcome="Identify exposed services, versions, and potential vulnerabilities"
        ))
        step_num += 1
        
        # Step 2: Initial Access via entry point
        entry_threat = next((t for t in threats if t.affected_component == entry and t.category in ["Spoofing", "Tampering"]), None)
        if entry_threat:
            steps.append(AttackPathStep(
                step_number=step_num,
                action=f"Exploit: {entry_threat.description[:80]}",
                target_component=entry,
                technique="T1190 - Exploit Public-Facing Application",
                outcome="Gain authenticated session or bypass authentication"
            ))
            referenced_threats.append(entry_threat.threat_id)
        else:
            steps.append(AttackPathStep(
                step_number=step_num,
                action="Exploit authentication weakness or use stolen credentials",
                target_component=entry,
                technique="T1078 - Valid Accounts / T1110 - Brute Force",
                outcome="Establish authenticated access to application"
            ))
        step_num += 1
        
        # Step 3: Move to backend via data flow
        middle_components = []
        for dest in flow_graph.get(entry, []):
            if dest not in entry_points and dest not in databases:
                middle_components.append(dest)
        
        if middle_components:
            middle = middle_components[0]
            middle_threat = next((t for t in threats if t.affected_component == middle), None)
            steps.append(AttackPathStep(
                step_number=step_num,
                action=f"Traverse to backend service, exploit internal API or service-to-service trust",
                target_component=middle,
                technique="T1021 - Remote Services / T1570 - Lateral Tool Transfer",
                outcome="Gain access to internal service layer"
            ))
            if middle_threat:
                referenced_threats.append(middle_threat.threat_id)
            step_num += 1
        
        # Step 4: Database exploitation
        db_threats = component_threats.get(target_db, [])
        db_cves = component_cves.get(target_db, [])
        
        db_threat = next((t for t in db_threats if t.category == "Information Disclosure"), None)
        if db_threat:
            steps.append(AttackPathStep(
                step_number=step_num,
                action=f"Exploit database: {db_threat.description[:80]}",
                target_component=target_db,
                technique="T1213 - Data from Information Repositories / T1005 - Data from Local System",
                outcome="Extract sensitive data from database"
            ))
            referenced_threats.append(db_threat.threat_id)
        else:
            steps.append(AttackPathStep(
                step_number=step_num,
                action="Execute SQL injection or abuse database credentials to extract data",
                target_component=target_db,
                technique="T1213 - Data from Information Repositories",
                outcome="Exfiltrate customer PII, credentials, or business data"
            ))
        
        if db_cves:
            referenced_cves.extend([c.cve_id for c in db_cves[:2]])
        
        # Step 5: Exfiltration
        step_num += 1
        steps.append(AttackPathStep(
            step_number=step_num,
            action="Exfiltrate data via HTTPS to attacker-controlled server or cloud storage",
            target_component=target_db,
            technique="T1041 - Exfiltration Over C2 Channel / T1567 - Exfiltration Over Web Service",
            outcome="Complete data breach"
        ))
        
        # Calculate likelihood based on threat severities
        threat_severities = [t.severity for t in threats if t.threat_id in referenced_threats]
        cve_severities = [c.severity for c in cves if c.cve_id in referenced_cves]
        
        # Likelihood based on highest severity threat/CVE
        if any(s in ["Critical", "CRITICAL"] for s in threat_severities + cve_severities):
            path_likelihood = "High"
        elif any(s in ["High", "HIGH"] for s in threat_severities + cve_severities):
            path_likelihood = "Medium"
        else:
            path_likelihood = "Low"
        
        attack_paths.append(AttackPath(
            path_id=f"AP-{path_id:02d}",
            name="External Attacker to Database Breach",
            description=f"Multi-stage attack from external access through {entry} to data exfiltration from {target_db}. Attacker chains application vulnerabilities with database access to achieve full data breach.",
            impact="Complete compromise of sensitive data including customer PII, credentials, and business data. Potential regulatory violations (GDPR, PCI-DSS).",
            likelihood=path_likelihood,
            steps=steps,
            referenced_threats=referenced_threats,
            referenced_cves=referenced_cves
        ))
        path_id += 1
    
    # ==========================================================================
    # PATH 2: Credential Theft -> Lateral Movement -> Privilege Escalation
    # ==========================================================================
    if auth_components and len(threats) >= 3:
        steps = []
        referenced_threats = []
        referenced_cves = []
        
        auth_comp = auth_components[0] if auth_components else "Auth Service"
        
        # Find spoofing threat
        spoof_threat = next((t for t in threats if t.category == "Spoofing"), None)
        priv_threat = next((t for t in threats if t.category == "Elevation of Privilege"), None)
        
        steps.append(AttackPathStep(
            step_number=1,
            action="Phishing campaign targeting employees to harvest credentials, or exploit password spray against SSO",
            target_component=auth_comp,
            technique="T1566 - Phishing / T1110.003 - Password Spraying",
            outcome="Obtain valid user credentials"
        ))
        
        if spoof_threat:
            steps.append(AttackPathStep(
                step_number=2,
                action=f"Use stolen credentials: {spoof_threat.description[:60]}",
                target_component=spoof_threat.affected_component,
                technique="T1078 - Valid Accounts",
                outcome="Authenticate as legitimate user"
            ))
            referenced_threats.append(spoof_threat.threat_id)
        else:
            steps.append(AttackPathStep(
                step_number=2,
                action="Authenticate to internal services using stolen credentials",
                target_component=auth_comp,
                technique="T1078 - Valid Accounts",
                outcome="Access internal applications as legitimate user"
            ))
        
        steps.append(AttackPathStep(
            step_number=3,
            action="Enumerate internal services, discover service accounts and API keys in environment variables or config files",
            target_component="Internal Services",
            technique="T1087 - Account Discovery / T1552 - Unsecured Credentials",
            outcome="Discover high-privilege credentials"
        ))
        
        if priv_threat:
            steps.append(AttackPathStep(
                step_number=4,
                action=f"Escalate privileges: {priv_threat.description[:60]}",
                target_component=priv_threat.affected_component,
                technique="T1068 - Exploitation for Privilege Escalation",
                outcome="Gain administrative access"
            ))
            referenced_threats.append(priv_threat.threat_id)
        else:
            steps.append(AttackPathStep(
                step_number=4,
                action="Exploit misconfigured RBAC or assume service account with elevated permissions",
                target_component="Backend Services",
                technique="T1078.003 - Valid Accounts: Cloud Accounts",
                outcome="Gain cluster-admin or database-admin privileges"
            ))
        
        steps.append(AttackPathStep(
            step_number=5,
            action="Establish persistence via backdoor service account, scheduled task, or modified container image",
            target_component="Kubernetes Cluster",
            technique="T1053 - Scheduled Task / T1525 - Implant Internal Image",
            outcome="Maintain persistent access even after initial credentials rotated"
        ))
        
        attack_paths.append(AttackPath(
            path_id=f"AP-{path_id:02d}",
            name="Credential Compromise to Cluster Takeover",
            description="Attacker compromises user credentials through social engineering, then leverages internal trust relationships and privilege escalation to gain full cluster control. Represents insider threat or advanced external attacker.",
            impact="Full administrative control of Kubernetes/OpenShift cluster. Ability to deploy malicious workloads, access secrets, and pivot to connected systems.",
            likelihood="Medium",
            steps=steps,
            referenced_threats=referenced_threats,
            referenced_cves=referenced_cves
        ))
        path_id += 1
    
    # ==========================================================================
    # PATH 3: Supply Chain / Dependency Attack
    # ==========================================================================
    if len(architecture.components) >= 3:
        steps = []
        referenced_threats = []
        
        tampering_threats = [t for t in threats if t.category == "Tampering"]
        
        steps.append(AttackPathStep(
            step_number=1,
            action="Compromise upstream dependency in container registry or package repository (npm, PyPI, Docker Hub)",
            target_component="Container Registry / Package Manager",
            technique="T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain",
            outcome="Inject malicious code into trusted dependency"
        ))
        
        steps.append(AttackPathStep(
            step_number=2,
            action="Malicious dependency pulled during CI/CD build or pod restart",
            target_component="CI/CD Pipeline",
            technique="T1195.002 - Supply Chain Compromise",
            outcome="Backdoored container deployed to production"
        ))
        
        if tampering_threats:
            target_threat = tampering_threats[0]
            steps.append(AttackPathStep(
                step_number=3,
                action=f"Backdoor activates: {target_threat.description[:60]}",
                target_component=target_threat.affected_component,
                technique="T1059 - Command and Scripting Interpreter",
                outcome="Execute arbitrary code within trusted service"
            ))
            referenced_threats.append(target_threat.threat_id)
        else:
            steps.append(AttackPathStep(
                step_number=3,
                action="Backdoor activates and establishes command-and-control channel",
                target_component="Application Pod",
                technique="T1059 - Command and Scripting Interpreter",
                outcome="Remote access to internal network"
            ))
        
        steps.append(AttackPathStep(
            step_number=4,
            action="Pivot from compromised pod to access service mesh, secrets, and connected databases",
            target_component="Service Mesh / Secrets",
            technique="T1552.007 - Unsecured Credentials: Container API",
            outcome="Access Kubernetes secrets, service account tokens"
        ))
        
        attack_paths.append(AttackPath(
            path_id=f"AP-{path_id:02d}",
            name="Supply Chain Compromise",
            description="Attacker compromises software supply chain (container images, packages, or CI/CD pipeline) to inject malicious code that executes within trusted production environment.",
            impact="Silent compromise of production systems with legitimate-appearing workloads. Difficult to detect. Can lead to data theft, cryptomining, or further lateral movement.",
            likelihood="Low",
            steps=steps,
            referenced_threats=referenced_threats,
            referenced_cves=[]
        ))
        path_id += 1
    
    return attack_paths


# =============================================================================
# Main Pipeline Orchestration
# =============================================================================

def run_threat_modeling_pipeline(
    image_path: str = None,
    json_input: str = None,
    json_data: Dict = None,
    output_file: str = None,
    verbose: bool = True
) -> Tuple[str, Dict[str, Any]]:
    """
    Orchestrates the Multi-Agent Threat Modeling Pipeline.
    
    Args:
        image_path: Path to architecture diagram image
        json_input: Path to JSON file with architecture data
        json_data: Dict with architecture data (for programmatic use)
        output_file: Path to save Markdown report
        verbose: Whether to print progress
        
    Returns:
        Tuple of (report_markdown, pipeline_results)
    """
    timer = PipelineTimer()
    timer.start()
    
    if verbose:
        print_header("LEFT<<SHIFT - Multi-Agent Threat Modeling Pipeline")
        print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    results = {
        "architecture": None,
        "inferred_components": [],
        "threats": [],
        "weaknesses": [],
        "cves": [],
        "attack_paths": [],
        "report": None,
        "timing": {}
    }
    
    # =========================================================================
    # Stage 1: Architecture Extraction
    # =========================================================================
    if verbose:
        print_stage(1, "Architecture Extraction")
    timer.start_stage("Stage 1: Architecture Extraction")
    
    architecture = None
    
    if image_path:
        if verbose:
            print_result("Input", f"Image file: {image_path}")
        
        # Use Vision Agent
        result = process_architecture_diagram(None, image_path)
        try:
            data = json.loads(result)
            if "error" in data:
                raise ValueError(data["error"])
            architecture = ArchitectureSchema.model_validate(data)
        except Exception as e:
            logger.error(f"Failed to process image: {e}")
            raise
    
    elif json_input:
        if verbose:
            print_result("Input", f"JSON file: {json_input}")
        
        # Load JSON file
        with open(json_input, 'r', encoding='utf-8') as f:
            data = json.load(f)
        architecture = ArchitectureSchema.model_validate(data)
    
    elif json_data:
        if verbose:
            print_result("Input", "JSON data (programmatic)")
        
        architecture = ArchitectureSchema.model_validate(json_data)
    
    else:
        raise ValueError("Must provide image_path, json_input, or json_data")
    
    results["architecture"] = architecture
    
    if verbose:
        print_result("Project", architecture.project_name)
        print_result("Components", f"{len(architecture.components)} found")
        
        comp_names = [c.name for c in architecture.components[:5]]
        if len(architecture.components) > 5:
            comp_names.append(f"... and {len(architecture.components) - 5} more")
        print_result("Component List", comp_names)
        
        print_result("Data Flows", len(architecture.data_flows))
        print_result("Trust Boundaries", len(architecture.trust_boundaries))
    
    duration = timer.end_stage()
    if verbose:
        print_complete(duration)
    
    # =========================================================================
    # Stage 2: Component Understanding
    # =========================================================================
    if verbose:
        print_stage(2, "Component Understanding")
    timer.start_stage("Stage 2: Component Understanding")
    
    component_agent = ComponentUnderstandingAgent()
    
    # Build component list with types
    components_for_inference = [
        {"name": c.name, "type": c.type}
        for c in architecture.components
    ]
    
    inferred = component_agent.analyze_architecture_components(components_for_inference)
    results["inferred_components"] = inferred
    
    if verbose:
        for comp in inferred[:5]:
            name = comp.get("component_name", comp.get("name", "Unknown"))
            cats = comp.get("inferred_product_categories", ["Unknown"])
            conf = comp.get("confidence", 0)
            print_result(name, f"{cats} (confidence={conf:.2f})")
        
        if len(inferred) > 5:
            print_result("...", f"and {len(inferred) - 5} more components")
    
    duration = timer.end_stage()
    if verbose:
        print_complete(duration)
    
    # =========================================================================
    # Stage 3: Threat Knowledge (STRIDE)
    # =========================================================================
    if verbose:
        print_stage(3, "Threat Knowledge (STRIDE Analysis)")
    timer.start_stage("Stage 3: Threat Knowledge")
    
    threat_agent = ThreatKnowledgeAgent()
    threat_results = threat_agent.generate_threats(inferred, architecture)
    
    threats = threat_results.get("threats", [])
    weaknesses = threat_results.get("weaknesses", [])
    
    results["threats"] = threats
    results["weaknesses"] = weaknesses
    
    if verbose:
        print_result("Threats Generated", len(threats))
        print_result("Weaknesses Identified", len(weaknesses))
        
        # STRIDE breakdown
        stride_counts = {}
        for t in threats:
            cat = t.category
            stride_counts[cat] = stride_counts.get(cat, 0) + 1
        
        print_result("STRIDE Breakdown", stride_counts)
        
        # Severity breakdown
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for t in threats:
            sev = t.severity
            if sev in sev_counts:
                sev_counts[sev] += 1
        print_result("Severity Distribution", sev_counts)
    
    duration = timer.end_stage()
    if verbose:
        print_complete(duration)
    
    # =========================================================================
    # Stage 4: CVE Discovery
    # =========================================================================
    if verbose:
        print_stage(4, "CVE Discovery (NVD + CISA KEV)")
    timer.start_stage("Stage 4: CVE Discovery")
    
    cve_agent = CVEDiscoveryAgent()
    cves = cve_agent.discover_cves(inferred)
    
    if verbose:
        print_result("CVEs Discovered", len(cves))
        
        critical_count = sum(1 for c in cves if c.severity == "CRITICAL")
        high_count = sum(1 for c in cves if c.severity == "HIGH")
        kev_count = sum(1 for c in cves if c.is_actively_exploited)
        
        print_result("Critical CVEs", critical_count)
        print_result("High CVEs", high_count)
        print_result("Actively Exploited (KEV)", kev_count)
        
        # Show top CVEs
        if cves:
            print_result("Top CVEs", "")
            for cve in cves[:3]:
                kev_tag = " [KEV]" if cve.is_actively_exploited else ""
                print(f"      - {cve.cve_id} [{cve.severity}]{kev_tag}")
    
    duration = timer.end_stage()
    if verbose:
        print_complete(duration)
    
    # =========================================================================
    # Stage 5: Threat Relevance Filtering
    # =========================================================================
    if verbose:
        print_stage(5, "Threat Relevance Analysis")
    timer.start_stage("Stage 5: Threat Relevance")
    
    relevance_agent = ThreatRelevanceAgent()
    relevance_results = relevance_agent.match_relevant_threats(
        inferred_components=inferred,
        generic_threats=threats,
        cve_threats=cves
    )
    
    relevant_threats = relevance_results.get("relevant_threats", threats)
    relevant_cves = relevance_results.get("relevant_cves", cves)
    
    # Update results with filtered data
    results["threats"] = relevant_threats
    results["cves"] = relevant_cves
    
    if verbose:
        filtered_cves = len(cves) - len(relevant_cves)
        promoted = len(relevant_threats) - len(threats)
        
        print_result("Input CVEs", len(cves))
        print_result("Relevant CVEs", len(relevant_cves))
        print_result("Filtered Out", filtered_cves)
        print_result("CVEs Promoted to Threats", max(0, promoted))
        print_result("Final Threat Count", len(relevant_threats))
    
    duration = timer.end_stage()
    if verbose:
        print_complete(duration)
    
    # =========================================================================
    # Stage 6: Attack Path Simulation
    # =========================================================================
    if verbose:
        print_stage(6, "Attack Path Simulation")
    timer.start_stage("Stage 6: Attack Path Simulation")
    
    attack_paths = generate_attack_paths(relevant_threats, relevant_cves, architecture)
    results["attack_paths"] = attack_paths
    
    if verbose:
        print_result("Attack Paths Generated", len(attack_paths))
        
        for path in attack_paths:
            print(f"      - {path.path_id}: {path.name}")
            print(f"        Impact: {path.impact[:50]}...")
            print(f"        Steps: {len(path.steps)}, Likelihood: {path.likelihood}")
    
    duration = timer.end_stage()
    if verbose:
        print_complete(duration)
    
    # =========================================================================
    # Stage 7: Report Synthesis
    # =========================================================================
    if verbose:
        print_stage(7, "Report Synthesis")
    timer.start_stage("Stage 7: Report Synthesis")
    
    report_agent = ReportSynthesizerAgent()
    
    report = report_agent.generate_full_report(
        architecture=architecture,
        inferred_components=inferred,
        threats=relevant_threats,
        weaknesses=weaknesses,
        cves=relevant_cves,
        attack_paths=attack_paths,
        output_path=output_file
    )
    
    results["report"] = report
    
    if verbose:
        print_result("Report Length", f"{len(report):,} characters")
        if output_file:
            print_result("Saved To", output_file)
    
    duration = timer.end_stage()
    if verbose:
        print_complete(duration)
    
    # =========================================================================
    # Pipeline Complete
    # =========================================================================
    results["timing"] = timer.stage_times
    
    if verbose:
        print(timer.get_summary())
        
        # Executive Summary
        print_header("EXECUTIVE SUMMARY")
        print(f"  Project: {architecture.project_name}")
        print(f"  Components Analyzed: {len(architecture.components)}")
        print(f"  Threats Identified: {len(relevant_threats)}")
        print(f"  Weaknesses Found: {len(weaknesses)}")
        print(f"  CVEs Discovered: {len(relevant_cves)}")
        print(f"  Attack Paths Simulated: {len(attack_paths)}")
        print()
        
        # Risk Overview
        critical_threats = sum(1 for t in relevant_threats if t.severity == "Critical")
        critical_cves = sum(1 for c in relevant_cves if c.severity == "CRITICAL")
        kev_cves = sum(1 for c in relevant_cves if c.is_actively_exploited)
        
        risk_level = "LOW"
        if critical_threats > 0 or critical_cves > 0:
            risk_level = "CRITICAL"
        elif kev_cves > 0 or sum(1 for t in relevant_threats if t.severity == "High") > 3:
            risk_level = "HIGH"
        elif len(relevant_threats) > 10:
            risk_level = "MEDIUM"
        
        print(f"  Overall Risk Level: {risk_level}")
        print(f"  Critical Threats: {critical_threats}")
        print(f"  Critical CVEs: {critical_cves}")
        print(f"  Actively Exploited (KEV): {kev_cves}")
        print()
        
        if output_file:
            print(f"  Report saved to: {output_file}")
        
        print("\n" + "=" * 60)
        print("  Pipeline completed successfully!")
        print("=" * 60 + "\n")
    
    return report, results


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "run_threat_modeling_pipeline",
    "PipelineTimer",
    "generate_attack_paths",
]
