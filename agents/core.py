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
    Generate attack path simulations based on threats and CVEs.
    
    This is a heuristic-based approach that chains related threats
    and CVEs into potential attack sequences.
    """
    attack_paths = []
    
    # Group threats by component
    component_threats: Dict[str, List[ArchitecturalThreat]] = {}
    for threat in threats:
        comp = threat.affected_component
        if comp not in component_threats:
            component_threats[comp] = []
        component_threats[comp].append(threat)
    
    # Create CVE lookup
    cve_lookup = {cve.cve_id: cve for cve in cves}
    
    # Find critical CVEs for path generation
    critical_cves = [c for c in cves if c.severity == "CRITICAL" or c.is_actively_exploited]
    
    path_id = 1
    
    # Generate paths for critical CVEs
    for cve in critical_cves[:3]:  # Limit to top 3
        # Find related threats
        related_threats = [
            t for t in threats 
            if t.related_cve_id == cve.cve_id or 
               (t.cwe_id and cve.cwe_id and t.cwe_id == cve.cwe_id)
        ]
        
        if not related_threats:
            # Find threats affecting same product
            product_name = cve.affected_products.split(":")[0] if ":" in cve.affected_products else cve.affected_products
            related_threats = [
                t for t in threats
                if product_name.lower() in t.affected_component.lower()
            ][:2]
        
        if related_threats:
            # Build attack path
            steps = []
            step_num = 1
            
            # Initial access
            steps.append(AttackPathStep(
                step_number=step_num,
                action=f"Exploit {cve.cve_id} ({cve.exploitability or 'vulnerability'})",
                target_component=related_threats[0].affected_component,
                technique="T1190 - Exploit Public-Facing Application",
                outcome=f"Gain initial access via {cve.cwe_id or 'vulnerability'}"
            ))
            step_num += 1
            
            # Escalation/lateral movement
            for threat in related_threats[:2]:
                steps.append(AttackPathStep(
                    step_number=step_num,
                    action=threat.description[:100],
                    target_component=threat.affected_component,
                    technique=f"STRIDE: {threat.category}",
                    outcome=f"Achieve {threat.category.lower()}"
                ))
                step_num += 1
            
            # Impact
            impact = "System compromise"
            if "RCE" in (cve.exploitability or ""):
                impact = "Remote code execution and full system control"
            elif "DoS" in (cve.exploitability or ""):
                impact = "Service disruption and availability loss"
            elif "Disclosure" in (cve.exploitability or ""):
                impact = "Sensitive data exfiltration"
            
            path = AttackPath(
                path_id=f"AP-{path_id:02d}",
                name=f"Attack via {cve.cve_id}",
                description=f"Attack chain exploiting {cve.cve_id} leading to {impact.lower()}",
                impact=impact,
                likelihood="High" if cve.is_actively_exploited else "Medium",
                steps=steps,
                referenced_threats=[t.threat_id for t in related_threats],
                referenced_cves=[cve.cve_id]
            )
            
            attack_paths.append(path)
            path_id += 1
    
    # Generate a generic lateral movement path if we have multiple components
    if len(architecture.components) >= 3 and len(threats) >= 5:
        # Find entry point threat
        entry_threats = [t for t in threats if t.category in ["Spoofing", "Tampering"]]
        escalation_threats = [t for t in threats if t.category == "Elevation of Privilege"]
        disclosure_threats = [t for t in threats if t.category == "Information Disclosure"]
        
        if entry_threats and (escalation_threats or disclosure_threats):
            steps = [
                AttackPathStep(
                    step_number=1,
                    action="Gain initial foothold via " + entry_threats[0].description[:50],
                    target_component=entry_threats[0].affected_component,
                    technique="T1078 - Valid Accounts / T1190 - Exploit Public-Facing Application",
                    outcome="Initial access to application layer"
                )
            ]
            
            if escalation_threats:
                steps.append(AttackPathStep(
                    step_number=2,
                    action="Escalate privileges via " + escalation_threats[0].description[:50],
                    target_component=escalation_threats[0].affected_component,
                    technique="T1068 - Exploitation for Privilege Escalation",
                    outcome="Elevated access rights"
                ))
            
            if disclosure_threats:
                steps.append(AttackPathStep(
                    step_number=len(steps) + 1,
                    action="Exfiltrate data via " + disclosure_threats[0].description[:50],
                    target_component=disclosure_threats[0].affected_component,
                    technique="T1041 - Exfiltration Over C2 Channel",
                    outcome="Data breach"
                ))
            
            path = AttackPath(
                path_id=f"AP-{path_id:02d}",
                name="Lateral Movement to Data Exfiltration",
                description="Multi-stage attack progressing from initial access to data theft",
                impact="Complete compromise of sensitive data",
                likelihood="Medium",
                steps=steps,
                referenced_threats=[
                    entry_threats[0].threat_id,
                    *([escalation_threats[0].threat_id] if escalation_threats else []),
                    *([disclosure_threats[0].threat_id] if disclosure_threats else [])
                ],
                referenced_cves=[c.cve_id for c in critical_cves[:2]]
            )
            
            attack_paths.append(path)
    
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
