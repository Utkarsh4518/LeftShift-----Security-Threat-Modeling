"""
LangGraph-based Pipeline Orchestration for Left<<Shift Threat Modeling System.

This module provides a graph-based pipeline that enables:
- Parallel execution of independent stages
- State management across nodes
- Checkpointing for resumption
- Better visualization and debugging

Pipeline Graph:
    Architecture Extraction
            |
    +-------+-------+
    |               |
    v               v
  Component    Threat Knowledge
Understanding     (STRIDE)
    |               |
    +-------+-------+
            |
            v
      CVE Discovery
            |
            v
    Threat Relevance
            |
            v
      Attack Paths
            |
            v
    Report Synthesis
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TypedDict, Annotated
import operator

from langgraph.graph import StateGraph, START, END
from langgraph.graph.state import CompiledStateGraph
from langgraph.checkpoint.memory import MemorySaver

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

# Import tools and agents
from tools.diagram_processor import process_architecture_diagram
from agents.component_understanding_agent import ComponentUnderstandingAgent
from agents.threat_knowledge_agent import ThreatKnowledgeAgent
from agents.cve_discovery_agent import CVEDiscoveryAgent
from agents.threat_relevance_agent import ThreatRelevanceAgent
from agents.report_synthesizer_agent import ReportSynthesizerAgent

logger = logging.getLogger(__name__)


# =============================================================================
# State Definition
# =============================================================================

def merge_dicts(left: Dict, right: Dict) -> Dict:
    """Merge two dictionaries, right values override left."""
    result = left.copy()
    result.update(right)
    return result


class PipelineState(TypedDict, total=False):
    """
    State schema for the threat modeling pipeline.
    
    All fields are optional to allow incremental updates.
    """
    # Inputs (set once at start)
    image_path: Optional[str]
    json_input: Optional[str]
    json_data: Optional[Dict]
    output_file: Optional[str]
    verbose: bool
    
    # Stage outputs
    architecture: Optional[Dict]  # Serialized ArchitectureSchema
    inferred_components: Optional[List[Dict]]
    threats: Optional[List[Dict]]  # Serialized ArchitecturalThreat list
    weaknesses: Optional[List[Dict]]  # Serialized ArchitecturalWeakness list
    cves: Optional[List[Dict]]  # Serialized ThreatRecord list
    attack_paths: Optional[List[Dict]]  # Serialized AttackPath list
    report: Optional[str]
    
    # Timing and metadata
    stage_times: Annotated[Dict[str, float], merge_dicts]
    errors: Annotated[List[str], operator.add]
    current_stage: Optional[str]
    start_time: Optional[float]


# =============================================================================
# Helper Functions
# =============================================================================

def _serialize_architecture(arch: ArchitectureSchema) -> Dict:
    """Serialize ArchitectureSchema to dict for state storage."""
    return arch.model_dump()


def _deserialize_architecture(data: Dict) -> ArchitectureSchema:
    """Deserialize dict to ArchitectureSchema."""
    return ArchitectureSchema.model_validate(data)


def _serialize_threats(threats: List[ArchitecturalThreat]) -> List[Dict]:
    """Serialize threats to list of dicts."""
    return [t.model_dump() for t in threats]


def _deserialize_threats(data: List[Dict]) -> List[ArchitecturalThreat]:
    """Deserialize list of dicts to threats."""
    return [ArchitecturalThreat.model_validate(d) for d in data]


def _serialize_weaknesses(weaknesses: List[ArchitecturalWeakness]) -> List[Dict]:
    """Serialize weaknesses to list of dicts."""
    return [w.model_dump() for w in weaknesses]


def _deserialize_weaknesses(data: List[Dict]) -> List[ArchitecturalWeakness]:
    """Deserialize list of dicts to weaknesses."""
    return [ArchitecturalWeakness.model_validate(d) for d in data]


def _serialize_cves(cves: List[ThreatRecord]) -> List[Dict]:
    """Serialize CVEs to list of dicts."""
    return [c.model_dump() for c in cves]


def _deserialize_cves(data: List[Dict]) -> List[ThreatRecord]:
    """Deserialize list of dicts to CVEs."""
    return [ThreatRecord.model_validate(d) for d in data]


def _serialize_attack_paths(paths: List[AttackPath]) -> List[Dict]:
    """Serialize attack paths to list of dicts."""
    return [p.model_dump() for p in paths]


def _deserialize_attack_paths(data: List[Dict]) -> List[AttackPath]:
    """Deserialize list of dicts to attack paths."""
    return [AttackPath.model_validate(d) for d in data]


def _log_stage(state: PipelineState, stage_name: str, message: str):
    """Log stage progress if verbose."""
    if state.get("verbose", True):
        print(f"  [{stage_name}] {message}")


# =============================================================================
# Node Functions
# =============================================================================

def extract_architecture_node(state: PipelineState) -> Dict:
    """
    Stage 1: Extract architecture from image or JSON.
    
    Wraps the existing diagram processor and JSON loading logic.
    """
    stage_start = time.time()
    stage_name = "Architecture Extraction"
    
    if state.get("verbose", True):
        print(f"\n[Stage 1] {stage_name}")
        print("-" * 50)
    
    architecture = None
    
    image_path = state.get("image_path")
    json_input = state.get("json_input")
    json_data = state.get("json_data")
    
    try:
        if image_path:
            _log_stage(state, stage_name, f"Processing image: {image_path}")
            result = process_architecture_diagram(None, image_path)
            data = json.loads(result)
            if "error" in data:
                raise ValueError(data["error"])
            architecture = ArchitectureSchema.model_validate(data)
        
        elif json_input:
            _log_stage(state, stage_name, f"Loading JSON: {json_input}")
            with open(json_input, 'r', encoding='utf-8') as f:
                data = json.load(f)
            architecture = ArchitectureSchema.model_validate(data)
        
        elif json_data:
            _log_stage(state, stage_name, "Using provided JSON data")
            architecture = ArchitectureSchema.model_validate(json_data)
        
        else:
            raise ValueError("Must provide image_path, json_input, or json_data")
        
        duration = time.time() - stage_start
        
        if state.get("verbose", True):
            print(f"  -> Project: {architecture.project_name}")
            print(f"  -> Components: {len(architecture.components)} found")
            print(f"  -> Data Flows: {len(architecture.data_flows)}")
            print(f"  -> Trust Boundaries: {len(architecture.trust_boundaries)}")
            print(f"  [OK] Complete ({duration:.2f}s)")
        
        return {
            "architecture": _serialize_architecture(architecture),
            "stage_times": {stage_name: duration},
            "errors": []
        }
    
    except Exception as e:
        logger.error(f"Architecture extraction failed: {e}")
        return {
            "errors": [f"Architecture extraction failed: {str(e)}"],
            "stage_times": {stage_name: time.time() - stage_start}
        }


def understand_components_node(state: PipelineState) -> Dict:
    """
    Stage 2: Infer technology products from component labels.
    
    Runs in PARALLEL with threat generation.
    """
    stage_start = time.time()
    stage_name = "Component Understanding"
    
    if state.get("verbose", True):
        print(f"\n[Stage 2a] {stage_name}")
        print("-" * 50)
    
    try:
        arch_data = state.get("architecture")
        if not arch_data:
            raise ValueError("No architecture data available")
        
        architecture = _deserialize_architecture(arch_data)
        
        component_agent = ComponentUnderstandingAgent()
        
        components_for_inference = [
            {"name": c.name, "type": c.type}
            for c in architecture.components
        ]
        
        inferred = component_agent.analyze_architecture_components(components_for_inference)
        
        duration = time.time() - stage_start
        
        if state.get("verbose", True):
            for comp in inferred[:3]:
                name = comp.get("component_name", comp.get("name", "Unknown"))
                cats = comp.get("inferred_product_categories", ["Unknown"])
                conf = comp.get("confidence", 0)
                print(f"  -> {name}: {cats} (confidence={conf:.2f})")
            if len(inferred) > 3:
                print(f"  -> ... and {len(inferred) - 3} more")
            print(f"  [OK] Complete ({duration:.2f}s)")
        
        return {
            "inferred_components": inferred,
            "stage_times": {stage_name: duration},
            "errors": []
        }
    
    except Exception as e:
        logger.error(f"Component understanding failed: {e}")
        return {
            "inferred_components": [],
            "errors": [f"Component understanding failed: {str(e)}"],
            "stage_times": {stage_name: time.time() - stage_start}
        }


def generate_threats_node(state: PipelineState) -> Dict:
    """
    Stage 2b: Generate STRIDE threats.
    
    Runs in PARALLEL with component understanding.
    Note: Uses architecture directly, doesn't need inferred components.
    """
    stage_start = time.time()
    stage_name = "Threat Knowledge (STRIDE)"
    
    if state.get("verbose", True):
        print(f"\n[Stage 2b] {stage_name}")
        print("-" * 50)
    
    try:
        arch_data = state.get("architecture")
        if not arch_data:
            raise ValueError("No architecture data available")
        
        architecture = _deserialize_architecture(arch_data)
        
        # For STRIDE, we can use basic component info without full inference
        basic_components = [
            {"name": c.name, "type": c.type, "component_name": c.name}
            for c in architecture.components
        ]
        
        threat_agent = ThreatKnowledgeAgent()
        threat_results = threat_agent.generate_threats(basic_components, architecture)
        
        threats = threat_results.get("threats", [])
        weaknesses = threat_results.get("weaknesses", [])
        
        duration = time.time() - stage_start
        
        if state.get("verbose", True):
            print(f"  -> Threats Generated: {len(threats)}")
            print(f"  -> Weaknesses Identified: {len(weaknesses)}")
            
            stride_counts = {}
            for t in threats:
                cat = t.category
                stride_counts[cat] = stride_counts.get(cat, 0) + 1
            print(f"  -> STRIDE Breakdown: {stride_counts}")
            print(f"  [OK] Complete ({duration:.2f}s)")
        
        return {
            "threats": _serialize_threats(threats),
            "weaknesses": _serialize_weaknesses(weaknesses),
            "stage_times": {stage_name: duration},
            "errors": []
        }
    
    except Exception as e:
        logger.error(f"Threat generation failed: {e}")
        return {
            "threats": [],
            "weaknesses": [],
            "errors": [f"Threat generation failed: {str(e)}"],
            "stage_times": {stage_name: time.time() - stage_start}
        }


def discover_cves_node(state: PipelineState) -> Dict:
    """
    Stage 3: Discover CVEs for inferred components.
    
    Requires inferred_components from Stage 2a.
    """
    stage_start = time.time()
    stage_name = "CVE Discovery"
    
    if state.get("verbose", True):
        print(f"\n[Stage 3] {stage_name}")
        print("-" * 50)
    
    try:
        inferred = state.get("inferred_components", [])
        if not inferred:
            _log_stage(state, stage_name, "No inferred components, skipping CVE discovery")
            return {
                "cves": [],
                "stage_times": {stage_name: time.time() - stage_start},
                "errors": []
            }
        
        cve_agent = CVEDiscoveryAgent()
        cves = cve_agent.discover_cves(inferred)
        
        duration = time.time() - stage_start
        
        if state.get("verbose", True):
            print(f"  -> CVEs Discovered: {len(cves)}")
            critical_count = sum(1 for c in cves if c.severity == "CRITICAL")
            high_count = sum(1 for c in cves if c.severity == "HIGH")
            kev_count = sum(1 for c in cves if c.is_actively_exploited)
            print(f"  -> Critical: {critical_count}, High: {high_count}, KEV: {kev_count}")
            print(f"  [OK] Complete ({duration:.2f}s)")
        
        return {
            "cves": _serialize_cves(cves),
            "stage_times": {stage_name: duration},
            "errors": []
        }
    
    except Exception as e:
        logger.error(f"CVE discovery failed: {e}")
        return {
            "cves": [],
            "errors": [f"CVE discovery failed: {str(e)}"],
            "stage_times": {stage_name: time.time() - stage_start}
        }


def analyze_relevance_node(state: PipelineState) -> Dict:
    """
    Stage 4: Filter and score threats/CVEs for relevance.
    """
    stage_start = time.time()
    stage_name = "Threat Relevance"
    
    if state.get("verbose", True):
        print(f"\n[Stage 4] {stage_name}")
        print("-" * 50)
    
    try:
        inferred = state.get("inferred_components", [])
        threats_data = state.get("threats", [])
        cves_data = state.get("cves", [])
        
        threats = _deserialize_threats(threats_data) if threats_data else []
        cves = _deserialize_cves(cves_data) if cves_data else []
        
        original_cve_count = len(cves)
        original_threat_count = len(threats)
        
        relevance_agent = ThreatRelevanceAgent()
        relevance_results = relevance_agent.match_relevant_threats(
            inferred_components=inferred,
            generic_threats=threats,
            cve_threats=cves
        )
        
        relevant_threats = relevance_results.get("relevant_threats", threats)
        relevant_cves = relevance_results.get("relevant_cves", cves)
        
        duration = time.time() - stage_start
        
        if state.get("verbose", True):
            filtered_cves = original_cve_count - len(relevant_cves)
            new_threats = len(relevant_threats) - original_threat_count
            print(f"  -> Input CVEs: {original_cve_count}")
            print(f"  -> Relevant CVEs: {len(relevant_cves)}")
            print(f"  -> Filtered Out: {filtered_cves}")
            print(f"  -> CVEs Promoted to Threats: {max(0, new_threats)}")
            print(f"  [OK] Complete ({duration:.2f}s)")
        
        return {
            "threats": _serialize_threats(relevant_threats),
            "cves": _serialize_cves(relevant_cves),
            "stage_times": {stage_name: duration},
            "errors": []
        }
    
    except Exception as e:
        logger.error(f"Relevance analysis failed: {e}")
        return {
            "errors": [f"Relevance analysis failed: {str(e)}"],
            "stage_times": {stage_name: time.time() - stage_start}
        }


def generate_attack_paths_node(state: PipelineState) -> Dict:
    """
    Stage 5: Generate attack path simulations.
    """
    stage_start = time.time()
    stage_name = "Attack Path Simulation"
    
    if state.get("verbose", True):
        print(f"\n[Stage 5] {stage_name}")
        print("-" * 50)
    
    try:
        arch_data = state.get("architecture")
        threats_data = state.get("threats", [])
        cves_data = state.get("cves", [])
        
        architecture = _deserialize_architecture(arch_data) if arch_data else None
        threats = _deserialize_threats(threats_data) if threats_data else []
        cves = _deserialize_cves(cves_data) if cves_data else []
        
        if not architecture:
            raise ValueError("No architecture data available")
        
        # Import the attack path generator from core
        from agents.core import generate_attack_paths
        
        attack_paths = generate_attack_paths(threats, cves, architecture)
        
        duration = time.time() - stage_start
        
        if state.get("verbose", True):
            print(f"  -> Attack Paths Generated: {len(attack_paths)}")
            for path in attack_paths:
                print(f"      - {path.path_id}: {path.name}")
            print(f"  [OK] Complete ({duration:.2f}s)")
        
        return {
            "attack_paths": _serialize_attack_paths(attack_paths),
            "stage_times": {stage_name: duration},
            "errors": []
        }
    
    except Exception as e:
        logger.error(f"Attack path generation failed: {e}")
        return {
            "attack_paths": [],
            "errors": [f"Attack path generation failed: {str(e)}"],
            "stage_times": {stage_name: time.time() - stage_start}
        }


def synthesize_report_node(state: PipelineState) -> Dict:
    """
    Stage 6: Generate final Markdown report.
    """
    stage_start = time.time()
    stage_name = "Report Synthesis"
    
    if state.get("verbose", True):
        print(f"\n[Stage 6] {stage_name}")
        print("-" * 50)
    
    try:
        arch_data = state.get("architecture")
        inferred = state.get("inferred_components", [])
        threats_data = state.get("threats", [])
        weaknesses_data = state.get("weaknesses", [])
        cves_data = state.get("cves", [])
        attack_paths_data = state.get("attack_paths", [])
        output_file = state.get("output_file")
        
        architecture = _deserialize_architecture(arch_data) if arch_data else None
        threats = _deserialize_threats(threats_data) if threats_data else []
        weaknesses = _deserialize_weaknesses(weaknesses_data) if weaknesses_data else []
        cves = _deserialize_cves(cves_data) if cves_data else []
        attack_paths = _deserialize_attack_paths(attack_paths_data) if attack_paths_data else []
        
        if not architecture:
            raise ValueError("No architecture data available")
        
        report_agent = ReportSynthesizerAgent()
        
        report = report_agent.generate_full_report(
            architecture=architecture,
            inferred_components=inferred,
            threats=threats,
            weaknesses=weaknesses,
            cves=cves,
            attack_paths=attack_paths,
            output_path=output_file
        )
        
        duration = time.time() - stage_start
        
        if state.get("verbose", True):
            print(f"  -> Report Length: {len(report):,} characters")
            if output_file:
                print(f"  -> Saved To: {output_file}")
            print(f"  [OK] Complete ({duration:.2f}s)")
        
        return {
            "report": report,
            "stage_times": {stage_name: duration},
            "errors": []
        }
    
    except Exception as e:
        logger.error(f"Report synthesis failed: {e}")
        return {
            "report": "",
            "errors": [f"Report synthesis failed: {str(e)}"],
            "stage_times": {stage_name: time.time() - stage_start}
        }


# =============================================================================
# Graph Construction
# =============================================================================

def build_pipeline_graph(checkpointer=None) -> CompiledStateGraph:
    """
    Build the LangGraph pipeline with parallel execution.
    
    Graph structure:
        extract_architecture
               |
        +------+------+
        |             |
        v             v
    understand    generate_threats
    components    (STRIDE)
        |             |
        +------+------+
               |
               v
         discover_cves
               |
               v
        analyze_relevance
               |
               v
       generate_attack_paths
               |
               v
        synthesize_report
               |
               v
              END
    
    Args:
        checkpointer: Optional checkpointer for state persistence
        
    Returns:
        Compiled state graph
    """
    builder = StateGraph(PipelineState)
    
    # Add all nodes
    builder.add_node("extract_architecture", extract_architecture_node)
    builder.add_node("understand_components", understand_components_node)
    builder.add_node("generate_threats", generate_threats_node)
    builder.add_node("discover_cves", discover_cves_node)
    builder.add_node("analyze_relevance", analyze_relevance_node)
    builder.add_node("generate_attack_paths", generate_attack_paths_node)
    builder.add_node("synthesize_report", synthesize_report_node)
    
    # Entry point
    builder.add_edge(START, "extract_architecture")
    
    # Parallel branches: Component Understanding and Threat Generation
    # Both only need architecture, so they can run in parallel
    builder.add_edge("extract_architecture", "understand_components")
    builder.add_edge("extract_architecture", "generate_threats")
    
    # Join: CVE Discovery needs inferred components
    builder.add_edge("understand_components", "discover_cves")
    builder.add_edge("generate_threats", "discover_cves")
    
    # Sequential: Each stage depends on previous
    builder.add_edge("discover_cves", "analyze_relevance")
    builder.add_edge("analyze_relevance", "generate_attack_paths")
    builder.add_edge("generate_attack_paths", "synthesize_report")
    builder.add_edge("synthesize_report", END)
    
    # Compile with optional checkpointer
    if checkpointer:
        return builder.compile(checkpointer=checkpointer)
    else:
        return builder.compile(checkpointer=MemorySaver())


def run_pipeline_graph(
    graph: CompiledStateGraph,
    image_path: str = None,
    json_input: str = None,
    json_data: Dict = None,
    output_file: str = None,
    verbose: bool = True,
    thread_id: str = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Execute the pipeline graph.
    
    Args:
        graph: Compiled pipeline graph
        image_path: Path to architecture diagram image
        json_input: Path to JSON file with architecture data
        json_data: Dict with architecture data
        output_file: Path to save Markdown report
        verbose: Whether to print progress
        thread_id: Optional thread ID for checkpointing
        
    Returns:
        Tuple of (report_markdown, pipeline_results)
    """
    start_time = time.time()
    
    if verbose:
        print("\n" + "=" * 60)
        print("  LEFT<<SHIFT - Multi-Agent Threat Modeling Pipeline")
        print("  (LangGraph Orchestration)")
        print("=" * 60)
        print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Initial state
    initial_state: PipelineState = {
        "image_path": image_path,
        "json_input": json_input,
        "json_data": json_data,
        "output_file": output_file,
        "verbose": verbose,
        "architecture": None,
        "inferred_components": None,
        "threats": None,
        "weaknesses": None,
        "cves": None,
        "attack_paths": None,
        "report": None,
        "stage_times": {},
        "errors": [],
        "current_stage": None,
        "start_time": start_time
    }
    
    # Configure thread
    config = {}
    if thread_id:
        config["configurable"] = {"thread_id": thread_id}
    else:
        config["configurable"] = {"thread_id": f"pipeline_{int(start_time)}"}
    
    # Execute graph - accumulate ALL state updates from stream
    merged_state = initial_state.copy()
    
    for state_update in graph.stream(initial_state, config):
        # Each state_update is a dict with node_name -> node_output
        if isinstance(state_update, dict):
            for node_name, node_state in state_update.items():
                if isinstance(node_state, dict):
                    for key, value in node_state.items():
                        if key == "stage_times" and isinstance(value, dict):
                            merged_state["stage_times"].update(value)
                        elif key == "errors" and isinstance(value, list):
                            merged_state["errors"].extend(value)
                        elif value is not None:
                            merged_state[key] = value
    
    # Debug: Check what we accumulated
    if verbose:
        print(f"\n[DEBUG] merged_state architecture: {type(merged_state.get('architecture'))}")
        if merged_state.get('architecture'):
            arch = merged_state['architecture']
            if isinstance(arch, dict):
                print(f"[DEBUG] Architecture components: {len(arch.get('components', []))}")
    
    total_time = time.time() - start_time
    
    # Build results dict
    results = {
        "architecture": _deserialize_architecture(merged_state["architecture"]) if merged_state.get("architecture") else None,
        "inferred_components": merged_state.get("inferred_components", []),
        "threats": _deserialize_threats(merged_state.get("threats", [])) if merged_state.get("threats") else [],
        "weaknesses": _deserialize_weaknesses(merged_state.get("weaknesses", [])) if merged_state.get("weaknesses") else [],
        "cves": _deserialize_cves(merged_state.get("cves", [])) if merged_state.get("cves") else [],
        "attack_paths": _deserialize_attack_paths(merged_state.get("attack_paths", [])) if merged_state.get("attack_paths") else [],
        "report": merged_state.get("report", ""),
        "timing": merged_state.get("stage_times", {}),
        "errors": merged_state.get("errors", []),
        "total_time": total_time
    }
    
    if verbose:
        # Print timing summary
        print("\n" + "=" * 60)
        print("  PIPELINE TIMING SUMMARY")
        print("=" * 60)
        for stage, duration in results["timing"].items():
            print(f"  {stage}: {duration:.2f}s")
        print("-" * 60)
        print(f"  TOTAL TIME: {total_time:.2f}s")
        print("=" * 60)
        
        # Executive summary
        arch = results["architecture"]
        if arch:
            print("\n" + "=" * 60)
            print("  EXECUTIVE SUMMARY")
            print("=" * 60)
            print(f"  Project: {arch.project_name}")
            print(f"  Components Analyzed: {len(arch.components)}")
            print(f"  Threats Identified: {len(results['threats'])}")
            print(f"  Weaknesses Found: {len(results['weaknesses'])}")
            print(f"  CVEs Discovered: {len(results['cves'])}")
            print(f"  Attack Paths Simulated: {len(results['attack_paths'])}")
            
            if results["errors"]:
                print(f"\n  Errors: {len(results['errors'])}")
                for err in results["errors"]:
                    print(f"    - {err}")
            
            print("\n" + "=" * 60)
            print("  Pipeline completed successfully!")
            print("=" * 60 + "\n")
    
    return results.get("report", ""), results


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "PipelineState",
    "build_pipeline_graph",
    "run_pipeline_graph",
]
