/**
 * DiagramCompiler - Transforms Sentinel analysis output into a RenderGraph.
 * 
 * This is a pure function that:
 * 1. Maps components to nodes with lane assignments
 * 2. Attaches threat severity to each node
 * 3. Deduplicates and normalizes edges
 * 4. Produces a deterministic, stable RenderGraph
 * 
 * The frontend treats this as a compiler - semantic meaning comes from Sentinel,
 * geometry and layout are handled separately.
 */

import type {
  SentinelAnalysisResult,
  SentinelThreat,
  RenderGraph,
  RenderNode,
  RenderEdge,
  Severity,
} from './types';
import { getLane } from './roleMapper';

/**
 * Severity priority for determining highest risk.
 * Higher number = higher priority.
 */
const SEVERITY_PRIORITY: Record<Severity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  None: 0,
};

/**
 * Get the highest severity from a list of threats.
 */
function getHighestSeverity(threats: SentinelThreat[]): Severity {
  if (threats.length === 0) return 'None';
  
  return threats.reduce((highest, threat) => {
    const currentPriority = SEVERITY_PRIORITY[threat.severity] || 0;
    const highestPriority = SEVERITY_PRIORITY[highest] || 0;
    return currentPriority > highestPriority ? threat.severity : highest;
  }, 'None' as Severity);
}

/**
 * Normalize component name for consistent matching.
 */
function normalizeId(name: string): string {
  return name.toLowerCase().trim();
}

/**
 * Find threats affecting a specific component.
 * Matches by component name (case-insensitive).
 */
function findComponentThreats(
  componentName: string,
  threats: SentinelThreat[]
): SentinelThreat[] {
  const normalizedName = normalizeId(componentName);
  
  return threats.filter((threat) => {
    const affectedNormalized = normalizeId(threat.affected_component);
    // Match exact name or partial match for component references
    return (
      affectedNormalized === normalizedName ||
      affectedNormalized.includes(normalizedName) ||
      normalizedName.includes(affectedNormalized)
    );
  });
}

/**
 * Create a unique edge ID from source and destination.
 */
function createEdgeId(source: string, destination: string): string {
  return `${normalizeId(source)}->${normalizeId(destination)}`;
}

/**
 * Compile Sentinel analysis result into a RenderGraph.
 * 
 * This is the main entry point for transforming backend data
 * into a format suitable for visualization.
 */
export function compileDiagram(analysis: SentinelAnalysisResult): RenderGraph {
  const { architecture, threats } = analysis;
  
  // Build node map for quick lookup
  const nodeMap = new Map<string, RenderNode>();
  
  // Process components into nodes
  for (const component of architecture.components) {
    const componentThreats = findComponentThreats(component.name, threats);
    const highestSeverity = getHighestSeverity(componentThreats);
    
    const node: RenderNode = {
      id: component.name,
      label: component.name,
      type: component.type,
      lane: getLane(component.name, component.type),
      risk: highestSeverity,
      threats: componentThreats,
    };
    
    nodeMap.set(normalizeId(component.name), node);
  }
  
  // Process data flows into edges (deduplicated)
  const edgeMap = new Map<string, RenderEdge>();
  
  for (const flow of architecture.data_flows) {
    const edgeId = createEdgeId(flow.source, flow.destination);
    
    // Skip if edge already exists (deduplication)
    if (edgeMap.has(edgeId)) continue;
    
    // Skip if source or destination doesn't exist
    const sourceExists = nodeMap.has(normalizeId(flow.source));
    const destExists = nodeMap.has(normalizeId(flow.destination));
    
    if (!sourceExists || !destExists) {
      console.warn(`Skipping edge: ${flow.source} -> ${flow.destination} (missing node)`);
      continue;
    }
    
    const edge: RenderEdge = {
      id: edgeId,
      from: flow.source,
      to: flow.destination,
      protocol: flow.protocol,
    };
    
    edgeMap.set(edgeId, edge);
  }
  
  // Calculate threat statistics
  const criticalCount = threats.filter((t) => t.severity === 'Critical').length;
  const highCount = threats.filter((t) => t.severity === 'High').length;
  
  // Build final RenderGraph
  const renderGraph: RenderGraph = {
    nodes: Array.from(nodeMap.values()),
    edges: Array.from(edgeMap.values()),
    metadata: {
      projectName: architecture.project_name,
      description: architecture.description,
      trustBoundaries: architecture.trust_boundaries,
      totalThreats: threats.length,
      criticalCount,
      highCount,
    },
  };
  
  return renderGraph;
}

/**
 * Sort nodes by lane for consistent rendering order.
 */
export function sortNodesByLane(nodes: RenderNode[]): RenderNode[] {
  return [...nodes].sort((a, b) => {
    // Primary sort by lane
    if (a.lane !== b.lane) return a.lane - b.lane;
    // Secondary sort by name for stability
    return a.id.localeCompare(b.id);
  });
}

/**
 * Group nodes by lane for lane-based rendering.
 */
export function groupNodesByLane(nodes: RenderNode[]): Map<number, RenderNode[]> {
  const groups = new Map<number, RenderNode[]>();
  
  for (const node of nodes) {
    const existing = groups.get(node.lane) || [];
    existing.push(node);
    groups.set(node.lane, existing);
  }
  
  return groups;
}
