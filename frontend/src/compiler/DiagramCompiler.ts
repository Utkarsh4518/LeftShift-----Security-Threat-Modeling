/**
 * DiagramCompiler - Transforms Sentinel analysis output into a RenderGraph.
 * 
 * This is a pure function that:
 * 1. Maps components to nodes with role and lane assignments
 * 2. Assigns nodes to domains based on their roles
 * 3. Attaches threat severity to each node
 * 4. Validates all edges (no dangling connections)
 * 5. Assigns edge indices for visual staggering
 * 6. Produces a deterministic, stable RenderGraph
 */

import type {
  SentinelAnalysisResult,
  SentinelThreat,
  RenderGraph,
  RenderNode,
  RenderEdge,
  Severity,
  EdgeType,
  RoutingDirection,
} from './types';
import { getLane, getComponentRole } from './roleMapper';
import { assignDomains, roleToDomain, DOMAIN_CONFIG } from './domainAssigner';

/**
 * Severity priority for determining highest risk.
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
 * Find a node by name with fuzzy matching.
 * Tries exact match first, then partial matches.
 */
function findNodeByName(
  name: string,
  nodeMap: Map<string, RenderNode>
): RenderNode | undefined {
  const normalized = normalizeId(name);
  
  // Try exact match first
  if (nodeMap.has(normalized)) {
    return nodeMap.get(normalized);
  }
  
  // Try partial match (source contains node name or vice versa)
  for (const [nodeId, node] of nodeMap.entries()) {
    if (normalized.includes(nodeId) || nodeId.includes(normalized)) {
      return node;
    }
  }
  
  return undefined;
}

/**
 * Find threats affecting a specific component.
 */
function findComponentThreats(
  componentName: string,
  threats: SentinelThreat[]
): SentinelThreat[] {
  const normalizedName = normalizeId(componentName);

  return threats.filter((threat) => {
    const affectedNormalized = normalizeId(threat.affected_component);
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
 * Classifies an edge based on source/target roles and protocol.
 */
function classifyEdge(
  sourceNode: RenderNode,
  targetNode: RenderNode,
  _protocol?: string
): EdgeType {
  const sourceRole = sourceNode.role;
  const targetRole = targetNode.role;

  // Primary: main business data flows
  if (sourceRole === 'external' || sourceRole === 'ingress') {
    if (targetRole === 'gateway' || targetRole === 'security' || targetRole === 'compute') {
      return 'primary';
    }
  }
  if (sourceRole === 'compute' && (targetRole === 'data' || targetRole === 'compute')) {
    return 'primary';
  }
  if (sourceRole === 'gateway' && targetRole !== 'monitoring') {
    return 'primary';
  }

  // Control: orchestration and messaging flows
  if (
    sourceRole === 'orchestration' ||
    targetRole === 'orchestration' ||
    sourceRole === 'messaging' ||
    targetRole === 'messaging'
  ) {
    return 'control';
  }

  // Infra: monitoring, logging, infrastructure
  if (
    targetRole === 'infra' ||
    targetRole === 'monitoring' ||
    sourceRole === 'infra'
  ) {
    return 'infra';
  }

  return 'secondary';
}

/**
 * Calculate edge index for staggering based on source-target pairs.
 * Edges between the same components (same source AND target) get different indices.
 * This prevents overlapping when multiple connections exist between the same components.
 */
function assignEdgeIndices(edges: RenderEdge[]): void {
  // Group edges by source-target pair (for edges between same components)
  const edgesByPair = new Map<string, RenderEdge[]>();
  
  for (const edge of edges) {
    // Create a key from both source and target
    const pairKey = `${normalizeId(edge.from)}->${normalizeId(edge.to)}`;
    const existing = edgesByPair.get(pairKey) || [];
    existing.push(edge);
    edgesByPair.set(pairKey, existing);
  }
  
  // Assign indices within each group (edges between same components)
  for (const pairEdges of edgesByPair.values()) {
    // Sort by protocol for consistent ordering
    pairEdges.sort((a, b) => (a.protocol || '').localeCompare(b.protocol || ''));
    
    const totalCount = pairEdges.length;
    pairEdges.forEach((edge, index) => {
      edge.edgeIndex = index;
      // Store total count for proper centering in stagger calculation
      (edge as any).totalEdgesInPair = totalCount;
    });
  }
}

/**
 * Calculate domain distance between source and target nodes.
 * Returns the absolute difference in grid positions.
 */
function calculateDomainDistance(sourceNode: RenderNode, targetNode: RenderNode): number {
  const sourceConfig = DOMAIN_CONFIG[sourceNode.domainId];
  const targetConfig = DOMAIN_CONFIG[targetNode.domainId];
  
  if (!sourceConfig || !targetConfig) {
    return 0;
  }
  
  return Math.abs(targetConfig.gridPosition - sourceConfig.gridPosition);
}

/**
 * Assign long-range edge properties for backbone routing.
 * Long-range edges (domain distance > 1) are routed through the backbone lane.
 */
function assignLongRangeRouting(edges: RenderEdge[], nodeMap: Map<string, RenderNode>): void {
  // Track which edges go above/below for alternating
  let aboveCount = 0;
  let belowCount = 0;
  
  for (const edge of edges) {
    const sourceNode = findNodeByName(edge.from, nodeMap);
    const targetNode = findNodeByName(edge.to, nodeMap);
    
    if (!sourceNode || !targetNode) continue;
    
    const distance = calculateDomainDistance(sourceNode, targetNode);
    edge.domainDistance = distance;
    
    // Long-range = distance > 1 (skips at least one domain)
    if (distance > 1) {
      edge.isLongRange = true;
      
      // Alternate routing direction to spread out backbone edges
      // Also consider edge type - primary edges go above, infra goes below
      let direction: RoutingDirection;
      
      if (edge.edgeType === 'primary' || edge.edgeType === 'control') {
        direction = 'above';
        edge.edgeIndex = aboveCount++;
      } else {
        direction = 'below';
        edge.edgeIndex = belowCount++;
      }
      
      edge.routingDirection = direction;
    } else {
      edge.isLongRange = false;
    }
  }
}

/**
 * Compiles the Sentinel analysis result into a RenderGraph.
 */
export function compileDiagram(analysisResult: SentinelAnalysisResult): RenderGraph {
  const { architecture, threats } = analysisResult;

  console.log('[DiagramCompiler] Input:', {
    projectName: architecture?.project_name,
    componentCount: architecture?.components?.length,
    flowCount: architecture?.data_flows?.length,
    threatCount: threats?.length,
  });

  // Build nodes with roles and domains
  const nodes: RenderNode[] = [];

  for (const component of architecture.components) {
    const role = getComponentRole(component.name, component.type);
    const lane = getLane(component.name, component.type);
    const domainId = roleToDomain(role);
    const componentThreats = findComponentThreats(component.name, threats);
    const risk = getHighestSeverity(componentThreats);

    nodes.push({
      id: component.name,
      label: component.name,
      type: component.type,
      role,
      lane,
      domainId,
      risk,
      threats: componentThreats,
    });
  }

  // Create node lookup for edge validation
  const nodeMap = new Map<string, RenderNode>(
    nodes.map((n) => [normalizeId(n.id), n])
  );

  // Process data flows into validated edges
  const edges: RenderEdge[] = [];
  const edgeSet = new Set<string>();
  let skippedEdges = 0;

  for (const flow of architecture.data_flows) {
    // Skip if missing source or destination
    if (!flow.source || !flow.destination) {
      skippedEdges++;
      continue;
    }

    // Find source and target nodes with fuzzy matching
    const sourceNode = findNodeByName(flow.source, nodeMap);
    const targetNode = findNodeByName(flow.destination, nodeMap);

    // CRITICAL: Skip edges where source or target doesn't exist
    if (!sourceNode) {
      console.warn(`[DiagramCompiler] Skipping edge: source "${flow.source}" not found`);
      skippedEdges++;
      continue;
    }
    
    if (!targetNode) {
      console.warn(`[DiagramCompiler] Skipping edge: target "${flow.destination}" not found`);
      skippedEdges++;
      continue;
    }

    // Skip self-loops
    if (sourceNode.id === targetNode.id) {
      continue;
    }

    // Create unique edge ID using actual node IDs and protocol (allow multiple edges between same components)
    const edgeId = flow.protocol 
      ? `${createEdgeId(sourceNode.id, targetNode.id)} (${flow.protocol})`
      : createEdgeId(sourceNode.id, targetNode.id);
    
    // Skip exact duplicates (same source, target, and protocol)
    if (edgeSet.has(edgeId)) {
      continue;
    }

    const edgeType = classifyEdge(sourceNode, targetNode, flow.protocol);

    edges.push({
      id: edgeId,
      from: sourceNode.id,  // Use actual node ID
      to: targetNode.id,    // Use actual node ID
      protocol: flow.protocol,
      edgeType,
      edgeIndex: 0, // Will be assigned later
    });
    edgeSet.add(edgeId);
  }

  // Assign edge indices for staggering overlapping edges
  assignEdgeIndices(edges);
  
  // Assign long-range routing for backbone edge routing
  assignLongRangeRouting(edges, nodeMap);

  if (skippedEdges > 0) {
    console.info(`[DiagramCompiler] Skipped ${skippedEdges} invalid edges`);
  }
  
  // Log long-range edge info for debugging
  const longRangeEdges = edges.filter(e => e.isLongRange);
  if (longRangeEdges.length > 0) {
    console.info(`[DiagramCompiler] ${longRangeEdges.length} long-range edges will use backbone routing`);
  }

  // Group nodes into domains
  const domains = assignDomains(nodes);

  console.log('[DiagramCompiler] Output:', {
    nodeCount: nodes.length,
    domainCount: domains.length,
    edgeCount: edges.length,
    domains: domains.map(d => ({ id: d.id, nodeCount: d.nodes.length })),
  });

  // Calculate threat statistics
  const criticalCount = threats.filter((t) => t.severity === 'Critical').length;
  const highCount = threats.filter((t) => t.severity === 'High').length;

  return {
    domains,
    nodes,
    edges,
    metadata: {
      projectName: architecture.project_name,
      description: architecture.description,
      trustBoundaries: architecture.trust_boundaries,
      totalThreats: threats.length,
      criticalCount,
      highCount,
    },
  };
}

/**
 * Sort nodes by lane for consistent rendering order.
 */
export function sortNodesByLane(nodes: RenderNode[]): RenderNode[] {
  return [...nodes].sort((a, b) => {
    if (a.lane !== b.lane) return a.lane - b.lane;
    return a.id.localeCompare(b.id);
  });
}

/**
 * Group nodes by lane.
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
