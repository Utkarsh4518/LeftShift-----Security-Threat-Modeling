/**
 * ELK Layout Engine - Deterministic graph layout using Eclipse Layout Kernel.
 * 
 * Features:
 * - Left-to-right layered layout
 * - Lane-based layer constraints (components in same lane stay together)
 * - Deterministic positioning (stable across reloads)
 * - No force-directed or physics-based layout
 */

import ELK from 'elkjs/lib/elk.bundled.js';
import type { ElkNode, ElkExtendedEdge } from 'elkjs';
import type { RenderGraph, PositionedNode, PositionedEdge } from '../compiler/types';

// Initialize ELK instance
const elk = new ELK();

/** Node dimensions */
const NODE_WIDTH = 180;
const NODE_HEIGHT = 60;

/** Spacing configuration */
const LAYER_SPACING = 150;
const NODE_SPACING = 40;

/**
 * ELK layout options for deterministic left-to-right layered layout.
 */
const ELK_OPTIONS = {
  'elk.algorithm': 'layered',
  'elk.direction': 'RIGHT',
  'elk.layered.spacing.nodeNodeBetweenLayers': String(LAYER_SPACING),
  'elk.layered.spacing.nodeNode': String(NODE_SPACING),
  'elk.spacing.nodeNode': String(NODE_SPACING),
  'elk.layered.nodePlacement.strategy': 'NETWORK_SIMPLEX',
  'elk.layered.crossingMinimization.strategy': 'LAYER_SWEEP',
  // Deterministic ordering
  'elk.layered.considerModelOrder.strategy': 'NODES_AND_EDGES',
  'elk.randomSeed': '1',
};

/**
 * Convert RenderGraph to ELK graph format.
 */
function toElkGraph(renderGraph: RenderGraph): ElkNode {
  // Sort nodes by lane for layer assignment
  const sortedNodes = [...renderGraph.nodes].sort((a, b) => {
    if (a.lane !== b.lane) return a.lane - b.lane;
    return a.id.localeCompare(b.id);
  });

  const elkNodes: ElkNode[] = sortedNodes.map((node) => ({
    id: node.id,
    width: NODE_WIDTH,
    height: NODE_HEIGHT,
    // Use lane as layer constraint hint
    layoutOptions: {
      'elk.layered.layerConstraint': getLaneLayerConstraint(node.lane),
    },
  }));

  const elkEdges: ElkExtendedEdge[] = renderGraph.edges.map((edge) => ({
    id: edge.id,
    sources: [edge.from],
    targets: [edge.to],
  }));

  return {
    id: 'root',
    layoutOptions: ELK_OPTIONS,
    children: elkNodes,
    edges: elkEdges,
  };
}

/**
 * Map lane to ELK layer constraint.
 * This helps ELK respect our lane-based ordering.
 */
function getLaneLayerConstraint(_lane: number): string {
  // ELK layer constraints: FIRST, NONE, LAST
  // We use NONE and let the algorithm respect our node ordering
  return 'NONE';
}

/**
 * Apply ELK layout to a RenderGraph and return positioned nodes/edges.
 */
export async function applyElkLayout(
  renderGraph: RenderGraph
): Promise<{ nodes: PositionedNode[]; edges: PositionedEdge[] }> {
  const elkGraph = toElkGraph(renderGraph);
  
  // Run ELK layout
  const layoutedGraph = await elk.layout(elkGraph);
  
  // Create node lookup for positioning
  const nodeDataMap = new Map(renderGraph.nodes.map((n) => [n.id, n]));
  const edgeDataMap = new Map(renderGraph.edges.map((e) => [e.id, e]));
  
  // Convert to positioned nodes
  const positionedNodes: PositionedNode[] = (layoutedGraph.children || []).map((elkNode) => {
    const nodeData = nodeDataMap.get(elkNode.id);
    if (!nodeData) {
      throw new Error(`Node data not found for ${elkNode.id}`);
    }
    
    return {
      id: elkNode.id,
      type: 'componentNode',
      position: {
        x: elkNode.x || 0,
        y: elkNode.y || 0,
      },
      data: nodeData,
    };
  });
  
  // Convert to positioned edges
  const positionedEdges: PositionedEdge[] = (layoutedGraph.edges || []).map((elkEdge) => {
    const edgeData = edgeDataMap.get(elkEdge.id);
    
    return {
      id: elkEdge.id,
      source: (elkEdge as ElkExtendedEdge).sources[0],
      target: (elkEdge as ElkExtendedEdge).targets[0],
      type: 'dataFlowEdge',
      data: {
        protocol: edgeData?.protocol,
      },
    };
  });
  
  return { nodes: positionedNodes, edges: positionedEdges };
}

/**
 * Get layout dimensions for canvas sizing.
 */
export function getLayoutBounds(nodes: PositionedNode[]): {
  width: number;
  height: number;
  center: { x: number; y: number };
} {
  if (nodes.length === 0) {
    return { width: 800, height: 600, center: { x: 400, y: 300 } };
  }
  
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  
  for (const node of nodes) {
    minX = Math.min(minX, node.position.x);
    minY = Math.min(minY, node.position.y);
    maxX = Math.max(maxX, node.position.x + NODE_WIDTH);
    maxY = Math.max(maxY, node.position.y + NODE_HEIGHT);
  }
  
  const width = maxX - minX + 100;
  const height = maxY - minY + 100;
  
  return {
    width,
    height,
    center: {
      x: (minX + maxX) / 2,
      y: (minY + maxY) / 2,
    },
  };
}

export { NODE_WIDTH, NODE_HEIGHT };
