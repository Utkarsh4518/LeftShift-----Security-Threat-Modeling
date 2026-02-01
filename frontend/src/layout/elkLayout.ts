/**
 * ELK Layout Engine - Domain-aware graph layout.
 * 
 * Layout strategy:
 * 1. Place domains on a horizontal grid (left to right)
 * 2. Layout nodes vertically within each domain with proper spacing
 * 3. Ensure all nodes fit within their domain containers
 */

import type { 
  RenderGraph, 
  PositionedNode, 
  PositionedEdge, 
  PositionedDomain,
  RenderNode,
} from '../compiler/types';

/** Layout configuration */
const CONFIG = {
  // Domain dimensions
  DOMAIN_MIN_WIDTH: 200,
  DOMAIN_MIN_HEIGHT: 150,
  DOMAIN_PADDING_X: 20,
  DOMAIN_PADDING_TOP: 55,    // Space for header
  DOMAIN_PADDING_BOTTOM: 20,
  DOMAIN_SPACING: 100,       // INCREASED: More space for edge routing and labels
  
  // Node dimensions
  NODE_WIDTH: 160,
  NODE_HEIGHT: 50,
  NODE_SPACING: 16,
  
  // Canvas padding
  CANVAS_PADDING: 50,
};

/**
 * Calculate the height needed for a domain based on its nodes.
 */
function calculateDomainHeight(nodeCount: number): number {
  if (nodeCount === 0) return CONFIG.DOMAIN_MIN_HEIGHT;
  
  const contentHeight = 
    nodeCount * CONFIG.NODE_HEIGHT + 
    (nodeCount - 1) * CONFIG.NODE_SPACING;
  
  return Math.max(
    CONFIG.DOMAIN_MIN_HEIGHT,
    contentHeight + CONFIG.DOMAIN_PADDING_TOP + CONFIG.DOMAIN_PADDING_BOTTOM
  );
}

/**
 * Calculate node positions within a domain (vertical stack).
 */
function layoutNodesInDomain(
  nodes: RenderNode[],
  domainWidth: number
): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();
  
  // Center nodes horizontally, stack vertically
  const startX = (domainWidth - CONFIG.NODE_WIDTH) / 2;
  let currentY = CONFIG.DOMAIN_PADDING_TOP;
  
  for (const node of nodes) {
    positions.set(node.id, { x: startX, y: currentY });
    currentY += CONFIG.NODE_HEIGHT + CONFIG.NODE_SPACING;
  }
  
  return positions;
}

/**
 * Apply domain-based layout to a RenderGraph.
 */
export async function applyElkLayout(
  renderGraph: RenderGraph
): Promise<{
  domains: PositionedDomain[];
  nodes: PositionedNode[];
  edges: PositionedEdge[];
}> {
  const positionedDomains: PositionedDomain[] = [];
  const positionedNodes: PositionedNode[] = [];
  
  let currentX = CONFIG.CANVAS_PADDING;
  let maxHeight = 0;
  
  // First pass: calculate all domain heights to find max
  for (const domain of renderGraph.domains) {
    const height = calculateDomainHeight(domain.nodes.length);
    maxHeight = Math.max(maxHeight, height);
  }
  
  // Second pass: create positioned domains and nodes
  for (const domain of renderGraph.domains) {
    const domainWidth = CONFIG.NODE_WIDTH + CONFIG.DOMAIN_PADDING_X * 2;
    const domainHeight = maxHeight; // Use max height for uniform appearance
    
    // Layout nodes within this domain
    const nodePositions = layoutNodesInDomain(domain.nodes, domainWidth);
    
    // Create positioned domain
    const positionedDomain: PositionedDomain = {
      id: `domain-${domain.id}`,
      type: 'domainContainer',
      position: { x: currentX, y: CONFIG.CANVAS_PADDING },
      data: {
        ...domain,
        size: { width: domainWidth, height: domainHeight },
      },
      style: { width: domainWidth, height: domainHeight },
    };
    
    positionedDomains.push(positionedDomain);
    
    // Create positioned nodes (positions are relative to domain)
    for (const node of domain.nodes) {
      const nodePos = nodePositions.get(node.id);
      if (nodePos) {
        const positionedNode: PositionedNode = {
          id: node.id,
          type: 'componentNode',
          position: nodePos,
          data: node,
          parentId: `domain-${domain.id}`,
          extent: 'parent',
        };
        positionedNodes.push(positionedNode);
      }
    }
    
    currentX += domainWidth + CONFIG.DOMAIN_SPACING;
  }
  
  // Calculate domain bounds for backbone routing
  const domainBounds = {
    topY: CONFIG.CANVAS_PADDING,
    bottomY: CONFIG.CANVAS_PADDING + maxHeight,
  };
  
  // Create maps for node ID validation and lookup (case-insensitive)
  const nodeIdMap = new Map<string, string>(); // lowercase -> actual ID
  for (const node of positionedNodes) {
    nodeIdMap.set(node.id.toLowerCase(), node.id);
  }
  
  // Create positioned edges - ONLY for edges with valid endpoints
  const positionedEdges: PositionedEdge[] = [];
  let skippedEdges = 0;
  
  for (const edge of renderGraph.edges) {
    const sourceId = nodeIdMap.get(edge.from.toLowerCase());
    const targetId = nodeIdMap.get(edge.to.toLowerCase());
    
    // Skip edges where source or target doesn't exist as a positioned node
    if (!sourceId) {
      console.warn(`[elkLayout] Skipping edge: source "${edge.from}" not positioned`);
      skippedEdges++;
      continue;
    }
    
    if (!targetId) {
      console.warn(`[elkLayout] Skipping edge: target "${edge.to}" not positioned`);
      skippedEdges++;
      continue;
    }
    
    // Use the actual positioned node IDs (preserving case)
    positionedEdges.push({
      id: edge.id,
      source: sourceId,
      target: targetId,
      type: 'dataFlowEdge',
      data: {
        protocol: edge.protocol,
        edgeType: edge.edgeType,
        collapsedCount: edge.collapsedCount,
        edgeIndex: edge.edgeIndex,
        isLongRange: edge.isLongRange,
        routingDirection: edge.routingDirection,
        domainDistance: edge.domainDistance,
        domainBounds,
      },
    });
  }
  
  if (skippedEdges > 0) {
    console.info(`[elkLayout] Skipped ${skippedEdges} edges with invalid endpoints`);
  }
  
  console.log('[elkLayout] Output:', {
    domainCount: positionedDomains.length,
    nodeCount: positionedNodes.length,
    edgeCount: positionedEdges.length,
    domains: positionedDomains.map(d => ({ id: d.id, pos: d.position })),
  });
  
  return { domains: positionedDomains, nodes: positionedNodes, edges: positionedEdges };
}

/**
 * Get layout dimensions for canvas sizing.
 */
export function getLayoutBounds(domains: PositionedDomain[]): {
  width: number;
  height: number;
  center: { x: number; y: number };
} {
  if (domains.length === 0) {
    return { width: 800, height: 600, center: { x: 400, y: 300 } };
  }
  
  let maxX = 0;
  let maxY = 0;
  
  for (const domain of domains) {
    const rightEdge = domain.position.x + (domain.style?.width || 200);
    const bottomEdge = domain.position.y + (domain.style?.height || 200);
    maxX = Math.max(maxX, rightEdge);
    maxY = Math.max(maxY, bottomEdge);
  }
  
  const width = maxX + CONFIG.CANVAS_PADDING;
  const height = maxY + CONFIG.CANVAS_PADDING;
  
  return {
    width,
    height,
    center: {
      x: width / 2,
      y: height / 2,
    },
  };
}

export { CONFIG as LAYOUT_CONFIG };
