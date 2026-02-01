/**
 * DataFlowEdge - Custom edge routing with backbone lane for long-range connections.
 * 
 * Features:
 * - Adjacent domains: Normal smooth step routing
 * - Long-range edges: Route through backbone lane above/below domains
 * - Staggered offsets to prevent overlapping in backbone
 * - Color-coded by edge type
 * - Always-visible protocol labels
 */

import { memo, useMemo } from 'react';
import { BaseEdge, EdgeLabelRenderer, getSmoothStepPath, type Position } from '@xyflow/react';
import type { EdgeType, RoutingDirection } from '../../compiler/types';

interface DataFlowEdgeData {
  protocol?: string;
  edgeType: EdgeType;
  collapsedCount?: number;
  edgeIndex?: number;
  isLongRange?: boolean;
  routingDirection?: RoutingDirection;
  domainDistance?: number;
  domainBounds?: {
    topY: number;
    bottomY: number;
  };
  totalEdgesInPair?: number; // Total edges between same source-target pair
}

interface DataFlowEdgeProps {
  id: string;
  sourceX: number;
  sourceY: number;
  targetX: number;
  targetY: number;
  sourcePosition: Position;
  targetPosition: Position;
  data?: DataFlowEdgeData;
  selected?: boolean;
}

/**
 * Edge style configuration.
 */
const EDGE_STYLES: Record<EdgeType, {
  stroke: string;
  strokeWidth: number;
  opacity: number;
  glow?: string;
  dashArray?: string;
}> = {
  primary: {
    stroke: '#22d3ee', // Cyan-400
    strokeWidth: 3,    // Increased from 2.5
    opacity: 1.0,       // Full opacity for maximum visibility
    glow: 'rgba(34, 211, 238, 0.4)', // Increased glow intensity
    dashArray: '8 4',
  },
  control: {
    stroke: '#a78bfa', // Violet-400
    strokeWidth: 2.5,  // Increased from 2
    opacity: 1.0,       // Full opacity
    glow: 'rgba(167, 139, 250, 0.3)', // Increased glow intensity
    dashArray: '4 4',
  },
  secondary: {
    stroke: '#cbd5e1', // Slate-300 (much brighter for high visibility)
    strokeWidth: 2.5,  // Increased from 2
    opacity: 1.0,       // Full opacity
    glow: 'rgba(203, 213, 225, 0.25)', // Added glow effect
    dashArray: '6 4',  // Added for animation effect
  },
  infra: {
    stroke: '#94a3b8', // Slate-400 (brighter)
    strokeWidth: 2.5,   // Increased from 2
    opacity: 1.0,       // Full opacity
    glow: 'rgba(148, 163, 184, 0.2)', // Added glow effect
    dashArray: '2 3',
  },
};

/** Backbone routing configuration */
const BACKBONE_CONFIG = {
  /** Base offset from domain edge to backbone lane */
  BASE_OFFSET: 60,
  /** Additional offset per edge index for staggering */
  STAGGER_OFFSET: 18,
  /** Horizontal padding before turning up/down */
  CORNER_OFFSET: 30,  // Increased from 15px to keep curves away from domain boundaries
  /** Border radius for corners */
  CORNER_RADIUS: 8,
};

/**
 * Generate a custom path for long-range edges through the backbone lane.
 * 
 * Path structure:
 * 1. Horizontal from source
 * 2. Vertical to backbone lane
 * 3. Horizontal across backbone
 * 4. Vertical from backbone to target level
 * 5. Horizontal to target
 */
function generateBackbonePath(
  sourceX: number,
  sourceY: number,
  targetX: number,
  targetY: number,
  direction: RoutingDirection,
  domainBounds: { topY: number; bottomY: number },
  edgeIndex: number = 0
): { path: string; labelX: number; labelY: number } {
  const { BASE_OFFSET, STAGGER_OFFSET, CORNER_OFFSET, CORNER_RADIUS } = BACKBONE_CONFIG;
  
  // Calculate backbone Y position with staggering
  const staggeredOffset = BASE_OFFSET + (edgeIndex * STAGGER_OFFSET);
  const backboneY = direction === 'above'
    ? domainBounds.topY - staggeredOffset
    : domainBounds.bottomY + staggeredOffset;
  
  // Calculate intermediate points
  const exitX = sourceX + CORNER_OFFSET;
  const entryX = targetX - CORNER_OFFSET;
  
  // Build SVG path with rounded corners
  // We use quadratic bezier curves (Q) for smooth corners
  const r = CORNER_RADIUS;
  
  let path: string;
  
  if (direction === 'above') {
    // Route above: source → up → across → down → target
    path = [
      `M ${sourceX} ${sourceY}`,           // Start at source
      `L ${exitX - r} ${sourceY}`,          // Horizontal to first corner
      `Q ${exitX} ${sourceY} ${exitX} ${sourceY - r}`, // Corner up
      `L ${exitX} ${backboneY + r}`,        // Vertical to backbone
      `Q ${exitX} ${backboneY} ${exitX + r} ${backboneY}`, // Corner right
      `L ${entryX - r} ${backboneY}`,       // Horizontal across backbone
      `Q ${entryX} ${backboneY} ${entryX} ${backboneY + r}`, // Corner down
      `L ${entryX} ${targetY - r}`,         // Vertical to target level
      `Q ${entryX} ${targetY} ${entryX + r} ${targetY}`, // Corner right
      `L ${targetX} ${targetY}`,            // Horizontal to target
    ].join(' ');
  } else {
    // Route below: source → down → across → up → target
    path = [
      `M ${sourceX} ${sourceY}`,           // Start at source
      `L ${exitX - r} ${sourceY}`,          // Horizontal to first corner
      `Q ${exitX} ${sourceY} ${exitX} ${sourceY + r}`, // Corner down
      `L ${exitX} ${backboneY - r}`,        // Vertical to backbone
      `Q ${exitX} ${backboneY} ${exitX + r} ${backboneY}`, // Corner right
      `L ${entryX - r} ${backboneY}`,       // Horizontal across backbone
      `Q ${entryX} ${backboneY} ${entryX} ${backboneY - r}`, // Corner up
      `L ${entryX} ${targetY + r}`,         // Vertical to target level
      `Q ${entryX} ${targetY} ${entryX + r} ${targetY}`, // Corner right
      `L ${targetX} ${targetY}`,            // Horizontal to target
    ].join(' ');
  }
  
  // Label position: middle of the backbone horizontal segment
  const labelX = (exitX + entryX) / 2;
  const labelY = backboneY;
  
  return { path, labelX, labelY };
}

/**
 * Generate a deterministic offset for adjacent edge staggering.
 * Ensures edges between the same components are properly spaced.
 */
function getAdjacentStaggerOffset(edgeId: string, edgeIndex?: number, totalEdgesBetweenSamePair?: number): number {
  // If we have edgeIndex, use it for proper staggering
  if (edgeIndex !== undefined) {
    // For multiple edges between same components, stagger them vertically
    // Center the first edge (index 0) and alternate above/below for others
    if (totalEdgesBetweenSamePair && totalEdgesBetweenSamePair > 1) {
      // Multiple edges: center them around 0
      const centerIndex = Math.floor((totalEdgesBetweenSamePair - 1) / 2);
      const offsetFromCenter = edgeIndex - centerIndex;
      return offsetFromCenter * 30; // 30px spacing between edges
    } else {
      // Single edge: use small hash-based offset to avoid overlap
      let hash = 0;
      for (let i = 0; i < edgeId.length; i++) {
        hash = ((hash << 5) - hash) + edgeId.charCodeAt(i);
        hash = hash & hash;
      }
      return (hash % 3) * 15 - 15; // Small offset between -15 and +15
    }
  }
  
  // Fallback: use hash-based offset
  let hash = 0;
  for (let i = 0; i < edgeId.length; i++) {
    hash = ((hash << 5) - hash) + edgeId.charCodeAt(i);
    hash = hash & hash;
  }
  return (hash % 3) * 15 - 15;
}

function DataFlowEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  selected,
}: DataFlowEdgeProps) {
  // Determine if this is a long-range edge requiring backbone routing
  const isLongRange = data?.isLongRange ?? false;
  const routingDirection = data?.routingDirection ?? 'above';
  const domainBounds = data?.domainBounds;
  const edgeIndex = data?.edgeIndex ?? 0;
  
  // Calculate edge path based on routing type
  const { edgePath, labelX, labelY } = useMemo(() => {
    if (isLongRange && domainBounds) {
      // Long-range: use backbone routing
      const { path, labelX, labelY } = generateBackbonePath(
        sourceX,
        sourceY,
        targetX,
        targetY,
        routingDirection,
        domainBounds,
        edgeIndex
      );
      return { edgePath: path, labelX, labelY };
    } else {
      // Adjacent: use standard smooth step with stagger offset
      const totalEdgesInPair = data?.totalEdgesInPair;
      const staggerOffset = getAdjacentStaggerOffset(id, edgeIndex, totalEdgesInPair);
      const totalOffset = 40 + staggerOffset;  // Increased from 25px to keep curves away from domains
      
      const [path, lx, ly] = getSmoothStepPath({
        sourceX,
        sourceY,
        sourcePosition,
        targetX,
        targetY,
        targetPosition,
        borderRadius: 12,
        offset: totalOffset,
      });
      
      return { edgePath: path, labelX: lx, labelY: ly };
    }
  }, [
    isLongRange,
    routingDirection,
    domainBounds,
    edgeIndex,
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    id,
  ]);

  const edgeType = data?.edgeType || 'secondary';
  const style = EDGE_STYLES[edgeType] || {
    stroke: '#cbd5e1', // Brighter default color
    strokeWidth: 2.5,
    opacity: 1.0, // Full opacity
    glow: 'rgba(203, 213, 225, 0.25)', // Default glow
  };
  const protocol = data?.protocol;
  const collapsedCount = data?.collapsedCount;

  // Show labels for all edges with protocols
  const showLabel = protocol || (collapsedCount && collapsedCount > 1);

  return (
    <>
      {/* Glow effect for all edges - improved visibility */}
      {style.glow && (
        <BaseEdge
          id={`${id}-glow`}
          path={edgePath}
          style={{
            stroke: style.glow,
            strokeWidth: style.strokeWidth + 5, // Increased glow width
            strokeLinecap: 'round',
            filter: 'blur(4px)', // Increased blur for more visible glow
            opacity: selected ? 0.9 : 0.6, // Increased opacity for better visibility
          }}
        />
      )}

      {/* Main edge path */}
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          stroke: selected ? '#f97316' : style.stroke,
          strokeWidth: selected ? style.strokeWidth + 0.5 : style.strokeWidth,
          strokeLinecap: 'round',
          strokeLinejoin: 'round',
          opacity: selected ? 1 : style.opacity,
          strokeDasharray: style.dashArray,
          animation: style.dashArray 
            ? `flowDash ${edgeType === 'primary' ? '1.5s' : edgeType === 'control' ? '1.8s' : edgeType === 'secondary' ? '2s' : '2.2s'} linear infinite`
            : undefined,
        }}
        markerEnd="url(#flowArrow)"
      />

      {/* Protocol/flow label */}
      {showLabel && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
              pointerEvents: 'all',
              zIndex: 1000,
            }}
            className={`
              px-2 py-0.5 rounded
              bg-slate-900/95 backdrop-blur-sm
              border border-slate-600/60
              text-[10px] text-slate-300
              shadow-md
              whitespace-nowrap
              ${selected ? 'border-orange-500/50' : ''}
              ${isLongRange ? 'border-dashed' : ''}
            `}
          >
            {protocol && (
              <span className="font-mono">{protocol}</span>
            )}
            {collapsedCount && collapsedCount > 1 && (
              <span className="text-slate-500 ml-1">
                ×{collapsedCount}
              </span>
            )}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

export default memo(DataFlowEdge);
