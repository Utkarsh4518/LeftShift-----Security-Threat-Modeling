/**
 * DataFlowEdge - Smooth step edges that route around domain containers.
 * 
 * Features:
 * - Step routing with rounded corners
 * - Staggered vertical offsets to prevent overlapping
 * - Color-coded by edge type
 * - Always-visible protocol labels
 */

import { memo, useMemo } from 'react';
import { BaseEdge, EdgeLabelRenderer, getSmoothStepPath, type Position } from '@xyflow/react';
import type { EdgeType } from '../../compiler/types';

interface DataFlowEdgeData {
  protocol?: string;
  edgeType: EdgeType;
  collapsedCount?: number;
  edgeIndex?: number; // For staggering overlapping edges
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
    strokeWidth: 2.5,
    opacity: 0.95,
    glow: 'rgba(34, 211, 238, 0.3)',
    dashArray: '8 4',
  },
  control: {
    stroke: '#a78bfa', // Violet-400
    strokeWidth: 2,
    opacity: 0.85,
    glow: 'rgba(167, 139, 250, 0.2)',
    dashArray: '4 4',
  },
  secondary: {
    stroke: '#64748b', // Slate-500
    strokeWidth: 1.5,
    opacity: 0.7,
  },
  infra: {
    stroke: '#475569', // Slate-600
    strokeWidth: 1,
    opacity: 0.5,
    dashArray: '2 3',
  },
};

/**
 * Generate a deterministic offset based on edge ID to stagger overlapping edges.
 */
function getStaggerOffset(edgeId: string, edgeIndex?: number): number {
  // Use edge index if provided, otherwise hash the ID
  if (edgeIndex !== undefined) {
    // Stagger pattern: 0, 20, -20, 40, -40, etc.
    const sign = edgeIndex % 2 === 0 ? 1 : -1;
    const magnitude = Math.floor((edgeIndex + 1) / 2) * 20;
    return sign * magnitude;
  }
  
  // Fallback: hash the edge ID to get a consistent offset
  let hash = 0;
  for (let i = 0; i < edgeId.length; i++) {
    hash = ((hash << 5) - hash) + edgeId.charCodeAt(i);
    hash = hash & hash;
  }
  // Return offset between -40 and 40
  return (hash % 5) * 15 - 30;
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
  // Calculate staggered offset to prevent overlapping edges
  const staggerOffset = useMemo(() => {
    return getStaggerOffset(id, data?.edgeIndex);
  }, [id, data?.edgeIndex]);
  
  // Base offset + stagger for vertical separation
  const baseOffset = 30;
  const totalOffset = baseOffset + staggerOffset;
  
  // Use smooth step path - routes around obstacles with right angles
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    borderRadius: 12,
    offset: totalOffset,
  });

  const edgeType = data?.edgeType || 'secondary';
  const style = EDGE_STYLES[edgeType];
  const protocol = data?.protocol;
  const collapsedCount = data?.collapsedCount;

  // Show labels for all edges with protocols
  const showLabel = protocol || (collapsedCount && collapsedCount > 1);

  return (
    <>
      {/* Glow effect for highlighted edges */}
      {style.glow && (
        <BaseEdge
          id={`${id}-glow`}
          path={edgePath}
          style={{
            stroke: style.glow,
            strokeWidth: style.strokeWidth + 4,
            strokeLinecap: 'round',
            filter: 'blur(3px)',
            opacity: selected ? 0.8 : 0.5,
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
          animation: edgeType === 'primary' ? 'flowDash 1.5s linear infinite' : undefined,
        }}
        markerEnd="url(#flowArrow)"
      />

      {/* Protocol/flow label - always visible */}
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
