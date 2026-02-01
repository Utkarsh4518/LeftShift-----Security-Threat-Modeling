/**
 * DataFlowEdge - Custom React Flow edge for data flows.
 * 
 * Features:
 * - Animated stroke drawing from left to right
 * - Protocol label on hover
 * - Smooth bezier curve
 */

import { memo } from 'react';
import { BaseEdge, EdgeLabelRenderer, getBezierPath, type Position } from '@xyflow/react';

interface DataFlowEdgeData {
  protocol?: string;
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
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const protocol = data?.protocol;

  return (
    <>
      {/* Background edge for better visibility */}
      <BaseEdge
        id={`${id}-bg`}
        path={edgePath}
        style={{
          stroke: 'rgba(100, 116, 139, 0.3)',
          strokeWidth: 8,
        }}
      />
      
      {/* Main animated edge */}
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          stroke: selected ? '#60a5fa' : '#64748b',
          strokeWidth: 2,
          strokeDasharray: 1000,
          strokeDashoffset: 1000,
          animation: 'drawEdge 0.8s ease-out forwards',
          animationDelay: '0.5s',
        }}
        markerEnd="url(#arrow)"
      />
      
      {/* Protocol label */}
      {protocol && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
              pointerEvents: 'all',
            }}
            className={`
              px-2 py-1 rounded text-xs
              bg-slate-700 text-slate-300
              border border-slate-600
              opacity-0 hover:opacity-100
              transition-opacity duration-200
              ${selected ? 'opacity-100' : ''}
            `}
          >
            {protocol}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

export default memo(DataFlowEdge);
