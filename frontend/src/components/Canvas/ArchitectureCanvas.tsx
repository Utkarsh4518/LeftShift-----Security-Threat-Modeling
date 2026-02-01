/**
 * ArchitectureCanvas - Main React Flow canvas for architecture visualization.
 * 
 * Features:
 * - Renders positioned nodes and edges
 * - Custom node and edge types
 * - Zoom and pan controls
 * - Node selection for threat panel
 */

import { useCallback, useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type OnSelectionChangeFunc,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import ComponentNode from './ComponentNode';
import DataFlowEdge from './DataFlowEdge';
import type { PositionedNode, PositionedEdge, RenderNode } from '../../compiler/types';

/** Custom node types - using any to bypass strict React Flow typing */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const nodeTypes: any = {
  componentNode: ComponentNode,
};

/** Custom edge types */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const edgeTypes: any = {
  dataFlowEdge: DataFlowEdge,
};

interface ArchitectureCanvasProps {
  nodes: PositionedNode[];
  edges: PositionedEdge[];
  onNodeSelect?: (node: RenderNode | null) => void;
}

/**
 * SVG marker definition for edge arrows.
 */
function ArrowMarker() {
  return (
    <svg style={{ position: 'absolute', width: 0, height: 0 }}>
      <defs>
        <marker
          id="arrow"
          viewBox="0 0 10 10"
          refX="8"
          refY="5"
          markerWidth="6"
          markerHeight="6"
          orient="auto-start-reverse"
        >
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
        </marker>
      </defs>
    </svg>
  );
}

export default function ArchitectureCanvas({
  nodes: initialNodes,
  edges: initialEdges,
  onNodeSelect,
}: ArchitectureCanvasProps) {
  // Convert to React Flow node format with proper typing
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const flowNodes: any[] = useMemo(
    () =>
      initialNodes.map((node) => ({
        ...node,
        type: 'componentNode',
      })),
    [initialNodes]
  );

  // Convert to React Flow edge format
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const flowEdges: any[] = useMemo(
    () =>
      initialEdges.map((edge) => ({
        ...edge,
        type: 'dataFlowEdge',
      })),
    [initialEdges]
  );

  const [nodes, , onNodesChange] = useNodesState(flowNodes);
  const [edges, , onEdgesChange] = useEdgesState(flowEdges);

  // Handle node selection
  const onSelectionChange: OnSelectionChangeFunc = useCallback(
    ({ nodes: selectedNodes }) => {
      if (selectedNodes.length > 0 && onNodeSelect) {
        const selectedNode = selectedNodes[0];
        onNodeSelect(selectedNode.data as unknown as RenderNode);
      } else if (onNodeSelect) {
        onNodeSelect(null);
      }
    },
    [onNodeSelect]
  );

  return (
    <div className="w-full h-full bg-slate-900">
      <ArrowMarker />
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onSelectionChange={onSelectionChange}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
        fitViewOptions={{
          padding: 0.2,
          maxZoom: 1.5,
        }}
        minZoom={0.1}
        maxZoom={2}
        defaultEdgeOptions={{
          type: 'dataFlowEdge',
        }}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#334155" gap={20} size={1} />
        <Controls
          className="!bg-slate-800 !border-slate-700 !rounded-lg"
          showZoom
          showFitView
          showInteractive={false}
        />
        <MiniMap
          className="!bg-slate-800 !border-slate-700 !rounded-lg"
          nodeColor={(node) => {
            const data = node.data as unknown as RenderNode;
            switch (data?.risk) {
              case 'Critical':
                return '#dc2626';
              case 'High':
                return '#ea580c';
              case 'Medium':
                return '#ca8a04';
              case 'Low':
                return '#16a34a';
              default:
                return '#64748b';
            }
          }}
          maskColor="rgba(15, 23, 42, 0.8)"
        />
      </ReactFlow>
    </div>
  );
}
