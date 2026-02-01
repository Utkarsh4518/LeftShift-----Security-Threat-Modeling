/**
 * ArchitectureCanvas - Main React Flow canvas for architecture visualization.
 * 
 * Features:
 * - Renders domains as containers with nodes inside
 * - Custom node and edge types
 * - Zoom and pan controls
 * - Minimap for navigation
 */

import { useCallback, useMemo, useEffect } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type OnSelectionChangeFunc,
  BackgroundVariant,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import ComponentNode from './ComponentNode';
import DataFlowEdge from './DataFlowEdge';
import DomainContainer from './DomainContainer';
import type { 
  RenderNode, 
  PositionedNode, 
  PositionedEdge, 
  PositionedDomain 
} from '../../compiler/types';

/** Custom node types - using any to allow typed data in custom nodes */
const nodeTypes: Record<string, React.ComponentType<any>> = {
  componentNode: ComponentNode,
  domainContainer: DomainContainer,
};

/** Custom edge types */
const edgeTypes: Record<string, React.ComponentType<any>> = {
  dataFlowEdge: DataFlowEdge,
};

interface ArchitectureCanvasProps {
  domains: PositionedDomain[];
  nodes: PositionedNode[];
  edges: PositionedEdge[];
  onNodeSelect?: (node: RenderNode | null) => void;
}

/**
 * SVG marker definitions for edge arrows.
 */
function ArrowMarkers() {
  return (
    <svg style={{ position: 'absolute', width: 0, height: 0 }}>
      <defs>
        {/* Standard arrow */}
        <marker
          id="arrow"
          viewBox="0 0 10 10"
          refX="8"
          refY="5"
          markerWidth="5"
          markerHeight="5"
          orient="auto-start-reverse"
        >
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
        </marker>
        {/* Flow arrow - cyan for primary flows */}
        <marker
          id="flowArrow"
          viewBox="0 0 10 10"
          refX="9"
          refY="5"
          markerWidth="4"
          markerHeight="4"
          orient="auto-start-reverse"
        >
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#22d3ee" />
        </marker>
      </defs>
    </svg>
  );
}

export default function ArchitectureCanvas({
  domains: initialDomains,
  nodes: initialNodes,
  edges: initialEdges,
  onNodeSelect,
}: ArchitectureCanvasProps) {
  // Combine domains and nodes for React Flow
  const flowNodes = useMemo(() => {
    // Domains first (they are parent containers)
    const domainNodes = initialDomains.map((domain) => ({
      id: domain.id,
      type: 'domainContainer' as const,
      position: domain.position,
      data: domain.data,
      style: domain.style,
      draggable: false,
      selectable: false,
      zIndex: 0,
    }));
    
    // Component nodes (children of domains)
    const componentNodes = initialNodes.map((node) => ({
      id: node.id,
      type: 'componentNode' as const,
      position: node.position,
      data: node.data,
      parentId: node.parentId,
      extent: node.extent,
      draggable: false,
      zIndex: 10,
    }));
    
    return [...domainNodes, ...componentNodes];
  }, [initialDomains, initialNodes]);

  // Convert to React Flow edge format
  const flowEdges = useMemo(
    () =>
      initialEdges.map((edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        type: 'dataFlowEdge' as const,
        data: edge.data,
        zIndex: 5,
      })),
    [initialEdges]
  );

  const [nodes, setNodes, onNodesChange] = useNodesState(flowNodes as any);
  const [edges, setEdges, onEdgesChange] = useEdgesState(flowEdges as any);

  // Update when props change
  useEffect(() => {
    setNodes(flowNodes as any);
    setEdges(flowEdges as any);
  }, [flowNodes, flowEdges, setNodes, setEdges]);

  // Handle node selection
  const onSelectionChange: OnSelectionChangeFunc = useCallback(
    ({ nodes: selectedNodes }) => {
      if (!onNodeSelect) return;
      
      if (selectedNodes.length > 0) {
        const selectedNode = selectedNodes[0];
        // Only allow selection of component nodes
        if (selectedNode.type === 'componentNode') {
          onNodeSelect(selectedNode.data as unknown as RenderNode);
        } else {
          onNodeSelect(null);
        }
      } else {
        onNodeSelect(null);
      }
    },
    [onNodeSelect]
  );

  return (
    <div className="w-full h-full bg-slate-900">
      <ArrowMarkers />
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
          padding: 0.15,
          maxZoom: 1.2,
        }}
        minZoom={0.2}
        maxZoom={2}
        defaultEdgeOptions={{
          type: 'dataFlowEdge',
        }}
        proOptions={{ hideAttribution: true }}
      >
        <Background 
          color="#334155" 
          variant={BackgroundVariant.Dots} 
          gap={16} 
          size={1} 
        />
        <Controls
          className="!bg-slate-800 !border-slate-700 !rounded-lg"
          showZoom
          showFitView
          showInteractive={false}
        />
        <MiniMap
          className="!bg-slate-800 !border-slate-700 !rounded-lg"
          nodeColor={(node) => {
            if (node.type === 'componentNode') {
              const data = node.data as unknown as RenderNode;
              switch (data?.risk) {
                case 'Critical': return '#ef4444';
                case 'High': return '#f97316';
                case 'Medium': return '#eab308';
                case 'Low': return '#22c55e';
                default: return '#64748b';
              }
            }
            return 'rgba(51, 65, 85, 0.5)'; // Domain containers
          }}
          maskColor="rgba(15, 23, 42, 0.8)"
        />
      </ReactFlow>
    </div>
  );
}
