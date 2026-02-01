/**
 * useAnalysis Hook - Manages async analysis state.
 * 
 * Features:
 * - Handles loading, error, and success states
 * - Integrates with DiagramCompiler for RenderGraph generation
 * - Applies ELK layout to produce positioned nodes/edges
 */

import { useState, useCallback } from 'react';
import type {
  AnalysisInput,
  AnalysisState,
  SentinelAnalysisResult,
  RenderGraph,
  PositionedNode,
  PositionedEdge,
} from '../compiler/types';
import { analyzeArchitecture } from '../api/analysisService';
import { compileDiagram } from '../compiler/DiagramCompiler';
import { applyElkLayout } from '../layout/elkLayout';

interface UseAnalysisResult {
  state: AnalysisState;
  result: SentinelAnalysisResult | null;
  renderGraph: RenderGraph | null;
  positionedNodes: PositionedNode[];
  positionedEdges: PositionedEdge[];
  analyze: (input: AnalysisInput) => Promise<void>;
  reset: () => void;
  loadFromResult: (result: SentinelAnalysisResult) => Promise<void>;
}

/**
 * Hook for managing architecture analysis and visualization.
 */
export function useAnalysis(): UseAnalysisResult {
  const [state, setState] = useState<AnalysisState>({ status: 'idle' });
  const [result, setResult] = useState<SentinelAnalysisResult | null>(null);
  const [renderGraph, setRenderGraph] = useState<RenderGraph | null>(null);
  const [positionedNodes, setPositionedNodes] = useState<PositionedNode[]>([]);
  const [positionedEdges, setPositionedEdges] = useState<PositionedEdge[]>([]);

  /**
   * Process analysis result into positioned visualization.
   */
  const processResult = useCallback(async (analysisResult: SentinelAnalysisResult) => {
    // Step 1: Compile to RenderGraph
    const graph = compileDiagram(analysisResult);
    setRenderGraph(graph);

    // Step 2: Apply ELK layout
    const { nodes, edges } = await applyElkLayout(graph);
    setPositionedNodes(nodes);
    setPositionedEdges(edges);
  }, []);

  /**
   * Submit input for analysis.
   */
  const analyze = useCallback(
    async (input: AnalysisInput) => {
      try {
        setState({ status: 'uploading' });

        // Call backend
        setState({ status: 'analyzing' });
        const analysisResult = await analyzeArchitecture(input);

        // Store result
        setResult(analysisResult);

        // Process into visualization
        await processResult(analysisResult);

        setState({ status: 'complete' });
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Analysis failed';
        setState({ status: 'error', error: message });
        console.error('Analysis error:', error);
      }
    },
    [processResult]
  );

  /**
   * Load visualization from an existing result (e.g., example data).
   */
  const loadFromResult = useCallback(
    async (analysisResult: SentinelAnalysisResult) => {
      try {
        setState({ status: 'analyzing' });
        setResult(analysisResult);
        await processResult(analysisResult);
        setState({ status: 'complete' });
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to load result';
        setState({ status: 'error', error: message });
      }
    },
    [processResult]
  );

  /**
   * Reset to initial state.
   */
  const reset = useCallback(() => {
    setState({ status: 'idle' });
    setResult(null);
    setRenderGraph(null);
    setPositionedNodes([]);
    setPositionedEdges([]);
  }, []);

  return {
    state,
    result,
    renderGraph,
    positionedNodes,
    positionedEdges,
    analyze,
    reset,
    loadFromResult,
  };
}
