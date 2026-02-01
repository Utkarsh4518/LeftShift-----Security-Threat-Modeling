/**
 * useAnalysis Hook - Manages async analysis state with progress tracking.
 * 
 * Features:
 * - Handles loading, error, and success states
 * - Tracks pipeline progress stages for user feedback
 * - Integrates with DiagramCompiler for RenderGraph generation
 * - Applies domain-based layout for visualization
 */

import { useState, useCallback, useRef } from 'react';
import type {
  AnalysisInput,
  AnalysisState,
  SentinelAnalysisResult,
  RenderGraph,
  PositionedNode,
  PositionedEdge,
  PositionedDomain,
} from '../compiler/types';
import { analyzeArchitecture } from '../api/analysisService';
import { compileDiagram } from '../compiler/DiagramCompiler';
import { applyElkLayout } from '../layout/elkLayout';
import type { PipelineStage } from '../components/Progress';

interface UseAnalysisResult {
  state: AnalysisState;
  stage: PipelineStage;
  result: SentinelAnalysisResult | null;
  renderGraph: RenderGraph | null;
  positionedDomains: PositionedDomain[];
  positionedNodes: PositionedNode[];
  positionedEdges: PositionedEdge[];
  analyze: (input: AnalysisInput) => Promise<void>;
  reset: () => void;
  loadFromResult: (result: SentinelAnalysisResult) => Promise<void>;
}

/**
 * Simulated stage durations for progress feedback.
 */
const STAGE_TIMINGS: Record<PipelineStage, number> = {
  upload: 500,
  extraction: 3000,
  threats: 8000,
  weaknesses: 4000,
  cves: 5000,
  attacks: 6000,
  report: 4000,
  layout: 500,
};

/**
 * Hook for managing architecture analysis and visualization.
 */
export function useAnalysis(): UseAnalysisResult {
  const [state, setState] = useState<AnalysisState>({ status: 'idle' });
  const [stage, setStage] = useState<PipelineStage>('upload');
  const [result, setResult] = useState<SentinelAnalysisResult | null>(null);
  const [renderGraph, setRenderGraph] = useState<RenderGraph | null>(null);
  const [positionedDomains, setPositionedDomains] = useState<PositionedDomain[]>([]);
  const [positionedNodes, setPositionedNodes] = useState<PositionedNode[]>([]);
  const [positionedEdges, setPositionedEdges] = useState<PositionedEdge[]>([]);
  
  const cancelledRef = useRef(false);

  /**
   * Simulate stage progression for user feedback.
   */
  const simulateProgress = useCallback(async () => {
    const stages: PipelineStage[] = [
      'upload',
      'extraction',
      'threats',
      'weaknesses',
      'cves',
      'attacks',
      'report',
    ];

    for (const stg of stages) {
      if (cancelledRef.current) return;
      setStage(stg);
      await sleep(STAGE_TIMINGS[stg]);
    }
  }, []);

  /**
   * Process analysis result into positioned visualization.
   */
  const processResult = useCallback(async (analysisResult: SentinelAnalysisResult) => {
    setStage('layout');
    
    // Step 1: Compile to RenderGraph with domains
    const graph = compileDiagram(analysisResult);
    setRenderGraph(graph);

    // Step 2: Apply domain-based layout
    const { domains, nodes, edges } = await applyElkLayout(graph);
    setPositionedDomains(domains);
    setPositionedNodes(nodes);
    setPositionedEdges(edges);
  }, []);

  /**
   * Submit input for analysis.
   */
  const analyze = useCallback(
    async (input: AnalysisInput) => {
      try {
        cancelledRef.current = false;
        setState({ status: 'uploading' });
        setStage('upload');

        // Start progress simulation in parallel
        const progressPromise = simulateProgress();

        // Call backend
        setState({ status: 'analyzing' });
        const analysisResult = await analyzeArchitecture(input);

        // Cancel progress simulation
        cancelledRef.current = true;

        // Store result
        setResult(analysisResult);

        // Process into visualization
        await processResult(analysisResult);

        // Wait for progress animation to complete minimum
        await progressPromise.catch(() => {});

        setState({ status: 'complete' });
      } catch (error) {
        cancelledRef.current = true;
        const message = error instanceof Error ? error.message : 'Analysis failed';
        setState({ status: 'error', error: message });
        console.error('Analysis error:', error);
      }
    },
    [processResult, simulateProgress]
  );

  /**
   * Load visualization from an existing result (e.g., example data).
   */
  const loadFromResult = useCallback(
    async (analysisResult: SentinelAnalysisResult) => {
      try {
        setState({ status: 'analyzing' });
        setStage('layout');
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
    cancelledRef.current = true;
    setState({ status: 'idle' });
    setStage('upload');
    setResult(null);
    setRenderGraph(null);
    setPositionedDomains([]);
    setPositionedNodes([]);
    setPositionedEdges([]);
  }, []);

  return {
    state,
    stage,
    result,
    renderGraph,
    positionedDomains,
    positionedNodes,
    positionedEdges,
    analyze,
    reset,
    loadFromResult,
  };
}

/**
 * Utility: sleep for specified milliseconds.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
