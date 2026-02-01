/**
 * App.tsx - Main application component for Left<<Shift Frontend.
 * 
 * Orchestrates the visualization workflow:
 * 1. Upload/Example selection
 * 2. Architecture visualization
 * 3. Threat panel and report preview
 */

import { useState, useCallback } from 'react';
import { ArchitectureCanvas } from './components/Canvas';
import { ThreatPanel } from './components/ThreatPanel';
import { ReportPreview } from './components/ReportPreview';
import { ThreatSelection } from './components/ThreatSelection';
import { UploadForm, ExampleSelector } from './components/Upload';
import { ProgressBar } from './components/Progress';
import StarsBackground from './components/StarsBackground';
import { useAnalysis } from './hooks';
import { getExampleAnalysisResult } from './data/examples';
import type { RenderNode, ExampleArchitecture, AnalysisInput } from './compiler/types';

type View = 'upload' | 'examples' | 'visualization';

export default function App() {
  const [view, setView] = useState<View>('upload');
  const [selectedNode, setSelectedNode] = useState<RenderNode | null>(null);
  const [isReportOpen, setIsReportOpen] = useState(false);

  const {
    state,
    stage,
    result,
    renderGraph,
    positionedDomains,
    positionedNodes,
    positionedEdges,
    analyze,
    loadFromResult,
    reset,
  } = useAnalysis();

  const isLoading = state.status === 'uploading' || state.status === 'analyzing';

  /**
   * Handle file upload submission.
   */
  const handleUpload = useCallback(
    async (input: AnalysisInput) => {
      await analyze(input);
      if (state.status !== 'error') {
        setView('visualization');
      }
    },
    [analyze, state.status]
  );

  /**
   * Handle example selection.
   */
  const handleExampleSelect = useCallback(
    async (example: ExampleArchitecture) => {
      const analysisResult = getExampleAnalysisResult(example.id);
      if (analysisResult) {
        await loadFromResult(analysisResult);
        setView('visualization');
      }
    },
    [loadFromResult]
  );

  /**
   * Handle node selection for threat panel.
   */
  const handleNodeSelect = useCallback((node: RenderNode | null) => {
    setSelectedNode(node);
  }, []);

  /**
   * Handle going back to upload.
   */
  const handleBack = useCallback(() => {
    reset();
    setSelectedNode(null);
    setView('upload');
  }, [reset]);

  /**
   * Get project name for display.
   */
  const projectName = renderGraph?.metadata.projectName || 'Architecture';

  return (
    <div className="min-h-screen bg-slate-900 text-white relative">
      {/* Stars Background */}
      <StarsBackground />

      {/* Header - shown in visualization view */}
      {view === 'visualization' && (
        <header className="fixed top-0 left-0 right-0 z-40 bg-slate-800/95 backdrop-blur border-b border-slate-700">
          <div className="flex items-center justify-between px-4 py-3">
            {/* Left: Back button and title */}
            <div className="flex items-center gap-4">
              <button
                onClick={handleBack}
                className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-700 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M15 19l-7-7 7-7"
                  />
                </svg>
              </button>
              <div>
                <h1 className="text-lg font-semibold">
                  Left<span className="text-blue-400">&lt;&lt;</span>Shift
                </h1>
                <p className="text-sm text-slate-400">{projectName}</p>
              </div>
            </div>

            {/* Right: Stats and actions */}
            <div className="flex items-center gap-4">
              {/* Threat stats */}
              {renderGraph && (
                <div className="flex items-center gap-3 text-sm">
                  {renderGraph.metadata.criticalCount > 0 && (
                    <span className="flex items-center gap-1 text-red-400">
                      <span className="w-2 h-2 rounded-full bg-red-500" />
                      {renderGraph.metadata.criticalCount} Critical
                    </span>
                  )}
                  {renderGraph.metadata.highCount > 0 && (
                    <span className="flex items-center gap-1 text-orange-400">
                      <span className="w-2 h-2 rounded-full bg-orange-500" />
                      {renderGraph.metadata.highCount} High
                    </span>
                  )}
                  <span className="text-slate-400">
                    {renderGraph.metadata.totalThreats} total threats
                  </span>
                </div>
              )}

              {/* Preview Report button */}
              {result?.report_markdown && (
                <button
                  onClick={() => setIsReportOpen(true)}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-500/20 text-blue-400 hover:bg-blue-500/30 border border-blue-500/50 transition-colors"
                >
                  <svg
                    className="w-4 h-4"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                    />
                  </svg>
                  <span className="text-sm font-medium">Preview Report</span>
                </button>
              )}

              {/* New Analysis button */}
              <button
                onClick={handleBack}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-700 text-slate-300 hover:bg-slate-600 transition-colors"
              >
                <svg
                  className="w-4 h-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 4v16m8-8H4"
                  />
                </svg>
                <span className="text-sm font-medium">New Analysis</span>
              </button>
            </div>
          </div>
        </header>
      )}

      {/* Main content */}
      <main className={view === 'visualization' ? 'pt-16' : ''}>
        {/* Upload view */}
        {view === 'upload' && (
          <div className="min-h-screen flex items-center justify-center">
            <UploadForm
              onSubmit={handleUpload}
              onShowExamples={() => setView('examples')}
              isLoading={isLoading}
            />
          </div>
        )}

        {/* Examples view */}
        {view === 'examples' && (
          <div className="min-h-screen py-12">
            <ExampleSelector
              onSelect={handleExampleSelect}
              onBack={() => setView('upload')}
              isLoading={isLoading}
            />
          </div>
        )}

        {/* Visualization view */}
        {view === 'visualization' && (
          <div className="relative">
            {/* Canvas */}
            <div
              className={`
                h-[calc(100vh-4rem)] transition-all duration-300
                ${selectedNode ? 'mr-96' : ''}
              `}
            >
              <ArchitectureCanvas
                domains={positionedDomains}
                nodes={positionedNodes}
                edges={positionedEdges}
                onNodeSelect={handleNodeSelect}
              />
            </div>

            {/* Threat panel */}
            <ThreatPanel node={selectedNode} onClose={() => setSelectedNode(null)} />

            {/* Threat Selection Section */}
            {result?.threats && result.threats.length > 0 && (
              <div className="border-t border-slate-700 bg-slate-900 p-6">
                <div className="container mx-auto max-w-7xl">
                  <ThreatSelection threats={result.threats} />
                </div>
              </div>
            )}
          </div>
        )}

        {/* Error state */}
        {state.status === 'error' && (
          <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50">
            <div className="px-6 py-3 rounded-lg bg-red-500/20 border border-red-500/50 text-red-400">
              <p className="text-sm">{state.error}</p>
            </div>
          </div>
        )}

        {/* Loading overlay with progress bar */}
        {isLoading && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/95 backdrop-blur-sm">
            <div className="w-full max-w-2xl px-8">
              {/* Logo */}
              <div className="text-center mb-8">
                <h1 className="text-3xl font-bold text-white">
                  Left<span className="text-blue-400">&lt;&lt;</span>Shift
                </h1>
                <p className="text-slate-400 mt-2">Security Threat Modeling</p>
              </div>

              {/* Progress bar */}
              <ProgressBar currentStage={stage} />

              {/* Estimated time */}
              <p className="text-center text-sm text-slate-500 mt-8">
                Full analysis typically takes 30-60 seconds
              </p>
            </div>
          </div>
        )}
      </main>

      {/* Report preview modal */}
      {result?.report_markdown && (
        <ReportPreview
          markdown={result.report_markdown}
          projectName={projectName}
          isOpen={isReportOpen}
          onClose={() => setIsReportOpen(false)}
        />
      )}
    </div>
  );
}
