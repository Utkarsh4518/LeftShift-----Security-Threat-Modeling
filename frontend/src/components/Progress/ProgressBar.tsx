/**
 * ProgressBar - Shows analysis progress with pipeline stages.
 * 
 * Displays the current stage of the threat modeling pipeline
 * with animated progress indicator.
 */

import { memo } from 'react';

/**
 * Pipeline stages in order of execution.
 */
export const PIPELINE_STAGES = [
  { id: 'upload', label: 'Uploading', description: 'Sending architecture to server...' },
  { id: 'extraction', label: 'Extracting', description: 'Analyzing architecture components...' },
  { id: 'threats', label: 'Threat Analysis', description: 'Identifying STRIDE threats...' },
  { id: 'weaknesses', label: 'Weakness Detection', description: 'Finding architectural weaknesses...' },
  { id: 'cves', label: 'CVE Discovery', description: 'Searching vulnerability databases...' },
  { id: 'attacks', label: 'Attack Paths', description: 'Simulating attack scenarios...' },
  { id: 'report', label: 'Report Generation', description: 'Synthesizing final report...' },
  { id: 'layout', label: 'Rendering', description: 'Building visualization...' },
] as const;

export type PipelineStage = typeof PIPELINE_STAGES[number]['id'];

interface ProgressBarProps {
  currentStage: PipelineStage;
  /** Optional custom message to display */
  message?: string;
}

function ProgressBar({ currentStage, message }: ProgressBarProps) {
  const currentIndex = PIPELINE_STAGES.findIndex((s) => s.id === currentStage);
  const currentStageData = PIPELINE_STAGES[currentIndex];
  const progress = ((currentIndex + 1) / PIPELINE_STAGES.length) * 100;

  return (
    <div className="w-full max-w-lg mx-auto">
      {/* Progress bar container */}
      <div className="relative">
        {/* Background track */}
        <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
          {/* Progress fill */}
          <div
            className="h-full bg-gradient-to-r from-blue-500 to-cyan-400 transition-all duration-500 ease-out"
            style={{ width: `${progress}%` }}
          />
        </div>

        {/* Stage indicators */}
        <div className="absolute top-0 left-0 right-0 flex justify-between -mt-1">
          {PIPELINE_STAGES.map((stage, index) => {
            const isComplete = index < currentIndex;
            const isCurrent = index === currentIndex;
            
            return (
              <div
                key={stage.id}
                className={`
                  w-4 h-4 rounded-full border-2 transition-all duration-300
                  ${isComplete ? 'bg-blue-500 border-blue-500' : ''}
                  ${isCurrent ? 'bg-cyan-400 border-cyan-400 scale-125 animate-pulse' : ''}
                  ${!isComplete && !isCurrent ? 'bg-slate-700 border-slate-600' : ''}
                `}
                title={stage.label}
              />
            );
          })}
        </div>
      </div>

      {/* Stage labels */}
      <div className="mt-6 text-center">
        <p className="text-lg font-semibold text-white">
          {currentStageData?.label || 'Processing...'}
        </p>
        <p className="text-sm text-slate-400 mt-1">
          {message || currentStageData?.description}
        </p>
        <p className="text-xs text-slate-500 mt-2">
          Stage {currentIndex + 1} of {PIPELINE_STAGES.length}
        </p>
      </div>

      {/* Animated processing indicator */}
      <div className="flex justify-center mt-6 gap-1">
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className="w-2 h-2 rounded-full bg-blue-500 animate-bounce"
            style={{ animationDelay: `${i * 0.15}s` }}
          />
        ))}
      </div>
    </div>
  );
}

export default memo(ProgressBar);
