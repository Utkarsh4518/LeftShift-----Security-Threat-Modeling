/**
 * ExampleSelector - Cards for selecting example architectures.
 * 
 * Allows users to test without uploading their own file.
 * Shows example name, description, component count, and highlights.
 */

import type { ExampleArchitecture } from '../../compiler/types';
import { EXAMPLE_ARCHITECTURES } from '../../data/examples';

interface ExampleSelectorProps {
  onSelect: (example: ExampleArchitecture) => void;
  onBack: () => void;
  isLoading: boolean;
}

function ExampleCard({
  example,
  onSelect,
  isLoading,
}: {
  example: ExampleArchitecture;
  onSelect: () => void;
  isLoading: boolean;
}) {
  return (
    <div
      className={`
        bg-slate-800 rounded-xl border border-slate-700
        p-6 space-y-4
        transition-all duration-200
        ${isLoading ? 'opacity-50 cursor-not-allowed' : 'hover:border-blue-500 hover:shadow-lg cursor-pointer'}
      `}
      onClick={isLoading ? undefined : onSelect}
    >
      {/* Header */}
      <div className="flex items-start justify-between">
        <h3 className="text-lg font-semibold text-white">{example.name}</h3>
        <span className="px-2 py-1 text-xs font-medium bg-slate-700 text-slate-300 rounded">
          {example.componentCount} components
        </span>
      </div>

      {/* Description */}
      <p className="text-sm text-slate-400 leading-relaxed">{example.description}</p>

      {/* Highlights */}
      <div className="flex flex-wrap gap-2">
        {example.highlights.map((highlight, index) => (
          <span
            key={index}
            className="px-2 py-1 text-xs bg-slate-700/50 text-slate-300 rounded-full"
          >
            {highlight}
          </span>
        ))}
      </div>

      {/* Action */}
      <button
        disabled={isLoading}
        className={`
          w-full py-2 px-4 rounded-lg font-medium text-sm
          transition-all duration-200
          ${isLoading
            ? 'bg-slate-700 text-slate-500 cursor-not-allowed'
            : 'bg-blue-500/20 text-blue-400 hover:bg-blue-500/30 border border-blue-500/50'
          }
        `}
      >
        Use This Example
      </button>
    </div>
  );
}

export default function ExampleSelector({
  onSelect,
  onBack,
  isLoading,
}: ExampleSelectorProps) {
  return (
    <div className="max-w-4xl mx-auto p-6">
      {/* Header */}
      <div className="flex items-center gap-4 mb-8">
        <button
          onClick={onBack}
          disabled={isLoading}
          className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
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
          <h2 className="text-2xl font-bold text-white">Example Architectures</h2>
          <p className="text-slate-400">
            Select an example to see how the threat analysis works
          </p>
        </div>
      </div>

      {/* Example cards grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {EXAMPLE_ARCHITECTURES.map((example) => (
          <ExampleCard
            key={example.id}
            example={example}
            onSelect={() => onSelect(example)}
            isLoading={isLoading}
          />
        ))}
      </div>

      {/* Info note */}
      <div className="mt-8 p-4 rounded-lg bg-slate-800/50 border border-slate-700">
        <div className="flex items-start gap-3">
          <svg
            className="w-5 h-5 text-blue-400 mt-0.5"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
          <div>
            <p className="text-sm text-slate-300">
              These examples include pre-generated threat analysis results for demonstration.
              Upload your own architecture to get a real-time security assessment.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
