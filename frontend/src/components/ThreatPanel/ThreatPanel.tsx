/**
 * ThreatPanel - Side panel showing threats for a selected component.
 * 
 * Features:
 * - Displays all threats affecting the selected component
 * - Shows severity, description, and mitigation steps
 * - Animated slide-in from right
 */

import type { RenderNode, SentinelThreat, Severity } from '../../compiler/types';

interface ThreatPanelProps {
  node: RenderNode | null;
  onClose: () => void;
}

/** Severity badge styling */
const SEVERITY_STYLES: Record<Severity, string> = {
  Critical: 'bg-red-500/20 text-red-400 border-red-500',
  High: 'bg-orange-500/20 text-orange-400 border-orange-500',
  Medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500',
  Low: 'bg-green-500/20 text-green-400 border-green-500',
  None: 'bg-gray-500/20 text-gray-400 border-gray-500',
};

/** STRIDE category colors */
const STRIDE_COLORS: Record<string, string> = {
  Spoofing: 'text-purple-400',
  Tampering: 'text-red-400',
  Repudiation: 'text-yellow-400',
  'Information Disclosure': 'text-blue-400',
  'Denial of Service': 'text-orange-400',
  'Elevation of Privilege': 'text-pink-400',
};

function ThreatCard({ threat }: { threat: SentinelThreat }) {
  const severityStyle = SEVERITY_STYLES[threat.severity];
  const categoryColor = STRIDE_COLORS[threat.category] || 'text-gray-400';

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 p-4 space-y-3">
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-mono text-slate-400">{threat.threat_id}</span>
          <span className={`text-sm font-medium ${categoryColor}`}>
            {threat.category}
          </span>
        </div>
        <span
          className={`px-2 py-0.5 text-xs font-medium rounded border ${severityStyle}`}
        >
          {threat.severity}
        </span>
      </div>

      {/* Description */}
      <p className="text-sm text-slate-300 leading-relaxed">{threat.description}</p>

      {/* CWE ID if present */}
      {threat.cwe_id && (
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500">CWE:</span>
          <a
            href={`https://cwe.mitre.org/data/definitions/${threat.cwe_id.replace('CWE-', '')}.html`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-blue-400 hover:underline"
          >
            {threat.cwe_id}
          </a>
        </div>
      )}

      {/* Impact */}
      {threat.impact && (
        <div className="space-y-1">
          <span className="text-xs font-medium text-slate-400">Impact</span>
          <p className="text-sm text-slate-300">{threat.impact}</p>
        </div>
      )}

      {/* Mitigation steps */}
      {threat.mitigation_steps.length > 0 && (
        <div className="space-y-2">
          <span className="text-xs font-medium text-slate-400">Mitigation</span>
          <ul className="space-y-1">
            {threat.mitigation_steps.map((step, index) => (
              <li key={index} className="text-sm text-slate-300 flex items-start gap-2">
                <span className="text-emerald-400 mt-1">•</span>
                <span>{step}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default function ThreatPanel({ node, onClose }: ThreatPanelProps) {
  if (!node) return null;

  const { label, type, risk, threats } = node;

  return (
    <div
      className={`
        fixed right-0 top-0 h-full w-96
        bg-slate-900 border-l border-slate-700
        shadow-2xl overflow-hidden
        transform transition-transform duration-300
        ${node ? 'translate-x-0' : 'translate-x-full'}
        z-50
      `}
    >
      {/* Header */}
      <div className="sticky top-0 bg-slate-900 border-b border-slate-700 p-4 z-10">
        <div className="flex items-start justify-between">
          <div className="flex-1 min-w-0">
            <h2 className="text-lg font-semibold text-white truncate">{label}</h2>
            <p className="text-sm text-slate-400">{type}</p>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-white transition-colors"
            aria-label="Close panel"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              className="h-5 w-5"
              viewBox="0 0 20 20"
              fill="currentColor"
            >
              <path
                fillRule="evenodd"
                d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
                clipRule="evenodd"
              />
            </svg>
          </button>
        </div>

        {/* Risk summary */}
        <div className="mt-3 flex items-center gap-3">
          <div
            className={`
              px-3 py-1 rounded-full text-sm font-medium
              ${SEVERITY_STYLES[risk]}
            `}
          >
            {risk} Risk
          </div>
          <span className="text-sm text-slate-400">
            {threats.length} threat{threats.length !== 1 ? 's' : ''}
          </span>
        </div>
      </div>

      {/* Threats list */}
      <div className="p-4 space-y-4 overflow-y-auto h-[calc(100%-140px)]">
        {threats.length === 0 ? (
          <div className="text-center py-8 text-slate-500">
            <p>No threats identified for this component</p>
          </div>
        ) : (
          threats.map((threat) => <ThreatCard key={threat.threat_id} threat={threat} />)
        )}
      </div>
    </div>
  );
}
