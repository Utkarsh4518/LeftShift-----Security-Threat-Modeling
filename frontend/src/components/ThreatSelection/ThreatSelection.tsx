/**
 * ThreatSelection - Component for selecting threats and creating Jira tickets.
 * 
 * Features:
 * - List of all threats with checkboxes
 * - Select/deselect individual threats
 * - Create Jira tickets button (POST to n8n endpoint)
 */

import { useState, useCallback } from 'react';
import type { SentinelThreat } from '../../compiler/types';

interface ThreatSelectionProps {
  threats: SentinelThreat[];
}

/** Severity badge styling */
const SEVERITY_STYLES: Record<string, string> = {
  Critical: 'bg-red-500/20 text-red-400 border-red-500/50',
  High: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
  Medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
  Low: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
};

/**
 * Create Jira tickets via POST request to n8n endpoint.
 */
async function createJiraTickets(selectedThreats: SentinelThreat[]): Promise<void> {
  // n8n endpoint - can be configured via environment variable
  const endpoint = import.meta.env.VITE_JIRA_WEBHOOK_URL || '/api/jira/create-tickets';
  
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      threats: selectedThreats.map((threat) => ({
        threat_id: threat.threat_id,
        category: threat.category,
        description: threat.description,
        affected_component: threat.affected_component,
        severity: threat.severity,
        cwe_id: threat.cwe_id,
        impact: threat.impact,
        mitigation_steps: threat.mitigation_steps,
      })),
      timestamp: new Date().toISOString(),
    }),
  });

  if (!response.ok) {
    throw new Error(`Failed to create tickets: ${response.statusText}`);
  }
}

export default function ThreatSelection({ threats }: ThreatSelectionProps) {
  const [selectedThreatIds, setSelectedThreatIds] = useState<Set<string>>(new Set());
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitStatus, setSubmitStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState<string>('');

  const selectedCount = selectedThreatIds.size;
  const selectedThreats = threats.filter((t) => selectedThreatIds.has(t.threat_id));

  const handleToggleThreat = useCallback((threatId: string) => {
    setSelectedThreatIds((prev) => {
      const next = new Set(prev);
      if (next.has(threatId)) {
        next.delete(threatId);
      } else {
        next.add(threatId);
      }
      return next;
    });
  }, []);

  const handleSelectAll = useCallback(() => {
    if (selectedCount === threats.length) {
      setSelectedThreatIds(new Set());
    } else {
      setSelectedThreatIds(new Set(threats.map((t) => t.threat_id)));
    }
  }, [selectedCount, threats]);

  const handleCreateTickets = useCallback(async () => {
    if (selectedThreats.length === 0) return;

    setIsSubmitting(true);
    setSubmitStatus('idle');
    setErrorMessage('');

    try {
      await createJiraTickets(selectedThreats);
      setSubmitStatus('success');
      
      // Reset success message after 3 seconds
      setTimeout(() => {
        setSubmitStatus('idle');
      }, 3000);
    } catch (error) {
      setSubmitStatus('error');
      setErrorMessage(error instanceof Error ? error.message : 'Failed to create tickets');
      
      // Reset error message after 5 seconds
      setTimeout(() => {
        setSubmitStatus('idle');
        setErrorMessage('');
      }, 5000);
    } finally {
      setIsSubmitting(false);
    }
  }, [selectedThreats]);

  if (threats.length === 0) {
    return null;
  }

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-white mb-1">Select Threats for Jira</h3>
          <p className="text-sm text-slate-400">
            {threats.length} threat{threats.length !== 1 ? 's' : ''} found
            {selectedCount > 0 && ` • ${selectedCount} selected`}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleSelectAll}
            className="text-sm text-blue-400 hover:text-blue-300 transition-colors"
          >
            {selectedCount === threats.length ? 'Deselect All' : 'Select All'}
          </button>
          <button
            onClick={handleCreateTickets}
            disabled={selectedCount === 0 || isSubmitting}
            className={`
              px-4 py-2 rounded-lg font-medium transition-all duration-200
              ${selectedCount > 0 && !isSubmitting
                ? 'bg-blue-500 hover:bg-blue-600 text-white'
                : 'bg-slate-700 text-slate-500 cursor-not-allowed'
              }
            `}
          >
            {isSubmitting ? (
              <span className="flex items-center gap-2">
                <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                    fill="none"
                  />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  />
                </svg>
                Creating...
              </span>
            ) : (
              `Create Jira Tickets (${selectedCount})`
            )}
          </button>
        </div>
      </div>

      {/* Status messages */}
      {submitStatus === 'success' && (
        <div className="mb-4 p-3 rounded-lg bg-green-500/20 border border-green-500/50 text-green-400 text-sm">
          ✓ Successfully created {selectedCount} Jira ticket{selectedCount !== 1 ? 's' : ''}
        </div>
      )}
      {submitStatus === 'error' && (
        <div className="mb-4 p-3 rounded-lg bg-red-500/20 border border-red-500/50 text-red-400 text-sm">
          ✗ {errorMessage || 'Failed to create tickets'}
        </div>
      )}

      {/* Threats list */}
      <div className="space-y-2 max-h-[400px] overflow-y-auto">
        {threats.map((threat) => {
          const isSelected = selectedThreatIds.has(threat.threat_id);
          const severityStyle = SEVERITY_STYLES[threat.severity] || 'bg-slate-500/20 text-slate-400 border-slate-500/50';

          return (
            <div
              key={threat.threat_id}
              className={`
                p-3 rounded-lg border transition-colors
                ${isSelected 
                  ? 'bg-blue-500/10 border-blue-500/50' 
                  : 'bg-slate-700/50 border-slate-600 hover:border-slate-500'
                }
              `}
            >
              <div className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={isSelected}
                  onChange={() => handleToggleThreat(threat.threat_id)}
                  className="mt-1 w-4 h-4 rounded border-slate-600 bg-slate-700 text-blue-500 focus:ring-blue-500"
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded border ${severityStyle}`}>
                      {threat.severity}
                    </span>
                    <span className="text-sm font-medium text-slate-200">
                      {threat.affected_component}
                    </span>
                    {threat.category && (
                      <span className="text-xs text-slate-500">
                        {threat.category}
                      </span>
                    )}
                    <span className="text-xs font-mono text-slate-500">
                      {threat.threat_id}
                    </span>
                  </div>
                  <p className="text-sm text-slate-300 leading-relaxed">{threat.description}</p>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
