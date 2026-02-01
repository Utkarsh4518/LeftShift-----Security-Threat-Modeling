/**
 * DomainContainer - Visual container for grouping related components.
 * 
 * Features:
 * - Glassmorphic design with rounded corners
 * - Header with icon, label, and severity indicator
 * - Severity-based border coloring
 */

import { memo } from 'react';
import type { Domain, Severity } from '../../compiler/types';

interface DomainContainerProps {
  data: Domain;
  selected?: boolean;
}

/**
 * Get severity-based border and glow styles.
 */
function getSeverityStyles(severity: Severity): {
  borderColor: string;
  bgTint: string;
} {
  switch (severity) {
    case 'Critical':
      return {
        borderColor: 'border-red-500/70',
        bgTint: 'from-red-500/5 to-transparent',
      };
    case 'High':
      return {
        borderColor: 'border-orange-500/70',
        bgTint: 'from-orange-500/5 to-transparent',
      };
    case 'Medium':
      return {
        borderColor: 'border-yellow-500/60',
        bgTint: 'from-yellow-500/5 to-transparent',
      };
    case 'Low':
      return {
        borderColor: 'border-green-500/60',
        bgTint: 'from-green-500/5 to-transparent',
      };
    default:
      return {
        borderColor: 'border-slate-600/60',
        bgTint: 'from-slate-500/5 to-transparent',
      };
  }
}

const DomainContainer = ({ data }: DomainContainerProps) => {
  const { label, icon, maxSeverity, nodes, size } = data;
  const styles = getSeverityStyles(maxSeverity);
  const hasThreat = maxSeverity !== 'None';
  
  // Calculate threat count in this domain
  const threatCount = nodes.reduce((sum, node) => sum + node.threats.length, 0);
  
  return (
    <div
      className={`
        rounded-xl border-2 ${styles.borderColor}
        bg-gradient-to-b ${styles.bgTint}
        backdrop-blur-sm
        flex flex-col
        overflow-visible
      `}
      style={{
        width: size?.width || 200,
        height: size?.height || 200,
        background: 'rgba(30, 41, 59, 0.6)', // slate-800 with alpha
      }}
    >
      {/* Header */}
      <div className={`
        flex items-center gap-2 px-3 py-2
        border-b border-slate-700/50
        bg-slate-700/40 rounded-t-[10px]
      `}>
        {/* Icon */}
        <span className="text-lg">{icon}</span>
        
        {/* Label */}
        <span className="flex-1 text-sm font-semibold text-slate-200 truncate">
          {label}
        </span>
        
        {/* Threat badge */}
        {hasThreat && threatCount > 0 && (
          <span
            className={`
              px-1.5 py-0.5 rounded text-[10px] font-bold
              ${maxSeverity === 'Critical' ? 'bg-red-500 text-white' : ''}
              ${maxSeverity === 'High' ? 'bg-orange-500 text-white' : ''}
              ${maxSeverity === 'Medium' ? 'bg-yellow-500 text-slate-900' : ''}
              ${maxSeverity === 'Low' ? 'bg-green-500 text-white' : ''}
            `}
          >
            {threatCount}
          </span>
        )}
      </div>
      
      {/* Content area - nodes will be positioned here by React Flow */}
      <div className="flex-1 relative">
        {/* Node count indicator (subtle) */}
        <div className="absolute bottom-2 left-2 text-[10px] text-slate-500">
          {nodes.length} component{nodes.length !== 1 ? 's' : ''}
        </div>
      </div>
    </div>
  );
};

export default memo(DomainContainer);
