/**
 * ComponentNode - Custom React Flow node for architecture components.
 * 
 * Visual features:
 * - Border color reflects threat severity
 * - Glow effect for Critical/High severity
 * - Lane-based fade-in animation
 * - Click handler for threat panel
 */

import { memo } from 'react';
import { Handle, Position } from '@xyflow/react';
import type { RenderNode, Severity } from '../../compiler/types';

/** Props for the component node */
interface ComponentNodeProps {
  data: RenderNode;
  selected?: boolean;
}

/** Severity to color mapping */
const SEVERITY_COLORS: Record<Severity, string> = {
  Critical: 'border-red-500',
  High: 'border-orange-500',
  Medium: 'border-yellow-500',
  Low: 'border-green-500',
  None: 'border-gray-600',
};

/** Severity to glow class mapping */
const SEVERITY_GLOW: Record<Severity, string> = {
  Critical: 'node-glow-critical animate-glow-pulse',
  High: 'node-glow-high',
  Medium: '',
  Low: '',
  None: '',
};

/** Severity badge colors */
const SEVERITY_BADGE: Record<Severity, string> = {
  Critical: 'bg-red-500 text-white',
  High: 'bg-orange-500 text-white',
  Medium: 'bg-yellow-500 text-black',
  Low: 'bg-green-500 text-white',
  None: 'bg-gray-600 text-gray-300',
};

/** Component type icons (simple text for now) */
function getTypeIcon(type: string): string {
  const lowerType = type.toLowerCase();
  if (lowerType.includes('database') || lowerType.includes('db')) return '🗄️';
  if (lowerType.includes('cache')) return '⚡';
  if (lowerType.includes('queue') || lowerType.includes('message')) return '📨';
  if (lowerType.includes('client') || lowerType.includes('browser')) return '🌐';
  if (lowerType.includes('mobile')) return '📱';
  if (lowerType.includes('gateway') || lowerType.includes('ingress')) return '🚪';
  if (lowerType.includes('auth')) return '🔐';
  if (lowerType.includes('service') || lowerType.includes('microservice')) return '⚙️';
  if (lowerType.includes('dns')) return '🔍';
  if (lowerType.includes('load balancer')) return '⚖️';
  return '📦';
}

/**
 * ComponentNode component for React Flow.
 */
function ComponentNode({ data, selected }: ComponentNodeProps) {
  const { label, type, lane, risk, threats } = data;
  const threatCount = threats.length;
  
  const borderColor = SEVERITY_COLORS[risk];
  const glowClass = SEVERITY_GLOW[risk];
  const badgeClass = SEVERITY_BADGE[risk];
  const icon = getTypeIcon(type);
  
  return (
    <div
      className={`
        relative px-4 py-3 rounded-lg border-2
        bg-slate-800 text-slate-100
        min-w-[160px] max-w-[200px]
        transition-all duration-200
        animate-fade-in lane-${lane}
        ${borderColor}
        ${glowClass}
        ${selected ? 'ring-2 ring-blue-400 ring-offset-2 ring-offset-slate-900' : ''}
        hover:scale-105 hover:shadow-lg
        cursor-pointer
      `}
    >
      {/* Input handle */}
      <Handle
        type="target"
        position={Position.Left}
        className="!bg-slate-500 !border-slate-400 !w-3 !h-3"
      />
      
      {/* Threat count badge */}
      {threatCount > 0 && (
        <div
          className={`
            absolute -top-2 -right-2
            px-2 py-0.5 rounded-full text-xs font-bold
            ${badgeClass}
          `}
        >
          {threatCount}
        </div>
      )}
      
      {/* Node content */}
      <div className="flex items-start gap-2">
        <span className="text-lg">{icon}</span>
        <div className="flex-1 min-w-0">
          <div className="font-medium text-sm truncate" title={label}>
            {label}
          </div>
          <div className="text-xs text-slate-400 truncate" title={type}>
            {type}
          </div>
        </div>
      </div>
      
      {/* Severity indicator */}
      {risk !== 'None' && (
        <div className="mt-2 flex items-center gap-1">
          <span
            className={`
              w-2 h-2 rounded-full
              ${risk === 'Critical' ? 'bg-red-500' : ''}
              ${risk === 'High' ? 'bg-orange-500' : ''}
              ${risk === 'Medium' ? 'bg-yellow-500' : ''}
              ${risk === 'Low' ? 'bg-green-500' : ''}
            `}
          />
          <span className="text-xs text-slate-400">{risk} Risk</span>
        </div>
      )}
      
      {/* Output handle */}
      <Handle
        type="source"
        position={Position.Right}
        className="!bg-slate-500 !border-slate-400 !w-3 !h-3"
      />
    </div>
  );
}

export default memo(ComponentNode);
