/**
 * ComponentNode - Custom React Flow node for architecture components.
 * 
 * Features:
 * - Compact design with icon, name, and type
 * - Severity indicator inside node boundaries
 * - Hover effects for interactivity
 */

import { memo } from 'react';
import { Handle, Position } from '@xyflow/react';
import type { RenderNode, Severity } from '../../compiler/types';

interface ComponentNodeProps {
  data: RenderNode;
  selected?: boolean;
}

/**
 * Get severity-based styling.
 */
function getSeverityStyles(severity: Severity): {
  dotColor: string;
  borderColor: string;
  glowClass: string;
} {
  switch (severity) {
    case 'Critical':
      return {
        dotColor: 'bg-red-500',
        borderColor: 'border-red-500/60',
        glowClass: 'shadow-red-500/30',
      };
    case 'High':
      return {
        dotColor: 'bg-orange-500',
        borderColor: 'border-orange-500/60',
        glowClass: 'shadow-orange-500/30',
      };
    case 'Medium':
      return {
        dotColor: 'bg-yellow-500',
        borderColor: 'border-yellow-500/60',
        glowClass: 'shadow-yellow-500/30',
      };
    case 'Low':
      return {
        dotColor: 'bg-green-500',
        borderColor: 'border-green-500/60',
        glowClass: 'shadow-green-500/30',
      };
    default:
      return {
        dotColor: '',
        borderColor: 'border-slate-600',
        glowClass: '',
      };
  }
}

/**
 * Get icon based on component type.
 */
function getTypeIcon(type: string): string {
  const lowerType = type.toLowerCase();
  
  if (lowerType.includes('database') || lowerType.includes('db') || lowerType.includes('sql')) {
    return '💾';
  }
  if (lowerType.includes('api') || lowerType.includes('gateway')) {
    return '🔌';
  }
  if (lowerType.includes('auth') || lowerType.includes('security')) {
    return '🔐';
  }
  if (lowerType.includes('ai') || lowerType.includes('llm') || lowerType.includes('ml')) {
    return '🤖';
  }
  if (lowerType.includes('client') || lowerType.includes('browser') || lowerType.includes('user')) {
    return '👤';
  }
  if (lowerType.includes('queue') || lowerType.includes('message') || lowerType.includes('kafka')) {
    return '📨';
  }
  if (lowerType.includes('storage') || lowerType.includes('blob') || lowerType.includes('s3')) {
    return '📦';
  }
  if (lowerType.includes('cache') || lowerType.includes('redis')) {
    return '⚡';
  }
  if (lowerType.includes('log') || lowerType.includes('monitor')) {
    return '📊';
  }
  if (lowerType.includes('orchestrat') || lowerType.includes('workflow')) {
    return '🎯';
  }
  
  // Default: generic service
  return '⚙️';
}

const ComponentNode = ({ data, selected }: ComponentNodeProps) => {
  const { label, type, risk, threats } = data;
  const styles = getSeverityStyles(risk);
  const icon = getTypeIcon(type);
  const hasThreat = risk !== 'None';
  
  return (
    <div
      className={`
        relative flex items-center gap-2
        px-3 py-2 rounded-lg
        bg-slate-800 text-white
        border ${hasThreat ? styles.borderColor : 'border-slate-600'}
        ${hasThreat ? 'shadow-lg ' + styles.glowClass : 'shadow-md'}
        transition-all duration-200
        min-w-[140px] max-w-[160px]
        ${selected ? 'ring-2 ring-blue-400' : ''}
        hover:scale-105 hover:shadow-xl
      `}
    >
      {/* Left handle */}
      <Handle 
        type="target" 
        position={Position.Left} 
        className="!bg-slate-400 !w-2 !h-2 !border-slate-600" 
      />
      
      {/* Icon */}
      <span className="text-base flex-shrink-0">{icon}</span>
      
      {/* Content */}
      <div className="flex-1 min-w-0 overflow-hidden">
        <div className="text-xs font-semibold truncate" title={label}>
          {label}
        </div>
        <div className="text-[10px] text-slate-400 truncate" title={type}>
          {type}
        </div>
      </div>
      
      {/* Severity indicator - positioned inside the node */}
      {hasThreat && (
        <div className="flex-shrink-0 flex items-center gap-1">
          <span
            className={`
              w-2 h-2 rounded-full ${styles.dotColor}
              ${(risk === 'Critical' || risk === 'High') ? 'animate-pulse' : ''}
            `}
            title={`${risk} - ${threats.length} threat${threats.length !== 1 ? 's' : ''}`}
          />
          <span className="text-[10px] text-slate-400">
            {threats.length}
          </span>
        </div>
      )}
      
      {/* Right handle */}
      <Handle 
        type="source" 
        position={Position.Right} 
        className="!bg-slate-400 !w-2 !h-2 !border-slate-600" 
      />
    </div>
  );
};

export default memo(ComponentNode);
