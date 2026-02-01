/**
 * Domain Assigner - Groups nodes into domains based on their roles.
 * 
 * Domains are visual containers that group related components.
 * Supports a wide variety of architecture patterns.
 */

import type { 
  RenderNode, 
  Domain, 
  DomainId, 
  ComponentRole, 
  Severity 
} from './types';

/**
 * Domain configuration - comprehensive set of domains
 */
export const DOMAIN_CONFIG: Record<DomainId, {
  label: string;
  icon: string;
  roles: ComponentRole[];
  gridPosition: number;
}> = {
  'data-sources': {
    label: 'Data Sources',
    icon: '📥',
    roles: ['external', 'ingress'],
    gridPosition: 0,
  },
  'gateway': {
    label: 'Gateway',
    icon: '🚪',
    roles: ['gateway'],
    gridPosition: 1,
  },
  'security': {
    label: 'Security',
    icon: '🔐',
    roles: ['security'],
    gridPosition: 2,
  },
  'processing': {
    label: 'Processing',
    icon: '⚙️',
    roles: ['orchestration', 'compute'],
    gridPosition: 3,
  },
  'messaging': {
    label: 'Messaging',
    icon: '📨',
    roles: ['messaging'],
    gridPosition: 4,
  },
  'ai-services': {
    label: 'AI Services',
    icon: '🤖',
    roles: ['ai'],
    gridPosition: 5,
  },
  'storage': {
    label: 'Storage',
    icon: '💾',
    roles: ['data'],
    gridPosition: 6,
  },
  'analytics': {
    label: 'Analytics',
    icon: '📊',
    roles: ['analytics'],
    gridPosition: 7,
  },
  'monitoring': {
    label: 'Monitoring',
    icon: '📈',
    roles: ['monitoring'],
    gridPosition: 8,
  },
  'edge': {
    label: 'Edge / CDN',
    icon: '🌐',
    roles: ['edge'],
    gridPosition: 9,
  },
  'infra': {
    label: 'Infrastructure',
    icon: '🔧',
    roles: ['infra'],
    gridPosition: 10,
  },
};

/**
 * Map a component role to its domain ID.
 */
export function roleToDomain(role: ComponentRole): DomainId {
  for (const [domainId, config] of Object.entries(DOMAIN_CONFIG)) {
    if (config.roles.includes(role)) {
      return domainId as DomainId;
    }
  }
  // Default to processing if unknown
  return 'processing';
}

/**
 * Get the highest severity from a list of nodes.
 */
function getMaxSeverity(nodes: RenderNode[]): Severity {
  const severityOrder: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'None'];
  
  for (const severity of severityOrder) {
    if (nodes.some(node => node.risk === severity)) {
      return severity;
    }
  }
  return 'None';
}

/**
 * Calculate domain size based on node count.
 * Ensures all nodes fit within the domain with proper padding.
 */
function calculateDomainSize(nodeCount: number): { width: number; height: number } {
  const NODE_WIDTH = 160;
  const NODE_HEIGHT = 50;
  const NODE_SPACING = 20;
  const PADDING_X = 20;
  const PADDING_TOP = 60; // Header space
  const PADDING_BOTTOM = 30;
  
  // Arrange nodes in a vertical column within the domain
  const width = NODE_WIDTH + PADDING_X * 2;
  const contentHeight = nodeCount * NODE_HEIGHT + (nodeCount - 1) * NODE_SPACING;
  const height = Math.max(
    150, // Minimum height
    contentHeight + PADDING_TOP + PADDING_BOTTOM
  );
  
  return { width, height };
}

/**
 * Assign nodes to domains and create domain structures.
 * Only creates domains that have nodes - empty domains are skipped.
 * 
 * @param nodes - All render nodes with roles assigned
 * @returns Array of domains with their contained nodes
 */
export function assignDomains(nodes: RenderNode[]): Domain[] {
  // Group nodes by domain
  const nodesByDomain = new Map<DomainId, RenderNode[]>();
  
  for (const node of nodes) {
    const domainId = node.domainId;
    const existing = nodesByDomain.get(domainId) || [];
    existing.push(node);
    nodesByDomain.set(domainId, existing);
  }
  
  // Create domains with computed properties (only for non-empty domains)
  const domains: Domain[] = [];
  const DOMAIN_SPACING = 30;
  let currentX = DOMAIN_SPACING;
  
  // Get domains sorted by grid position
  const sortedDomainIds = Object.keys(DOMAIN_CONFIG).sort(
    (a, b) => DOMAIN_CONFIG[a as DomainId].gridPosition - DOMAIN_CONFIG[b as DomainId].gridPosition
  ) as DomainId[];
  
  for (const domainId of sortedDomainIds) {
    const domainNodes = nodesByDomain.get(domainId);
    
    // Skip empty domains
    if (!domainNodes || domainNodes.length === 0) {
      continue;
    }
    
    const config = DOMAIN_CONFIG[domainId];
    const size = calculateDomainSize(domainNodes.length);
    
    const domain: Domain = {
      id: domainId,
      label: config.label,
      icon: config.icon,
      roles: config.roles,
      gridPosition: config.gridPosition,
      position: { x: currentX, y: DOMAIN_SPACING },
      size,
      nodes: domainNodes,
      maxSeverity: getMaxSeverity(domainNodes),
    };
    
    domains.push(domain);
    currentX += size.width + DOMAIN_SPACING;
  }
  
  return domains;
}

/**
 * Get domain display info for a given domain ID.
 */
export function getDomainInfo(domainId: DomainId): { label: string; icon: string } {
  const config = DOMAIN_CONFIG[domainId];
  return { label: config.label, icon: config.icon };
}
