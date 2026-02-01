/**
 * Role Mapper - Deterministic lane assignment based on component type.
 * 
 * Maps component types to lanes for consistent left-to-right layout:
 * - Lane 0 (external): Clients, browsers, mobile apps, users
 * - Lane 1 (ingress): Gateways, load balancers, ingress controllers
 * - Lane 2 (compute): Services, APIs, microservices, backends
 * - Lane 3 (data): Databases, caches, storage systems
 * - Lane 4 (infra): DNS, queues, logging, monitoring
 */

import type { ComponentRole, Lane } from './types';

/**
 * Keywords for each role category.
 * Order matters - first match wins.
 */
const ROLE_KEYWORDS: Record<ComponentRole, string[]> = {
  external: [
    'client',
    'browser',
    'mobile',
    'user',
    'external',
    'app',
    'web browser',
    'mobile app',
  ],
  ingress: [
    'ingress',
    'gateway',
    'route',
    'load balancer',
    'cdn',
    'cloudfront',
    'nginx',
    'proxy',
    'waf',
    'public route',
    'api gateway',
  ],
  compute: [
    'service',
    'api',
    'backend',
    'frontend',
    'microservice',
    'server',
    'function',
    'lambda',
    'container',
    'pod',
    'worker',
    'controller',
    'handler',
    'processor',
    'web server',
    'app server',
    'auth',
    'authentication',
    'order',
    'payment',
    'catalog',
    'customer',
    'inventory',
    'portal',
    'foundation',
  ],
  data: [
    'database',
    'db',
    'cache',
    'storage',
    'elasticsearch',
    'mysql',
    'postgres',
    'mariadb',
    'mongodb',
    'redis',
    'couchdb',
    's3',
    'bucket',
    'blob',
    'data',
    'warehouse',
    'lake',
  ],
  infra: [
    'dns',
    'queue',
    'message',
    'logging',
    'monitoring',
    'rabbitmq',
    'kafka',
    'sqs',
    'pubsub',
    'event',
    'trace',
    'metric',
    'prometheus',
    'grafana',
    'kube dns',
    'coredns',
  ],
};

/** Lane mapping for each role */
const ROLE_TO_LANE: Record<ComponentRole, Lane> = {
  external: 0,
  ingress: 1,
  compute: 2,
  data: 3,
  infra: 4,
};

/**
 * Determine the role of a component based on its name and type.
 * Uses keyword matching with priority ordering.
 */
export function getComponentRole(name: string, type: string): ComponentRole {
  const combined = `${name} ${type}`.toLowerCase();

  // Check each role in priority order
  const roleOrder: ComponentRole[] = ['external', 'ingress', 'data', 'infra', 'compute'];
  
  for (const role of roleOrder) {
    const keywords = ROLE_KEYWORDS[role];
    for (const keyword of keywords) {
      if (combined.includes(keyword.toLowerCase())) {
        return role;
      }
    }
  }

  // Default to compute for unknown types
  return 'compute';
}

/**
 * Get the lane number for a component.
 * Lanes determine horizontal position in the diagram.
 */
export function getLane(name: string, type: string): Lane {
  const role = getComponentRole(name, type);
  return ROLE_TO_LANE[role];
}

/**
 * Get display information for a lane.
 */
export function getLaneInfo(lane: Lane): { label: string; description: string } {
  const laneInfo: Record<Lane, { label: string; description: string }> = {
    0: { label: 'External', description: 'Clients and external users' },
    1: { label: 'Ingress', description: 'Entry points and gateways' },
    2: { label: 'Compute', description: 'Services and processing' },
    3: { label: 'Data', description: 'Databases and storage' },
    4: { label: 'Infrastructure', description: 'Supporting systems' },
  };
  return laneInfo[lane];
}
