/**
 * Role Mapper - Deterministic role and lane assignment based on component type.
 * 
 * Comprehensive role detection for various architecture patterns.
 */

import type { ComponentRole, Lane } from './types';

/**
 * Keywords for each role category.
 * Matched against combined (name + type) in lowercase.
 */
const ROLE_KEYWORDS: Record<ComponentRole, string[]> = {
  external: [
    'client',
    'browser',
    'mobile',
    'user',
    'external',
    'web browser',
    'mobile app',
    'smtp',
    'email server',
    'inbox',
    'mailbox',
    'customer',
    'admin',
    'iot',
    'device',
    'sensor',
  ],
  ingress: [
    'ingress',
    'public route',
    'entry point',
    'load balancer',
    'reverse proxy',
  ],
  gateway: [
    'gateway',
    'api gateway',
    'api management',
    'apim',
    'kong',
    'zuul',
    'ambassador',
    'traefik',
  ],
  security: [
    'auth',
    'authentication',
    'authorization',
    'oauth',
    'oidc',
    'identity',
    'iam',
    'sso',
    'saml',
    'jwt',
    'keycloak',
    'okta',
    'waf',
    'firewall',
    'security',
    'vault',
    'secret',
    'certificate',
  ],
  orchestration: [
    'master agent',
    'orchestrat',
    'workflow',
    'power automate',
    'logic app',
    'logic/ai agent',
    'step function',
    'airflow',
    'n8n',
    'zapier',
    'automation',
    'scheduler',
    'coordinator',
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
    'order',
    'payment',
    'catalog',
    'inventory',
    'portal',
    'foundation',
    'form',
    'app',
    'data transfor',
    'dataflow',
  ],
  messaging: [
    'queue',
    'message',
    'rabbitmq',
    'kafka',
    'sqs',
    'sns',
    'pubsub',
    'event hub',
    'event grid',
    'service bus',
    'activemq',
    'nats',
    'redis pub',
    'stream',
  ],
  ai: [
    'openai',
    'azure openai',
    'llm',
    'ml model',
    'ai service',
    'ai agent',
    'gpt',
    'claude',
    'gemini',
    'external ai',
    'pdf processing',
    'extract & store',
    'text generation',
    'embedding',
    'vector',
    'cognitive',
    'machine learning',
    'neural',
    'inference',
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
    'sql db',
    'sql server',
    'warehouse',
    'lake',
    'dynamo',
    'cosmos',
    'cassandra',
    'neo4j',
    'graph db',
  ],
  analytics: [
    'analytics',
    'bi',
    'business intelligence',
    'reporting',
    'dashboard',
    'tableau',
    'power bi',
    'powerbi',
    'looker',
    'metabase',
    'superset',
    'qlik',
    'sisense',
  ],
  monitoring: [
    'monitoring',
    'logging',
    'log',
    'trace',
    'tracing',
    'metric',
    'prometheus',
    'grafana',
    'datadog',
    'new relic',
    'splunk',
    'elk',
    'kibana',
    'jaeger',
    'zipkin',
    'observability',
    'apm',
    'application insights',
  ],
  edge: [
    'cdn',
    'cloudfront',
    'akamai',
    'fastly',
    'cloudflare',
    'edge',
    'edge computing',
    'lambda@edge',
    'cloudflare workers',
  ],
  infra: [
    'dns',
    'coredns',
    'kube dns',
    'route53',
    'terraform',
    'ansible',
    'kubernetes',
    'docker',
    'container registry',
    'acr',
    'ecr',
    'gcr',
  ],
};

/** 
 * Role matching priority order.
 * Earlier roles take precedence when multiple keywords match.
 */
const ROLE_PRIORITY: ComponentRole[] = [
  'external',
  'ingress',
  'gateway',
  'security',
  'orchestration',
  'ai',
  'messaging',
  'data',
  'analytics',
  'monitoring',
  'edge',
  'infra',
  'compute', // Default fallback - checked last
];

/** Lane mapping for each role (for left-to-right ordering) */
const ROLE_TO_LANE: Record<ComponentRole, Lane> = {
  external: 0,
  ingress: 0,
  gateway: 1,
  security: 1,
  orchestration: 2,
  compute: 2,
  messaging: 3,
  ai: 3,
  data: 4,
  analytics: 5,
  monitoring: 5,
  edge: 0,
  infra: 5,
};

/**
 * Determine the role of a component based on its name and type.
 */
export function getComponentRole(name: string, type: string): ComponentRole {
  const combined = `${name} ${type}`.toLowerCase();

  // Check each role in priority order
  for (const role of ROLE_PRIORITY) {
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
    0: { label: 'External', description: 'Clients and entry points' },
    1: { label: 'Gateway', description: 'API and security gateways' },
    2: { label: 'Processing', description: 'Compute and orchestration' },
    3: { label: 'Services', description: 'AI and messaging' },
    4: { label: 'Data', description: 'Databases and storage' },
    5: { label: 'Operations', description: 'Analytics and monitoring' },
  };
  return laneInfo[lane];
}

/**
 * Check if a role is considered "shared infrastructure" (many edges point to it).
 */
export function isSharedInfraRole(role: ComponentRole): boolean {
  return role === 'ai' || role === 'infra' || role === 'data' || role === 'monitoring';
}
