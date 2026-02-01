/**
 * Example Architectures - Pre-built examples for testing.
 * 
 * These include architecture JSON and sample threat data
 * so users can see the visualization without a backend.
 */

import type { ExampleArchitecture, SentinelThreat } from '../compiler/types';

/** Sample threats for the E-Commerce example */
const ecommerceThreats: SentinelThreat[] = [
  {
    threat_id: 'T-001',
    category: 'Spoofing',
    description: 'JWT token forgery via algorithm confusion attack. Attacker can bypass authentication by manipulating the token algorithm header.',
    affected_component: 'Auth Service',
    severity: 'Critical',
    cwe_id: 'CWE-347',
    impact: 'Complete authentication bypass allowing unauthorized access to any user account.',
    mitigation_steps: [
      'Use asymmetric key algorithms (RS256) instead of symmetric (HS256)',
      'Explicitly verify the algorithm in token validation',
      'Implement token binding to prevent replay attacks',
    ],
  },
  {
    threat_id: 'T-002',
    category: 'Tampering',
    description: 'SQL Injection in Order Service through unsanitized order search parameters.',
    affected_component: 'Order Service',
    severity: 'High',
    cwe_id: 'CWE-89',
    impact: 'Data exfiltration, modification, or deletion of order records.',
    mitigation_steps: [
      'Use parameterized queries or prepared statements',
      'Implement input validation and sanitization',
      'Apply principle of least privilege for database connections',
    ],
  },
  {
    threat_id: 'T-003',
    category: 'Information Disclosure',
    description: 'Sensitive payment data exposed in application logs due to insufficient log filtering.',
    affected_component: 'Payment Service',
    severity: 'High',
    cwe_id: 'CWE-532',
    impact: 'PCI compliance violation and potential exposure of credit card data.',
    mitigation_steps: [
      'Implement structured logging with data classification',
      'Mask sensitive fields before logging',
      'Use centralized log management with access controls',
    ],
  },
  {
    threat_id: 'T-004',
    category: 'Denial of Service',
    description: 'API Gateway lacks rate limiting, allowing resource exhaustion attacks.',
    affected_component: 'API Gateway',
    severity: 'Medium',
    cwe_id: 'CWE-770',
    impact: 'Service unavailability affecting all downstream services.',
    mitigation_steps: [
      'Implement rate limiting per client/IP',
      'Add request throttling during high load',
      'Deploy circuit breakers for backend services',
    ],
  },
  {
    threat_id: 'T-005',
    category: 'Elevation of Privilege',
    description: 'Insecure Direct Object Reference in Product Service allows accessing other merchants products.',
    affected_component: 'Product Service',
    severity: 'High',
    cwe_id: 'CWE-639',
    impact: 'Unauthorized modification of competitor product listings.',
    mitigation_steps: [
      'Implement authorization checks for all resource access',
      'Use indirect references (UUIDs) instead of sequential IDs',
      'Add ownership validation in service layer',
    ],
  },
  {
    threat_id: 'T-006',
    category: 'Information Disclosure',
    description: 'Redis cache stores session data without encryption, vulnerable to memory inspection.',
    affected_component: 'Redis Cache',
    severity: 'Medium',
    cwe_id: 'CWE-311',
    impact: 'Session hijacking if cache server is compromised.',
    mitigation_steps: [
      'Enable TLS for Redis connections',
      'Encrypt sensitive session data before caching',
      'Implement short TTLs for session data',
    ],
  },
];

/** Sample threats for the K8s example */
const k8sThreats: SentinelThreat[] = [
  {
    threat_id: 'T-001',
    category: 'Spoofing',
    description: 'DNS cache poisoning via Kaminsky attack on Kube DNS could redirect service traffic.',
    affected_component: 'Kube DNS',
    severity: 'Critical',
    cwe_id: 'CWE-345',
    impact: 'Man-in-the-middle attacks on all inter-service communication.',
    mitigation_steps: [
      'Enable DNSSEC for external DNS resolution',
      'Use source port randomization',
      'Implement service mesh with mTLS',
    ],
  },
  {
    threat_id: 'T-002',
    category: 'Tampering',
    description: 'Lack of network policies allows lateral movement between pods.',
    affected_component: 'Public Route',
    severity: 'High',
    cwe_id: 'CWE-284',
    impact: 'Compromised pod can access any other service in the cluster.',
    mitigation_steps: [
      'Implement default-deny NetworkPolicies',
      'Use namespace isolation',
      'Deploy service mesh for zero-trust networking',
    ],
  },
  {
    threat_id: 'T-003',
    category: 'Information Disclosure',
    description: 'Elasticsearch cluster exposes sensitive logs without authentication.',
    affected_component: 'Elasticsearch (Logs)',
    severity: 'High',
    cwe_id: 'CWE-306',
    impact: 'Exposure of application logs containing PII and security events.',
    mitigation_steps: [
      'Enable X-Pack security or OpenSearch security plugin',
      'Implement role-based access control',
      'Encrypt data at rest',
    ],
  },
  {
    threat_id: 'T-004',
    category: 'Denial of Service',
    description: 'MariaDB connection pool exhaustion through slow query attacks.',
    affected_component: 'MariaDB',
    severity: 'Medium',
    cwe_id: 'CWE-400',
    impact: 'Database unavailability affecting order processing.',
    mitigation_steps: [
      'Set connection timeouts and limits',
      'Implement query timeout policies',
      'Use connection pooling with proper sizing',
    ],
  },
];

/** Sample threats for Django example */
const djangoThreats: SentinelThreat[] = [
  {
    threat_id: 'T-001',
    category: 'Tampering',
    description: 'Cross-Site Request Forgery possible due to missing CSRF token validation in API endpoints.',
    affected_component: 'REST API',
    severity: 'High',
    cwe_id: 'CWE-352',
    impact: 'Attackers can perform actions on behalf of authenticated users.',
    mitigation_steps: [
      'Enable Django CSRF middleware for all state-changing operations',
      'Use SameSite cookie attribute',
      'Implement CORS restrictions',
    ],
  },
  {
    threat_id: 'T-002',
    category: 'Information Disclosure',
    description: 'Debug mode enabled in production exposes stack traces and configuration.',
    affected_component: 'Web Portal',
    severity: 'Medium',
    cwe_id: 'CWE-209',
    impact: 'Internal paths, dependencies, and configuration exposed to attackers.',
    mitigation_steps: [
      'Set DEBUG=False in production',
      'Configure proper error pages',
      'Use structured logging for errors',
    ],
  },
];

/**
 * Example architectures available for testing.
 */
export const EXAMPLE_ARCHITECTURES: ExampleArchitecture[] = [
  {
    id: 'ecommerce',
    name: 'E-Commerce Platform',
    description:
      'A three-tier web application with CDN, API Gateway, microservices (Auth, Product, Order, Payment), PostgreSQL, Redis Cache, and Stripe integration.',
    componentCount: 13,
    highlights: ['Microservices', 'Payment Processing', 'External APIs', 'Caching'],
    data: {
      project_name: 'E-Commerce Platform',
      description:
        'A three-tier web application with user authentication, product catalog, and payment processing.',
      components: [
        { name: 'Web Browser', type: 'Client' },
        { name: 'CDN (CloudFront)', type: 'Content Delivery Network' },
        { name: 'Load Balancer', type: 'Load Balancer' },
        { name: 'Web Server (Nginx)', type: 'Web Server' },
        { name: 'API Gateway', type: 'API Gateway' },
        { name: 'Auth Service', type: 'Microservice' },
        { name: 'Product Service', type: 'Microservice' },
        { name: 'Order Service', type: 'Microservice' },
        { name: 'Payment Service', type: 'Microservice' },
        { name: 'PostgreSQL Database', type: 'Database' },
        { name: 'Redis Cache', type: 'Cache' },
        { name: 'RabbitMQ', type: 'Message Queue' },
        { name: 'Stripe API', type: 'External Service' },
      ],
      data_flows: [
        { source: 'Web Browser', destination: 'CDN (CloudFront)', protocol: 'HTTPS' },
        { source: 'CDN (CloudFront)', destination: 'Load Balancer', protocol: 'HTTPS' },
        { source: 'Load Balancer', destination: 'Web Server (Nginx)', protocol: 'HTTP' },
        { source: 'Web Server (Nginx)', destination: 'API Gateway', protocol: 'HTTP' },
        { source: 'API Gateway', destination: 'Auth Service', protocol: 'gRPC' },
        { source: 'API Gateway', destination: 'Product Service', protocol: 'gRPC' },
        { source: 'API Gateway', destination: 'Order Service', protocol: 'gRPC' },
        { source: 'Order Service', destination: 'Payment Service', protocol: 'gRPC' },
        { source: 'Auth Service', destination: 'PostgreSQL Database', protocol: 'TCP/5432' },
        { source: 'Product Service', destination: 'PostgreSQL Database', protocol: 'TCP/5432' },
        { source: 'Order Service', destination: 'PostgreSQL Database', protocol: 'TCP/5432' },
        { source: 'Product Service', destination: 'Redis Cache', protocol: 'TCP/6379' },
        { source: 'Order Service', destination: 'RabbitMQ', protocol: 'AMQP' },
        { source: 'Payment Service', destination: 'Stripe API', protocol: 'HTTPS' },
      ],
      trust_boundaries: ['Internet', 'DMZ', 'Application Zone', 'Data Zone', 'External Services'],
    },
  },
  {
    id: 'k8s-platform',
    name: 'Cloud Native K8s Platform',
    description:
      'OpenShift/Kubernetes microservices architecture with Web + Mobile frontends, service discovery, backend services, and multiple database systems.',
    componentCount: 20,
    highlights: ['Kubernetes', 'Service Mesh', 'Multiple DBs', 'Mobile Backend'],
    data: {
      project_name: 'Cloud Native E-Commerce Platform',
      description:
        'OpenShift/Kubernetes-based microservices architecture with mobile and web frontends.',
      components: [
        { name: 'Web Browser', type: 'Client' },
        { name: 'Mobile App', type: 'Client' },
        { name: 'Public Route', type: 'Ingress Controller' },
        { name: 'Web Frontend', type: 'Frontend Service' },
        { name: 'Mobile Foundation', type: 'Mobile Backend Service' },
        { name: 'Kube DNS', type: 'Service Discovery' },
        { name: 'Catalog Service', type: 'Backend Microservice' },
        { name: 'Customer Service', type: 'Backend Microservice' },
        { name: 'Inventory Service', type: 'Backend Microservice' },
        { name: 'Orders Service', type: 'Backend Microservice' },
        { name: 'Auth Service', type: 'Authentication Service' },
        { name: 'Elasticsearch (Catalog)', type: 'Search Database' },
        { name: 'CouchDB', type: 'Document Database' },
        { name: 'MySQL (Inventory)', type: 'Relational Database' },
        { name: 'MariaDB', type: 'Relational Database' },
        { name: 'Elasticsearch (Logs)', type: 'Search Database' },
        { name: 'MySQL (Auth)', type: 'Relational Database' },
      ],
      data_flows: [
        { source: 'Web Browser', destination: 'Public Route', protocol: 'HTTPS' },
        { source: 'Mobile App', destination: 'Public Route', protocol: 'HTTPS' },
        { source: 'Public Route', destination: 'Web Frontend', protocol: 'HTTP' },
        { source: 'Public Route', destination: 'Mobile Foundation', protocol: 'HTTP' },
        { source: 'Web Frontend', destination: 'Kube DNS', protocol: 'DNS' },
        { source: 'Kube DNS', destination: 'Catalog Service', protocol: 'HTTP/gRPC' },
        { source: 'Kube DNS', destination: 'Customer Service', protocol: 'HTTP/gRPC' },
        { source: 'Kube DNS', destination: 'Inventory Service', protocol: 'HTTP/gRPC' },
        { source: 'Kube DNS', destination: 'Orders Service', protocol: 'HTTP/gRPC' },
        { source: 'Catalog Service', destination: 'Elasticsearch (Catalog)', protocol: 'HTTP/9200' },
        { source: 'Customer Service', destination: 'CouchDB', protocol: 'HTTP/5984' },
        { source: 'Inventory Service', destination: 'MySQL (Inventory)', protocol: 'TCP/3306' },
        { source: 'Orders Service', destination: 'MariaDB', protocol: 'TCP/3306' },
        { source: 'Auth Service', destination: 'Elasticsearch (Logs)', protocol: 'HTTP/9200' },
        { source: 'Auth Service', destination: 'MySQL (Auth)', protocol: 'TCP/3306' },
        { source: 'Web Frontend', destination: 'Auth Service', protocol: 'HTTP' },
      ],
      trust_boundaries: [
        'Internet (Untrusted)',
        'DMZ - Public Route',
        'K8s Cluster - Frontend',
        'K8s Cluster - Backend',
        'Database Zone',
      ],
    },
  },
  {
    id: 'django-portal',
    name: 'Django Web Portal',
    description:
      'Layered architecture with Backbone.js frontend, Django REST API, MVC pattern, and data access layer. Demonstrates internal component communication.',
    componentCount: 10,
    highlights: ['Django', 'REST API', 'MVC Pattern', 'Backbone.js'],
    data: {
      project_name: 'Django Web Portal',
      description: 'Layered web application with Django backend and Backbone.js frontend.',
      components: [
        { name: 'Web Browser', type: 'Client' },
        { name: 'Backbone.js App', type: 'Frontend Framework' },
        { name: 'Event Handler', type: 'Frontend Component' },
        { name: 'REST API', type: 'API Layer' },
        { name: 'Router', type: 'Django Router' },
        { name: 'View', type: 'Django View' },
        { name: 'Model', type: 'Django Model' },
        { name: 'Template', type: 'Django Template' },
        { name: 'Common Server', type: 'Application Server' },
        { name: 'Database', type: 'Database' },
      ],
      data_flows: [
        { source: 'Web Browser', destination: 'Backbone.js App', protocol: 'HTTP' },
        { source: 'Backbone.js App', destination: 'Event Handler', protocol: 'Internal' },
        { source: 'Event Handler', destination: 'REST API', protocol: 'HTTP/JSON' },
        { source: 'REST API', destination: 'Router', protocol: 'Internal' },
        { source: 'Router', destination: 'View', protocol: 'Internal' },
        { source: 'View', destination: 'Model', protocol: 'Internal' },
        { source: 'View', destination: 'Template', protocol: 'Internal' },
        { source: 'Model', destination: 'Common Server', protocol: 'HTTP/REST' },
        { source: 'Common Server', destination: 'Database', protocol: 'TCP/IP' },
      ],
      trust_boundaries: ['Client Browser', 'Frontend Layer', 'API Layer', 'Data Layer'],
    },
  },
];

/**
 * Get example threats by architecture ID.
 */
export function getExampleThreats(exampleId: string): SentinelThreat[] {
  switch (exampleId) {
    case 'ecommerce':
      return ecommerceThreats;
    case 'k8s-platform':
      return k8sThreats;
    case 'django-portal':
      return djangoThreats;
    default:
      return [];
  }
}

/**
 * Get full analysis result for an example.
 */
export function getExampleAnalysisResult(exampleId: string) {
  const example = EXAMPLE_ARCHITECTURES.find((e) => e.id === exampleId);
  if (!example) return null;

  return {
    architecture: example.data,
    threats: getExampleThreats(exampleId),
    report_markdown: generateExampleReport(example, getExampleThreats(exampleId)),
  };
}

/**
 * Generate a sample markdown report for the example.
 */
function generateExampleReport(
  example: ExampleArchitecture,
  threats: SentinelThreat[]
): string {
  const criticalCount = threats.filter((t) => t.severity === 'Critical').length;
  const highCount = threats.filter((t) => t.severity === 'High').length;

  return `# Threat Modeling Report: ${example.name}

## 1. EXECUTIVE SUMMARY

- **Project Name**: ${example.name}
- **Total Threats Found**: ${threats.length}
- **Critical Severity**: ${criticalCount}
- **High Severity**: ${highCount}
- **Overall Risk Assessment**: ${criticalCount > 0 ? 'CRITICAL' : highCount > 0 ? 'HIGH' : 'MEDIUM'}

## 2. ARCHITECTURE OVERVIEW

${example.description}

### Components (${example.componentCount})

| Component | Type |
|-----------|------|
${example.data.components.map((c) => `| ${c.name} | ${c.type} |`).join('\n')}

### Trust Boundaries

${example.data.trust_boundaries.map((b) => `- ${b}`).join('\n')}

## 3. STRIDE THREAT ANALYSIS

${threats
  .map(
    (t) => `### ${t.threat_id}: ${t.category}

**Severity**: ${t.severity}  
**Affected Component**: ${t.affected_component}  
${t.cwe_id ? `**CWE**: ${t.cwe_id}` : ''}

${t.description}

**Impact**: ${t.impact || 'Not specified'}

**Mitigation Steps**:
${t.mitigation_steps.map((s) => `- ${s}`).join('\n')}
`
  )
  .join('\n---\n\n')}

## 4. RECOMMENDATIONS

1. Address all Critical and High severity threats immediately
2. Implement defense-in-depth security controls
3. Conduct regular security assessments
4. Establish security monitoring and alerting

---

*This is a demonstration report generated from example data.*
`;
}
