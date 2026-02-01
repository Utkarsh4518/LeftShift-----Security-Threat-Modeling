/**
 * Type definitions for the Sentinel Frontend Visualization Layer.
 * 
 * These types define the contract between:
 * 1. Backend Sentinel analysis output
 * 2. Frontend RenderGraph for visualization
 * 3. Domain-based layout system
 */

// =============================================================================
// Sentinel Input Types (from backend)
// =============================================================================

/** Component from Sentinel architecture analysis */
export interface SentinelComponent {
  name: string;
  type: string;
}

/** Data flow between components */
export interface SentinelDataFlow {
  source: string;
  destination: string;
  protocol: string;
}

/** Architecture schema from Sentinel */
export interface SentinelArchitecture {
  project_name: string;
  description: string;
  components: SentinelComponent[];
  data_flows: SentinelDataFlow[];
  trust_boundaries: string[];
}

/** STRIDE threat from Sentinel analysis */
export interface SentinelThreat {
  threat_id: string;
  category: string;
  description: string;
  affected_component: string;
  severity: Severity;
  mitigation_steps: string[];
  cwe_id?: string;
  preconditions?: string[];
  impact?: string;
  example?: string;
}

/** Architectural weakness identified by Sentinel */
export interface SentinelWeakness {
  weakness_id: string;
  title: string;
  description: string;
  impact: string;
  mitigation: string;
}

/** CVE/Threat record from vulnerability discovery */
export interface SentinelCVE {
  cve_id: string;
  summary: string;
  severity: Severity;
  affected_products: string;
  cvss_score?: number;
  is_actively_exploited: boolean;
}

/** Complete Sentinel analysis result */
export interface SentinelAnalysisResult {
  architecture: SentinelArchitecture;
  threats: SentinelThreat[];
  weaknesses?: SentinelWeakness[];
  cves?: SentinelCVE[];
  report_markdown?: string;
}

// =============================================================================
// RenderGraph Types (frontend visualization)
// =============================================================================

/** Severity levels for threats */
export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'None';

/** Lane assignments for component roles (left-to-right) */
export type Lane = 0 | 1 | 2 | 3 | 4 | 5;

/** Role categories for lane mapping */
export type ComponentRole = 
  | 'external'      // Data Sources domain
  | 'ingress'       // Data Sources domain
  | 'gateway'       // Gateway domain
  | 'security'      // Security domain
  | 'orchestration' // Processing domain
  | 'compute'       // Processing domain
  | 'messaging'     // Messaging domain
  | 'ai'            // AI Services domain
  | 'data'          // Storage domain
  | 'analytics'     // Analytics domain
  | 'monitoring'    // Monitoring domain
  | 'edge'          // Edge/CDN domain
  | 'infra';        // Infrastructure domain

/** Domain identifiers for grouping components */
export type DomainId = 
  | 'data-sources' 
  | 'gateway'
  | 'security'
  | 'processing' 
  | 'messaging'
  | 'ai-services' 
  | 'storage' 
  | 'analytics'
  | 'monitoring'
  | 'edge'
  | 'infra';

/** Edge type for visual differentiation */
export type EdgeType = 'primary' | 'control' | 'secondary' | 'infra';

/** Routing direction for long-range edges */
export type RoutingDirection = 'above' | 'below';

/** Node in the RenderGraph for visualization */
export interface RenderNode {
  id: string;
  label: string;
  type: string;
  role: ComponentRole;
  lane: Lane;
  risk: Severity;
  threats: SentinelThreat[];
  /** Domain this node belongs to */
  domainId: DomainId;
}

/** Edge in the RenderGraph for visualization */
export interface RenderEdge {
  id: string;
  from: string;
  to: string;
  protocol?: string;
  edgeType: EdgeType;
  /** Number of collapsed edges (for infra edges) */
  collapsedCount?: number;
  /** Index for staggering overlapping edges */
  edgeIndex?: number;
  /** True if edge spans non-adjacent domains (distance > 1) */
  isLongRange?: boolean;
  /** Routing direction for long-range edges through backbone */
  routingDirection?: RoutingDirection;
  /** Domain distance (gridPosition difference) */
  domainDistance?: number;
}

/** Domain container for grouping related components */
export interface Domain {
  id: DomainId;
  label: string;
  icon: string;
  roles: ComponentRole[];
  /** Position in the grid (0-4 for 5 domains) */
  gridPosition: number;
  /** Computed position after layout */
  position: { x: number; y: number };
  /** Computed size based on contained nodes */
  size: { width: number; height: number };
  /** Nodes contained in this domain */
  nodes: RenderNode[];
  /** Highest severity among contained nodes */
  maxSeverity: Severity;
}

/** Complete RenderGraph for React Flow visualization */
export interface RenderGraph {
  /** Nodes grouped by domain */
  domains: Domain[];
  /** All nodes (flat list for edge routing) */
  nodes: RenderNode[];
  /** Edges between nodes */
  edges: RenderEdge[];
  /** Metadata */
  metadata: {
    projectName: string;
    description: string;
    trustBoundaries: string[];
    totalThreats: number;
    criticalCount: number;
    highCount: number;
  };
}

// =============================================================================
// React Flow Types (positioned nodes/edges)
// =============================================================================

/** Positioned node for React Flow */
export interface PositionedNode {
  id: string;
  type: 'componentNode';
  position: { x: number; y: number };
  data: RenderNode;
  parentId?: string; // Domain ID for grouping
  extent?: 'parent';
}

/** Positioned domain container for React Flow */
export interface PositionedDomain {
  id: string;
  type: 'domainContainer';
  position: { x: number; y: number };
  data: Domain;
  style?: { width: number; height: number };
}

/** Positioned edge for React Flow */
export interface PositionedEdge {
  id: string;
  source: string;
  target: string;
  type: 'dataFlowEdge';
  data: {
    protocol?: string;
    edgeType: EdgeType;
    collapsedCount?: number;
    edgeIndex?: number;
    isLongRange?: boolean;
    routingDirection?: RoutingDirection;
    domainDistance?: number;
    /** Domain bounds for backbone routing */
    domainBounds?: {
      topY: number;
      bottomY: number;
    };
  };
  animated?: boolean;
}

// =============================================================================
// API Types
// =============================================================================

/** Input for analysis request */
export interface AnalysisInput {
  type: 'image' | 'json' | 'example';
  file?: File;
  json?: object;
  exampleId?: string;
}

/** Status of analysis request */
export type AnalysisStatus = 'idle' | 'uploading' | 'analyzing' | 'complete' | 'error';

/** Analysis state for the hook */
export interface AnalysisState {
  status: AnalysisStatus;
  progress?: number;
  result?: SentinelAnalysisResult;
  error?: string;
}

// =============================================================================
// Example Architecture Types
// =============================================================================

/** Example architecture for quick testing */
export interface ExampleArchitecture {
  id: string;
  name: string;
  description: string;
  componentCount: number;
  highlights: string[];
  thumbnail?: string;
  data: SentinelArchitecture;
}
