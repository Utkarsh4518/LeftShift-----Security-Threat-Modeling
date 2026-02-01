/**
 * Type definitions for the Sentinel Frontend Visualization Layer.
 * 
 * These types define the contract between:
 * 1. Backend Sentinel analysis output
 * 2. Frontend RenderGraph for visualization
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

/** Lane assignments for component roles */
export type Lane = 0 | 1 | 2 | 3 | 4;

/** Role categories for lane mapping */
export type ComponentRole = 'external' | 'ingress' | 'compute' | 'data' | 'infra';

/** Node in the RenderGraph for visualization */
export interface RenderNode {
  id: string;
  label: string;
  type: string;
  lane: Lane;
  risk: Severity;
  threats: SentinelThreat[];
}

/** Edge in the RenderGraph for visualization */
export interface RenderEdge {
  id: string;
  from: string;
  to: string;
  protocol?: string;
}

/** Complete RenderGraph for React Flow visualization */
export interface RenderGraph {
  nodes: RenderNode[];
  edges: RenderEdge[];
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
}

/** Positioned edge for React Flow */
export interface PositionedEdge {
  id: string;
  source: string;
  target: string;
  type: 'dataFlowEdge';
  data: {
    protocol?: string;
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
