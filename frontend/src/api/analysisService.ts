/**
 * Analysis Service - Backend-agnostic API client for Sentinel.
 * 
 * Design principles:
 * - Single endpoint abstraction (POST /analyze)
 * - Configurable base URL via environment variable
 * - Ready for async polling pattern (future n8n integration)
 * - Does not tie frontend state to Sentinel internals
 */

import type { SentinelAnalysisResult, AnalysisInput } from '../compiler/types';

/** API configuration */
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
const ANALYZE_ENDPOINT = '/analyze';

/** Polling configuration for async analysis */
const POLL_INTERVAL = 2000; // 2 seconds
const MAX_POLL_ATTEMPTS = 60; // 2 minutes max

/**
 * Response from the analysis endpoint.
 * Supports both sync and async (polling) modes.
 */
interface AnalysisResponse {
  status: 'complete' | 'processing' | 'error';
  job_id?: string;
  result?: SentinelAnalysisResult;
  error?: string;
  progress?: number;
}

/**
 * Submit architecture for analysis.
 * Handles both file uploads and JSON submissions.
 */
export async function analyzeArchitecture(
  input: AnalysisInput
): Promise<SentinelAnalysisResult> {
  const formData = new FormData();

  if (input.type === 'image' && input.file) {
    formData.append('image', input.file);
  } else if (input.type === 'json' && input.json) {
    formData.append('json', JSON.stringify(input.json));
  } else if (input.type === 'example' && input.exampleId) {
    formData.append('example_id', input.exampleId);
  } else {
    throw new Error('Invalid input: must provide file, JSON, or example ID');
  }

  const response = await fetch(`${API_BASE_URL}${ANALYZE_ENDPOINT}`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Analysis failed: ${response.status} - ${errorText}`);
  }

  const data: AnalysisResponse = await response.json();

  // Handle async processing (future n8n support)
  if (data.status === 'processing' && data.job_id) {
    return await pollForResult(data.job_id);
  }

  if (data.status === 'error') {
    throw new Error(data.error || 'Analysis failed');
  }

  if (!data.result) {
    throw new Error('No result returned from analysis');
  }

  return data.result;
}

/**
 * Poll for analysis result (for async backends like n8n).
 */
async function pollForResult(jobId: string): Promise<SentinelAnalysisResult> {
  for (let attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt++) {
    await sleep(POLL_INTERVAL);

    const response = await fetch(`${API_BASE_URL}/jobs/${jobId}`);
    
    if (!response.ok) {
      throw new Error(`Failed to check job status: ${response.status}`);
    }

    const data: AnalysisResponse = await response.json();

    if (data.status === 'complete' && data.result) {
      return data.result;
    }

    if (data.status === 'error') {
      throw new Error(data.error || 'Analysis failed');
    }

    // Still processing, continue polling
  }

  throw new Error('Analysis timed out');
}

/**
 * Utility: sleep for specified milliseconds.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Check if the backend is available.
 */
export async function checkHealth(): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE_URL}/health`, {
      method: 'GET',
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Get the configured API base URL.
 */
export function getApiBaseUrl(): string {
  return API_BASE_URL;
}
