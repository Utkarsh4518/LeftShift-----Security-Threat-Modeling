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
// In production (Vercel), use Render backend URL from environment variable
// In development, use localhost or configured URL
function getApiBaseUrlInternal(): string {
  // Always use VITE_API_BASE_URL if set (for Render backend)
  // Otherwise fall back to localhost for development
  return import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
}

const API_BASE_URL = getApiBaseUrlInternal();
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
  // #region agent log
  const fullUrl = `${API_BASE_URL}${ANALYZE_ENDPOINT}`;
  fetch('http://127.0.0.1:7242/ingest/5b6b6abc-8724-4f4c-b306-ebb9d08f709a',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'analysisService.ts:analyzeArchitecture',message:'request URL and env',data:{apiBaseUrl:API_BASE_URL,fullUrl,envSet:!!(import.meta as unknown as { env?: { VITE_API_BASE_URL?: string } }).env?.VITE_API_BASE_URL,inputType:input.type},timestamp:Date.now(),sessionId:'debug-session',hypothesisId:'H1'})}).catch(()=>{});
  // #endregion
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

  let response: Response;
  try {
    response = await fetch(fullUrl, {
      method: 'POST',
      body: formData,
    });
  } catch (err) {
    // #region agent log
    const e = err as Error;
    fetch('http://127.0.0.1:7242/ingest/5b6b6abc-8724-4f4c-b306-ebb9d08f709a',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'analysisService.ts:fetch catch',message:'fetch threw',data:{message:e?.message,name:e?.name,cause:String(e?.cause ?? '')},timestamp:Date.now(),sessionId:'debug-session',hypothesisId:'H3'})}).catch(()=>{});
    // #endregion
    throw err;
  }

  if (!response.ok) {
    const errorText = await response.text();
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/5b6b6abc-8724-4f4c-b306-ebb9d08f709a',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'analysisService.ts:!response.ok',message:'backend returned error',data:{status:response.status,statusText:response.statusText,errorTextSlice:errorText.slice(0,200)},timestamp:Date.now(),sessionId:'debug-session',hypothesisId:'H4'})}).catch(()=>{});
    // #endregion
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
  return import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
}
