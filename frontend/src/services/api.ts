// API Service for Seva Cyber Sandbox
import type {
  HealthResponse,
  UnifiedAnalysisResponse,
  CaseRecord,
  ThreatGraphResponse,
  AiModelsResponse,
  SanitizeResponse,
} from '../types';

const API_BASE = '/api';

function getAuthHeaders(): HeadersInit {
  const token = localStorage.getItem('seva_operator_token');
  const headers: Record<string, string> = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

async function safeFetch(url: string, init?: RequestInit): Promise<Response> {
  try {
    return await fetch(url, init);
  } catch (err: any) {
    throw new Error(
      'Network connection failed. The local API server at http://127.0.0.1:8000 could not be reached.'
    );
  }
}

async function handleResponseError(res: Response, defaultMessage: string): Promise<never> {
  if (res.status === 502 || res.status === 503 || res.status === 504) {
    let extra = '';
    try {
      const errJson = await res.json();
      if (errJson && errJson.detail) {
        extra = ` (${errJson.detail})`;
      }
    } catch {}
    throw new Error(
      `Local API server is unreachable (HTTP ${res.status} ${res.statusText || 'Bad Gateway'})${extra}. Please verify that the FastAPI backend is running on http://127.0.0.1:8000.`
    );
  }

  let errorDetail = '';
  try {
    const errorJson = await res.json();
    if (errorJson && typeof errorJson === 'object') {
      if (typeof errorJson.detail === 'string') {
        errorDetail = errorJson.detail;
      } else if (Array.isArray(errorJson.detail)) {
        errorDetail = errorJson.detail
          .map((d: any) => (d.msg ? `${d.loc ? d.loc.slice(-1) + ': ' : ''}${d.msg}` : JSON.stringify(d)))
          .join('; ');
      } else if (errorJson.message) {
        errorDetail = errorJson.message;
      }
    }
  } catch {
    try {
      const text = await res.text();
      if (text && text.length < 250) {
        errorDetail = text;
      }
    } catch {}
  }
  throw new Error(errorDetail || `${defaultMessage} (HTTP ${res.status}: ${res.statusText})`);
}

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await safeFetch(`${API_BASE}/health`);
  if (!res.ok) await handleResponseError(res, 'Health check failed');
  return res.json();
}

export async function fetchDashboardSummary(): Promise<any> {
  const res = await safeFetch(`${API_BASE}/dashboard/summary`);
  if (!res.ok) await handleResponseError(res, 'Failed to load dashboard summary');
  return res.json();
}

export async function loginOperator(username: string, password: string): Promise<any> {
  const res = await safeFetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    await handleResponseError(res, 'Authentication failed');
  }
  const data = await res.json();
  if (data.session_token) {
    localStorage.setItem('seva_operator_token', data.session_token);
  }
  return data;
}

export async function logoutOperator(): Promise<void> {
  await safeFetch(`${API_BASE}/auth/logout`, {
    method: 'POST',
    headers: getAuthHeaders(),
  }).catch(() => {});
  localStorage.removeItem('seva_operator_token');
}

export async function fetchAuthMe(): Promise<any> {
  try {
    const res = await safeFetch(`${API_BASE}/auth/me`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) return { authenticated: false, username: 'anonymous', role: 'viewer' };
    return res.json();
  } catch {
    return { authenticated: false, username: 'anonymous', role: 'viewer' };
  }
}

export async function analyzeUnified(formData: FormData): Promise<UnifiedAnalysisResponse> {
  const res = await safeFetch(`${API_BASE}/analyze/unified`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: formData,
  });
  if (!res.ok) {
    await handleResponseError(res, 'Evidence analysis failed');
  }
  return res.json();
}

export async function analyzeMessage(message: string, enableShadowAi: boolean = true): Promise<UnifiedAnalysisResponse> {
  const res = await safeFetch(`${API_BASE}/analyze/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({ message, enable_shadow_ai: enableShadowAi }),
  });
  if (!res.ok) {
    await handleResponseError(res, 'Message analysis failed');
  }
  return res.json();
}

export async function analyzeUrl(url: string): Promise<any> {
  const res = await safeFetch(`${API_BASE}/analyze/url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) {
    await handleResponseError(res, 'URL analysis failed');
  }
  return res.json();
}

export async function analyzeApk(file: File, enableShadowAi: boolean = true): Promise<UnifiedAnalysisResponse> {
  const formData = new FormData();
  formData.append('apk_file', file);
  formData.append('enable_shadow_ai', String(enableShadowAi));
  const res = await safeFetch(`${API_BASE}/analyze/apk`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: formData,
  });
  if (!res.ok) {
    await handleResponseError(res, 'APK analysis failed');
  }
  return res.json();
}

export async function analyzeScheme(claimText: string): Promise<any> {
  const res = await safeFetch(`${API_BASE}/analyze/scheme`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({ claim_text: claimText }),
  });
  if (!res.ok) {
    await handleResponseError(res, 'Scheme verification failed');
  }
  return res.json();
}

export async function fetchCases(search?: string, riskCategory?: string): Promise<{ total_cases: number; cases: CaseRecord[] }> {
  const params = new URLSearchParams();
  if (search) params.append('search', search);
  if (riskCategory && riskCategory !== 'ALL') params.append('risk_category', riskCategory);
  const res = await safeFetch(`${API_BASE}/cases?${params.toString()}`);
  if (!res.ok) {
    await handleResponseError(res, 'Failed to load cases');
  }
  return res.json();
}

export async function fetchCaseDetails(caseId: string): Promise<{ case: CaseRecord; investigation_details?: any }> {
  const res = await safeFetch(`${API_BASE}/cases/${encodeURIComponent(caseId)}`);
  if (!res.ok) {
    await handleResponseError(res, 'Failed to load case details');
  }
  return res.json();
}

export async function saveInvestigation(analysisResult: any, consentGiven: boolean = true): Promise<any> {
  const res = await safeFetch(`${API_BASE}/cases/save-investigation`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({
      analysis_result: analysisResult,
      submitted_by: 'web_investigator',
      consent_given: consentGiven,
    }),
  });
  if (!res.ok) {
    await handleResponseError(res, 'Failed to save investigation');
  }
  return res.json();
}

export async function fetchThreatGraph(): Promise<ThreatGraphResponse> {
  const res = await safeFetch(`${API_BASE}/threat-intel/graph`);
  if (!res.ok) {
    await handleResponseError(res, 'Failed to load threat intelligence graph');
  }
  return res.json();
}

export async function fetchThreatIndicators(type?: string, reviewState?: string): Promise<any> {
  const params = new URLSearchParams();
  if (type) params.append('indicator_type', type);
  if (reviewState) params.append('review_state', reviewState);
  const res = await safeFetch(`${API_BASE}/threat-intelligence/indicators?${params.toString()}`);
  if (!res.ok) {
    await handleResponseError(res, 'Failed to load threat indicators');
  }
  return res.json();
}

export async function fetchAiModels(): Promise<AiModelsResponse> {
  const res = await safeFetch(`${API_BASE}/ai/models`);
  if (!res.ok) {
    await handleResponseError(res, 'Failed to load AI models telemetry');
  }
  return res.json();
}

export async function sanitizeText(text: string): Promise<SanitizeResponse> {
  const res = await safeFetch(`${API_BASE}/privacy/sanitize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) {
    await handleResponseError(res, 'Sanitization failed');
  }
  return res.json();
}

export async function uploadEvidenceStorage(file: File, artifactType: string = 'evidence'): Promise<any> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('artifact_type', artifactType);
  const res = await safeFetch(`${API_BASE}/storage/upload`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: formData,
  });
  if (!res.ok) {
    await handleResponseError(res, 'Evidence storage upload failed');
  }
  return res.json();
}

// Unified client object for ergonomic calls across components
export const apiClient = {
  getHealth: fetchHealth,
  getDashboardSummary: fetchDashboardSummary,
  login: loginOperator,
  logout: logoutOperator,
  getAuthMe: fetchAuthMe,
  analyzeUnified,
  analyzeMessage,
  analyzeUrl,
  analyzeApk,
  analyzeScheme,
  getCases: fetchCases,
  getCaseDetails: fetchCaseDetails,
  saveInvestigation,
  getThreatGraph: fetchThreatGraph,
  getIndicators: fetchThreatIndicators,
  uploadStorage: uploadEvidenceStorage,
  getAiTelemetry: async () => {
    const data = await fetchAiModels();
    return {
      model_name: data.active_model.version,
      operating_mode: data.active_model.operating_mode,
      is_production_authoritative: data.active_model.is_production_authoritative,
      macro_f1: data.active_model.metrics.macro_f1,
      precision: data.active_model.metrics.precision,
      recall: data.active_model.metrics.recall,
      total_eval_samples: data.active_model.metrics.evaluation_samples,
      concordance_rate: 1.0,
      score_delta_with_rules: 0.0,
      training_gate_status: data.candidate_training_gate.status,
      real_world_samples_count: data.candidate_training_gate.current_reviewed_evidence,
      min_required_samples: data.candidate_training_gate.reviewed_evidence_threshold,
    };
  },
  sanitizeEvidence: async (text: string) => {
    const res = await sanitizeText(text);
    return {
      sanitized_text: res.sanitized_text,
      redacted_entities_count: (res.redactions_applied.aadhaar_numbers ? 1 : 0) + (res.redactions_applied.phone_numbers ? 1 : 0),
    };
  },
};
