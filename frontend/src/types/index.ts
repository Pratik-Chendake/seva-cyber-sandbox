// TypeScript Type Definitions for Seva Cyber Sandbox

export interface HealthResponse {
  status: 'operational' | 'degraded';
  timestamp_utc: string;
  database: {
    connected: boolean;
    path: string;
    cases_count: number;
    indicators_count: number;
    lifecycle_audit_records: number;
    error?: string | null;
  };
  active_model: {
    version: string;
    operating_mode: string;
    is_production_authoritative: boolean;
    governance_note: string;
  };
  platform: {
    version: string;
    name: string;
    visual_identity: string;
    execution_environment: string;
  };
  ai_engine?: {
    active_model: string;
    operating_mode: string;
    is_production_authoritative: boolean;
  };
  test_suite?: {
    total_tests: number;
    passed: number;
    status: string;
  };
  environment?: {
    python_version: string;
    os: string;
    cloud_cost: string;
  };
}

export interface AiTelemetryResponse {
  model_name: string;
  operating_mode: string;
  is_production_authoritative: boolean;
  macro_f1: number;
  precision: number;
  recall: number;
  total_eval_samples: number;
  concordance_rate: number;
  score_delta_with_rules: number;
  training_gate_status: string;
  real_world_samples_count: number;
  min_required_samples: number;
}

export interface ArtifactResult {
  artifact_id: string;
  artifact_type: 'message' | 'url' | 'apk' | 'document_pdf' | 'image' | 'text_file' | 'unsupported';
  target_identifier: string;
  status: 'completed' | 'failed' | 'rejected' | 'unsupported';
  risk_score: number;
  risk_category: string;
  badge_color: string;
  artifact_sha256?: string;
  error?: string | null;
  analysis_result?: any;
  scored_result?: any;
  shadow_eval?: any;
}

export interface CorrelationFinding {
  correlation_id: string;
  correlation_type: string;
  source_artifact_id: string;
  target_artifact_id: string;
  headline_en: string;
  headline_mr: string;
  detail_en: string;
  detail_mr: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  supporting_evidence: string[];
  limitations_note: string;
}

export interface UnifiedAnalysisResponse {
  investigation_id: string;
  created_at_utc: string;
  summary_stats: {
    total_artifacts: number;
    completed_count: number;
    failed_count: number;
    unsupported_count: number;
  };
  overall_verdict: {
    score: number;
    risk_category: string;
    badge_color: string;
    driving_artifact_id?: string | null;
    key_observations: string[];
    authoritative_score_delta?: number;
    note?: string;
  };
  artifacts: ArtifactResult[];
  correlations: CorrelationFinding[];
}

export interface CaseRecord {
  case_id: string;
  timestamp_utc: string;
  analysis_type: string;
  analysis_status: string;
  risk_score: number;
  risk_category: string;
  badge_color: string;
  target_identifier: string;
  recommended_action: string;
  sha256_hash?: string;
  observed_evidence: string[];
  heuristic_inferences: string[];
  metadata?: any;
  consent_given?: boolean;
}

export interface ThreatNode {
  id: string;
  name: string;
  type: 'campaign' | 'indicator' | 'case';
  cluster_type?: string;
  indicator_type?: string;
  severity?: string;
  review_state?: string;
  confidence?: number;
  size: number;
  color: string;
  status?: string;
  occurrence_count?: number;
  case_id?: string;
  risk_score?: number;
  // Dynamic 3D simulation coordinates
  x?: number;
  y?: number;
  z?: number;
}

export interface ThreatLink {
  source: string;
  target: string;
  strength: number;
}

export interface ThreatGraphResponse {
  nodes: ThreatNode[];
  links: ThreatLink[];
  meta: {
    total_nodes: number;
    total_links: number;
    palette: Record<string, string>;
  };
}

export interface AiModelsResponse {
  active_model: {
    version: string;
    operating_mode: string;
    is_production_authoritative: boolean;
    last_known_good_version: string;
    architecture: {
      type: string;
      input_dimension: number;
      hidden_layers: number[];
      output_classes: number;
      activation: string;
      training_seed: number;
    };
    metrics: {
      macro_f1: number;
      precision: number;
      recall: number;
      evaluation_samples: number;
      concordance_rate_with_rules: string;
    };
    governance_safeguard: string;
  };
  candidate_training_gate: {
    status: string;
    reviewed_evidence_threshold: number;
    current_reviewed_evidence: number;
    human_in_the_loop_required: boolean;
  };
}

export interface SanitizeResponse {
  original_length: number;
  sanitized_length: number;
  sanitized_text: string;
  redactions_applied: {
    aadhaar_numbers: boolean;
    phone_numbers: boolean;
  };
  privacy_gate_status: string;
  zero_network_disclosure: string;
}
