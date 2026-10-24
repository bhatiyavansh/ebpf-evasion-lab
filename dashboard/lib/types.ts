// Client-safe types and constants. No Node built-ins here so this module can be
// imported by client components without pulling fs/path into the browser bundle.

export type Tool = "falco" | "tracee" | "tetragon";
export const TOOLS: Tool[] = ["falco", "tracee", "tetragon"];

export type Status =
  | "confirmed_detection"
  | "telemetry_observed"
  | "partial"
  | "not_tested"
  | "confirmed_miss"
  | "collection_failed";

export interface NormRecord {
  experiment_id: string;
  tool: Tool;
  behavior: string;
  variant: string;
  status: Status;
  status_label: string;
  detected: boolean | null;
  event_observed: boolean;
  containerized: boolean;
  context_enriched: boolean;
  detection_type: string | null;
  rule_class: "builtin_security" | "custom_research" | null;
  alert_count: number | null;
  latency_ms: number | null;
  processes_observed: string[] | null;
  evidence_raw: string | null;
  evidence_events: string | null;
  confidence: "high" | "medium" | "low" | "n/a";
  run_id: string | null;
  provenance: "live" | "recorded" | null;
  started_at: string | null;
  ended_at: string | null;
  tool_version: string | null;
  dimensions: {
    execution: string;
    collection: string;
    telemetry: string;
    detection: string;
  } | null;
  notes: string;
  interpretation: string;
}

export interface RunRow {
  run_id: string;
  experiment_id: string;
  tool: Tool;
  provenance: "live" | "recorded";
  status: Status;
  started_at: string | null;
  ended_at: string | null;
  evidence_raw: string | null;
  evidence_events: string | null;
  processes_observed: string[] | null;
}

export interface CveEntry {
  id: string;
  name: string;
  class: string;
  cvss_v3: number;
  cvss_severity: string;
  impact: string;
  affected_range: string;
  fixed_versions: string[];
  sources: { label: string; url: string }[];
  applicability: { status: string; reason: string; confidence: string };
  modes_available: string[];
  mode_b_blocked_reason: string;
  reproduction_status?: string;
  reproduction_note?: string;
  simulation: {
    category: string;
    benign_workload: string;
    related_evidence_experiments: string[];
    disclaimer: string;
  };
}

export interface CveCatalog {
  description: string;
  host_assessment_basis: Record<string, unknown>;
  modes: Record<string, string>;
  cves: CveEntry[];
}

export interface Experiment {
  id: string;
  title: string;
  behavior: string;
  variant: string;
  purpose: string;
  command: string;
  shell_payload?: string;
  expected_observation: string;
  target_path?: string;
  benign_path?: string;
  shell_payload_benign?: string;
  baseline_reference?: string;
  timing_intervals_seconds?: number[];
  trials?: number;
  derived?: boolean;
  derived_from?: string[];
  tools: Tool[];
}

export interface Catalog {
  schema_version: string;
  description: string;
  detectors: Record<
    Tool,
    { label: string; role: string; has_alerting_engine: boolean; configured_events: string; image: string }
  >;
  experiments: Experiment[];
}

export interface Analysis {
  matrix: {
    experiment_id: string;
    title: string;
    behavior: string;
    variant: string;
    tools_in_scope?: Tool[];
    cells: Record<
      Tool,
      {
        status: Status;
        detection_type?: string | null;
        event_observed?: boolean;
        context_enriched?: boolean;
        rule_class?: string | null;
        provenance?: string | null;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        dimensions?: any;
      }
    >;
  }[];
  detection_vs_telemetry: Record<
    Tool,
    {
      eligible_evaluations: number;
      confirmed_detections: number;
      telemetry_observed: number;
      partial: number;
      confirmed_miss: number;
      detection_rate: number | null;
      telemetry_rate: number | null;
      has_alerting_engine: boolean;
    }
  >;
  baseline_vs_adaptive: {
    adaptive_id: string;
    adaptive_title: string;
    variant: string;
    baseline_id: string;
    tools: Record<
      Tool,
      {
        baseline_status: Status;
        adaptive_status: Status;
        baseline_processes: string[] | null;
        adaptive_processes: string[] | null;
        observability_change: "unchanged" | "reduced" | "increased";
      }
    >;
  }[];
  data_completeness: {
    experiments_defined: number;
    detectors: number;
    grid_cells: number;
    evaluated_cells: number;
    not_tested_cells: number;
    coverage_fraction: number | null;
    cells_with_evidence_file: number;
    cells_with_event_evidence: number;
    experiments_evaluated?: number;
    derived_experiments?: number;
    live_cells?: number;
    recorded_cells?: number;
  };
  evidence_coverage: { experiment_id: string; tools_defined: Tool[]; tools_with_evidence: Tool[]; complete: boolean }[];
  latency_summary: { measurements_available: number; note: string; values_ms: number[] | null };
  cross_tool_status_counts: Record<Tool, Record<string, number>>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  e06_repeatability?: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  e07_sensitive_vs_benign?: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  e08_network_coverage?: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  e09_sequence_timing?: any;
}

export interface Environment {
  captured_at: string;
  kernel: string;
  arch: string;
  os: string;
  btf_vmlinux: boolean;
  docker_version: string;
  detectors: Record<string, string>;
  image_digests: Record<string, string>;
}

export type ComparisonOutcome =
  | "DETECTED"
  | "TELEMETRY_ONLY"
  | "NOT_DETECTED"
  | "NOT_EVALUATED"
  | "EXECUTION_FAILED"
  | "COLLECTION_FAILED"
  | "INCONCLUSIVE";

export interface ComparisonCell {
  tool: string;
  config: "baseline" | "configured";
  track_key: string;
  headline_outcome: ComparisonOutcome;
  trial_counts: Record<string, number>;
  trials_executed: number;
  trials_total: number;
  valid_trials?: number;
  detections: number;
  expected?: string;
  config_note?: string;
  trials: {
    trial: number;
    outcome: ComparisonOutcome;
    detail: string;
    run_id?: string;
    evidence_events?: string;
    started_at?: string;
  }[];
}

export interface ComparisonScenario {
  id: string;
  title: string;
  mitre: string[];
  technique_note: string;
  payload: string;
  hypothesis: string;
  success_criteria: string;
  detection_objective: string;
  cells: Record<string, ComparisonCell>;
}

export interface Comparison {
  qualifying_detection_criteria: Record<string, string>;
  scenarios: ComparisonScenario[];
  detection_rates: {
    baseline: { detections: number; eligible_evaluations: number; rate: number | null };
    configured: { detections: number; eligible_evaluations: number; rate: number | null };
  };
  per_scenario_rates?: {
    scenario: string;
    title: string;
    condition: "baseline" | "configured";
    tools: string[];
    detection_trials: number;
    valid_trials: number;
    rate: number | null;
  }[];
  per_tool_config: Record<string, { detected: number; eligible: number; trials?: number }>;
  coverage_note?: string;
  benign_control?: {
    scenario: string;
    rows: { tool: string; config: string; false_positive_detections: number; valid_trials: number; specific: boolean }[];
    all_specific: boolean;
    note: string;
  } | null;
}

export interface DashboardData {
  catalog: Catalog;
  records: NormRecord[];
  analysis: Analysis | null;
  environment: Environment | null;
  cve: CveCatalog | null;
  runs: RunRow[];
  comparison: Comparison | null;
}
