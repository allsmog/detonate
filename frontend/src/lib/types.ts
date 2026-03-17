export interface Submission {
  id: string;
  filename: string | null;
  url: string | null;
  file_hash_sha256: string;
  file_hash_md5: string | null;
  file_hash_sha1: string | null;
  file_size: number | null;
  file_type: string | null;
  mime_type: string | null;
  storage_path: string;
  submitted_at: string | null;
  tags: string[] | null;
  verdict: string;
  score: number;
  ai_summary: string | null;
  ai_verdict: string | null;
  ai_score: number | null;
  ai_analyzed_at: string | null;
}

export interface SubmissionListResponse {
  items: Submission[];
  total: number;
  limit: number;
  offset: number;
}

export interface ServiceStatus {
  status: string;
}

export interface HealthResponse {
  status: string;
  db: ServiceStatus;
  redis: ServiceStatus;
  minio: ServiceStatus;
}

export interface Conversation {
  id: string;
  submission_id: string;
  title: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface ChatMessage {
  id: string;
  conversation_id: string;
  role: string;
  content: string;
  created_at: string | null;
}

export interface AITask {
  id: string;
  submission_id: string;
  task_type: string;
  status: string;
  celery_task_id: string | null;
  input_data: Record<string, unknown> | null;
  output_data: Record<string, unknown> | null;
  error: string | null;
  started_at: string | null;
  completed_at: string | null;
  model_used: string | null;
  tokens_used: Record<string, unknown> | null;
  created_at: string | null;
}

export interface AISummary {
  submission_id: string;
  summary: string | null;
  generated: boolean;
}

export interface AIStatus {
  enabled: boolean;
  configured: boolean;
  provider: string | null;
  model: string | null;
}

export interface IDSAlert {
  signature_id: number;
  signature: string;
  severity: number;
  category: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  timestamp: string;
}

export interface IDSSummary {
  total_alerts: number;
  high_severity: number;
  medium_severity: number;
  low_severity: number;
  categories: string[];
}

export interface AnalysisResult {
  id: string;
  submission_id: string;
  type: string;
  status: string;
  machine_id: string | null;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  config: Record<string, unknown> | null;
  result: Record<string, unknown> | null;
  celery_task_id: string | null;
}

export interface AnalysisListResponse {
  items: AnalysisResult[];
  total: number;
}

export interface YaraMatch {
  rule: string;
  tags: string[];
  meta: Record<string, string>;
  strings: string[];
}

export interface YaraDroppedFileMatch {
  file: string;
  matches: YaraMatch[];
}

export interface YaraResults {
  sample_matches: YaraMatch[];
  dropped_file_matches: YaraDroppedFileMatch[];
  total_matches: number;
  rules_loaded: number;
}

export interface YaraScanResult {
  matches: YaraMatch[];
  total_matches: number;
  filename: string | null;
  file_hash: string | null;
  error?: string;
  enabled?: boolean;
}

export interface PoolMachine {
  id: string;
  name: string;
  machinery: string;
  platform: string;
  status: string;
  ip_address: string | null;
  container_id: string | null;
  last_health_check: string | null;
  locked_at: string | null;
}

export interface MachineListResponse {
  items: PoolMachine[];
  total: number;
}

export interface PoolStatus {
  total: number;
  available: number;
  busy: number;
  error: number;
  platform: string;
  pool_enabled: boolean;
}

// Auth
export interface User {
  id: string;
  email: string;
  display_name: string | null;
  role: string;
  is_active: boolean;
  created_at: string | null;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface APIKeyInfo {
  id: string;
  key_prefix: string;
  name: string | null;
  is_active: boolean;
  created_at: string | null;
}

// Screenshots / Video
export interface ScreenshotInfo {
  url: string;
  index: number;
  timestamp?: number;
}

export interface AnalysisMedia {
  screenshots: ScreenshotInfo[];
  video_url: string | null;
}

// VNC
export interface VNCSessionInfo {
  ws_url: string;
  timeout: number;
  ws_port: number;
}

// AI Report
export interface ReportResponse {
  report: string;
  format: string;
}

// Similar Submissions
export interface SimilarSubmission {
  id: string;
  filename: string | null;
  similarity_score: number;
  shared_iocs: string[];
  verdict: string;
}

export interface SimilarSubmissionsResponse {
  items: SimilarSubmission[];
  total: number;
}

// Threat Intelligence
export interface ThreatIntelProviderResult {
  provider: string;
  data: Record<string, unknown> | null;
  cached: boolean;
  error: string | null;
}

export interface ThreatIntelAggregateResponse {
  hash_results: ThreatIntelProviderResult[];
  ip_results: Record<string, ThreatIntelProviderResult[]>;
  domain_results: Record<string, ThreatIntelProviderResult[]>;
}

export interface ThreatIntelProviderStatus {
  name: string;
  configured: boolean;
}

export interface ThreatIntelStatusResponse {
  providers: ThreatIntelProviderStatus[];
}

// MITRE ATT&CK
export interface MITRETechniqueMatch {
  technique_id: string;
  name: string;
  confidence: number;
  evidence: string;
  source: string;
}

export interface MITREAnalysisResponse {
  techniques: MITRETechniqueMatch[];
  tactics_coverage: Record<string, number>;
}

export interface MITRETechniqueDetail {
  technique_id: string;
  name: string;
  description: string;
  tactics: string[];
  platforms: string[];
  url: string;
}

// Search
export interface SearchFilters {
  q?: string;
  verdict?: string;
  file_type?: string;
  tag?: string;
  score_min?: number;
  score_max?: number;
  date_from?: string;
  date_to?: string;
  has_analysis?: boolean;
  sort_by?: string;
  sort_order?: string;
}

export interface SearchResponse {
  items: Submission[];
  total: number;
  limit: number;
  offset: number;
  query: string;
  filters: Record<string, unknown>;
}

// Dashboard
export interface DashboardStats {
  total_submissions: number;
  total_analyses: number;
  verdicts: Record<string, number>;
  submissions_today: number;
  submissions_this_week: number;
  submissions_this_month: number;
  average_score: number;
  top_file_types: { type: string; count: number }[];
  top_tags: { tag: string; count: number }[];
  analysis_status_breakdown: Record<string, number>;
}

export interface TimelinePoint {
  date: string;
  count: number;
  malicious: number;
  suspicious: number;
}

// IOC Export
export interface IOCData {
  hashes: { sha256: string; md5: string | null; sha1: string | null };
  ips: { value: string; port?: number; source?: string }[];
  domains: { value: string; type?: string; source?: string }[];
  urls: { value: string; source?: string }[];
  emails: { value: string }[];
  file_paths: { value: string; size?: number }[];
  registry_keys: { value: string }[];
  mutexes: { value: string }[];
}

// Comments
export interface Comment {
  id: string;
  submission_id: string;
  user_id: string;
  user_email: string;
  user_display_name: string | null;
  content: string;
  created_at: string | null;
  updated_at: string | null;
}

// Webhooks
export interface WebhookInfo {
  id: string;
  url: string;
  events: string[];
  is_active: boolean;
  created_at: string | null;
  last_triggered_at: string | null;
  failure_count: number;
}

// Network Analysis (enriched)
export interface EnrichedConnection {
  protocol: string;
  address: string;
  port: number;
  service: string;
  is_private: boolean;
  direction: string;
}

export interface NetworkAnalysisData {
  connections: EnrichedConnection[];
  connection_summary: {
    total: number;
    external: number;
    internal: number;
    services: string[];
    unique_ips: string[];
  };
  dns_analysis: {
    total_queries: number;
    unique_domains: string[];
    query_types: Record<string, number>;
  };
  suspicious_indicators: string[];
}

export interface PcapStats {
  total_packets: number;
  total_bytes: number;
  pcap_size: number;
}

export interface NetworkAnalysisResponse {
  connections: EnrichedConnection[];
  connection_summary: {
    total: number;
    external: number;
    internal: number;
    services: string[];
    unique_ips: string[];
  };
  dns_analysis: {
    total_queries: number;
    unique_domains: string[];
    query_types: Record<string, number>;
  };
  http_hosts: string[];
  pcap_stats: PcapStats;
  suspicious_indicators: string[];
}

export interface NetworkIOCsResponse {
  ips: string[];
  private_ips: string[];
  domains: string[];
  urls: string[];
  total: number;
}

// YARA Management
export interface YaraRuleFile {
  filename: string;
  rule_count: number;
  last_modified: number;
  size_bytes: number;
}

export interface YaraRuleContent {
  filename: string;
  content: string;
}

export interface YaraValidateResponse {
  valid: boolean;
  error: string | null;
}

// Settings / Feature Flags
export interface FeatureFlags {
  ai_enabled: boolean;
  yara_enabled: boolean;
  suricata_enabled: boolean;
  auth_enabled: boolean;
  screenshots_enabled: boolean;
  qemu_enabled: boolean;
  sandbox_pool_enabled: boolean;
}

// Teams
export interface Team {
  id: string;
  name: string;
  description: string | null;
  is_active: boolean;
  created_at: string | null;
  member_count: number;
}

// Static Analysis
export interface EntropyResult {
  overall: number;
  sections: Record<string, number> | null;
}

export interface InterestingStrings {
  urls: string[];
  ips: string[];
  emails: string[];
  registry_keys: string[];
  file_paths: string[];
}

export interface StringsResult {
  total_ascii: number;
  total_wide: number;
  interesting: InterestingStrings;
  ascii_strings: string[];
  wide_strings: string[];
}

export interface PESection {
  name: string;
  virtual_address: string;
  virtual_size: number;
  raw_size: number;
  entropy: number;
  characteristics: string;
}

export interface PEExport {
  name: string;
  ordinal: number;
  address: string;
}

export interface PEResource {
  type: string;
  offset: number;
  size: number;
  language: number;
}

export interface PEAnalysis {
  machine: string;
  timestamp: number;
  characteristics: string | null;
  is_dll: boolean;
  is_exe: boolean;
  subsystem: number | null;
  entry_point: string | null;
  image_base: string | null;
  linker_version: string | null;
  sections: PESection[];
  imports: Record<string, string[]>;
  import_count: number;
  exports: PEExport[];
  resources: PEResource[];
  has_signature: boolean;
  suspicious_indicators: string[];
}

export interface ELFAnalysis {
  class_: string;
  type: string;
  machine: string;
  endian: string;
  entry_point: string;
  program_headers: number;
  section_headers: number;
}

export interface StaticAnalysisResponse {
  entropy: EntropyResult;
  strings: StringsResult;
  pe: PEAnalysis | null;
  elf: ELFAnalysis | null;
  file_size: number;
  filename: string;
}
