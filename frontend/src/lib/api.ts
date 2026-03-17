import type {
  AIStatus,
  AISummary,
  AITask,
  AnalysisListResponse,
  AnalysisMedia,
  AnalysisResult,
  ChatMessage,
  Conversation,
  HealthResponse,
  MachineListResponse,
  MITREAnalysisResponse,
  MITRETechniqueDetail,
  NetworkAnalysisResponse,
  NetworkIOCsResponse,
  PoolMachine,
  PoolStatus,
  ReportResponse,
  SimilarSubmissionsResponse,
  StaticAnalysisResponse,
  Submission,
  SubmissionListResponse,
  ThreatIntelAggregateResponse,
  ThreatIntelStatusResponse,
  TokenResponse,
  User,
  VNCSessionInfo,
  YaraRuleContent,
  YaraRuleFile,
  YaraScanResult,
  YaraValidateResponse,
} from "./types";

const API_BASE = "/api/v1";

class ApiClient {
  private _getAuthHeaders(): Record<string, string> {
    if (typeof window === "undefined") return {};
    const token = localStorage.getItem("detonate_token");
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const authHeaders = this._getAuthHeaders();
    const headers = { ...authHeaders, ...(init?.headers || {}) };
    const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
    if (!res.ok) {
      const body = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(body.detail || `Request failed: ${res.status}`);
    }
    return res.json();
  }

  async submitFile(file: File, tags?: string): Promise<Submission> {
    const formData = new FormData();
    formData.append("file", file);
    if (tags) {
      formData.append("tags", tags);
    }
    return this.request<Submission>("/submit", {
      method: "POST",
      body: formData,
    });
  }

  async getSubmissions(limit = 20, offset = 0): Promise<SubmissionListResponse> {
    return this.request<SubmissionListResponse>(
      `/submissions?limit=${limit}&offset=${offset}`
    );
  }

  async getSubmission(id: string): Promise<Submission> {
    return this.request<Submission>(`/submissions/${id}`);
  }

  async getHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>("/health");
  }

  // AI Status
  async getAIStatus(): Promise<AIStatus> {
    return this.request<AIStatus>("/ai/status");
  }

  // Chat
  async createConversation(submissionId: string): Promise<Conversation> {
    return this.request<Conversation>(
      `/submissions/${submissionId}/chat/conversations`,
      { method: "POST" }
    );
  }

  async getConversations(
    submissionId: string
  ): Promise<{ items: Conversation[] }> {
    return this.request<{ items: Conversation[] }>(
      `/submissions/${submissionId}/chat/conversations`
    );
  }

  async getMessages(
    submissionId: string,
    conversationId: string
  ): Promise<ChatMessage[]> {
    return this.request<ChatMessage[]>(
      `/submissions/${submissionId}/chat/conversations/${conversationId}/messages`
    );
  }

  async streamMessage(
    submissionId: string,
    conversationId: string,
    content: string,
    onChunk: (delta: string, done: boolean) => void
  ): Promise<void> {
    const res = await fetch(
      `${API_BASE}/submissions/${submissionId}/chat/conversations/${conversationId}/messages`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content }),
      }
    );
    if (!res.ok) {
      const body = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(body.detail || `Request failed: ${res.status}`);
    }
    const reader = res.body?.getReader();
    if (!reader) return;
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";
      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const data = line.slice(6).trim();
          if (data === "[DONE]") {
            onChunk("", true);
            return;
          }
          try {
            const parsed = JSON.parse(data);
            onChunk(parsed.delta || "", parsed.done || false);
          } catch {
            // skip malformed chunks
          }
        }
      }
    }
  }

  // AI Tasks
  async requestSummary(submissionId: string): Promise<AITask> {
    return this.request<AITask>(
      `/submissions/${submissionId}/ai/summarize`,
      { method: "POST" }
    );
  }

  async requestClassify(submissionId: string): Promise<AITask> {
    return this.request<AITask>(
      `/submissions/${submissionId}/ai/classify`,
      { method: "POST" }
    );
  }

  async requestAgentAnalysis(submissionId: string): Promise<AITask> {
    return this.request<AITask>(
      `/submissions/${submissionId}/ai/agent`,
      { method: "POST" }
    );
  }

  async getAITask(submissionId: string, taskId: string): Promise<AITask> {
    return this.request<AITask>(
      `/submissions/${submissionId}/ai/tasks/${taskId}`
    );
  }

  async getSummary(submissionId: string): Promise<AISummary> {
    return this.request<AISummary>(
      `/submissions/${submissionId}/ai/summary`
    );
  }

  // Dynamic Analysis
  async startAnalysis(
    submissionId: string,
    config?: { timeout?: number; network?: boolean }
  ): Promise<AnalysisResult> {
    return this.request<AnalysisResult>(
      `/submissions/${submissionId}/analyze`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config || {}),
      }
    );
  }

  async getAnalyses(submissionId: string): Promise<AnalysisListResponse> {
    return this.request<AnalysisListResponse>(
      `/submissions/${submissionId}/analyses`
    );
  }

  async getAnalysis(
    submissionId: string,
    analysisId: string
  ): Promise<AnalysisResult> {
    return this.request<AnalysisResult>(
      `/submissions/${submissionId}/analyses/${analysisId}`
    );
  }

  getPcapDownloadUrl(submissionId: string, analysisId: string): string {
    return `${API_BASE}/submissions/${submissionId}/analyses/${analysisId}/pcap`;
  }

  // YARA Scanning
  async yaraStaticScan(submissionId: string): Promise<YaraScanResult> {
    return this.request<YaraScanResult>(
      `/submissions/${submissionId}/yara`,
      { method: "POST" }
    );
  }

  // Machine Pool
  async getPoolStatus(): Promise<PoolStatus> {
    return this.request<PoolStatus>("/machines/pool/status");
  }

  async getMachines(): Promise<MachineListResponse> {
    return this.request<MachineListResponse>("/machines");
  }

  async getMachine(id: string): Promise<PoolMachine> {
    return this.request<PoolMachine>(`/machines/${id}`);
  }

  async scalePool(size: number): Promise<PoolStatus> {
    return this.request<PoolStatus>("/machines/pool/scale", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ size }),
    });
  }

  // MITRE ATT&CK Mapping
  async getMitreMapping(
    submissionId: string,
    analysisId: string,
  ): Promise<MITREAnalysisResponse> {
    return this.request<MITREAnalysisResponse>(
      `/submissions/${submissionId}/analyses/${analysisId}/mitre`
    );
  }

  async runMitreMapping(
    submissionId: string,
    analysisId: string,
    useAI = false,
  ): Promise<MITREAnalysisResponse> {
    return this.request<MITREAnalysisResponse>(
      `/submissions/${submissionId}/analyses/${analysisId}/mitre?use_ai=${useAI}`,
      { method: "POST" }
    );
  }

  async getMitreTechniques(
    search = "",
    limit = 50,
    offset = 0,
  ): Promise<MITRETechniqueDetail[]> {
    const params = new URLSearchParams();
    if (search) params.set("search", search);
    params.set("limit", String(limit));
    params.set("offset", String(offset));
    return this.request<MITRETechniqueDetail[]>(
      `/mitre/techniques?${params.toString()}`
    );
  }

  async getMitreTechnique(techniqueId: string): Promise<MITRETechniqueDetail> {
    return this.request<MITRETechniqueDetail>(
      `/mitre/techniques/${techniqueId}`
    );
  }

  // Threat Intelligence
  async getThreatIntel(
    submissionId: string
  ): Promise<ThreatIntelAggregateResponse> {
    return this.request<ThreatIntelAggregateResponse>(
      `/submissions/${submissionId}/threat-intel`
    );
  }

  async getThreatIntelStatus(): Promise<ThreatIntelStatusResponse> {
    return this.request<ThreatIntelStatusResponse>("/threat-intel/status");
  }

  // Auth
  async login(email: string, password: string): Promise<TokenResponse> {
    return this.request<TokenResponse>("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
  }

  async register(
    email: string,
    password: string,
    displayName?: string
  ): Promise<User> {
    return this.request<User>("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, display_name: displayName }),
    });
  }

  async getMe(): Promise<User> {
    return this.request<User>("/auth/me");
  }

  // Screenshots / Video
  async getAnalysisMedia(
    submissionId: string,
    analysisId: string
  ): Promise<AnalysisMedia> {
    return this.request<AnalysisMedia>(
      `/submissions/${submissionId}/analyses/${analysisId}/media`
    );
  }

  getScreenshotUrl(
    submissionId: string,
    analysisId: string,
    index: number
  ): string {
    return `${API_BASE}/submissions/${submissionId}/analyses/${analysisId}/screenshots/${index}`;
  }

  getVideoUrl(submissionId: string, analysisId: string): string {
    return `${API_BASE}/submissions/${submissionId}/analyses/${analysisId}/video`;
  }

  // VNC
  async startVNCSession(
    submissionId: string,
    analysisId: string
  ): Promise<VNCSessionInfo> {
    return this.request<VNCSessionInfo>(
      `/submissions/${submissionId}/analyses/${analysisId}/vnc/start`,
      { method: "POST" }
    );
  }

  async stopVNCSession(
    submissionId: string,
    analysisId: string
  ): Promise<void> {
    await this.request(
      `/submissions/${submissionId}/analyses/${analysisId}/vnc/stop`,
      { method: "POST" }
    );
  }

  // AI Report
  async generateReport(submissionId: string): Promise<ReportResponse> {
    return this.request<ReportResponse>(
      `/submissions/${submissionId}/ai/report`,
      { method: "POST" }
    );
  }

  // Similar Submissions
  async getSimilarSubmissions(
    submissionId: string
  ): Promise<SimilarSubmissionsResponse> {
    return this.request<SimilarSubmissionsResponse>(
      `/submissions/${submissionId}/similar`
    );
  }

  // Static Analysis
  async getStaticAnalysis(submissionId: string) {
    return this.request(`/submissions/${submissionId}/static`);
  }

  // Search
  async search(params: Record<string, string | number | boolean>) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
    }
    return this.request(`/search?${qs.toString()}`);
  }

  async lookupHash(hash: string) {
    return this.request(`/search/hash/${hash}`);
  }

  // Dashboard
  async getDashboardStats() {
    return this.request("/dashboard/stats");
  }

  async getDashboardTimeline(days = 30) {
    return this.request(`/dashboard/timeline?days=${days}`);
  }

  // URL Submission
  async submitUrl(url: string, tags?: string) {
    return this.request("/submit-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, tags: tags || "" }),
    });
  }

  // IOC Export
  async getIOCs(submissionId: string) {
    return this.request(`/submissions/${submissionId}/iocs`);
  }

  getIOCExportUrl(submissionId: string, format: string): string {
    return `${API_BASE}/submissions/${submissionId}/iocs/${format}`;
  }

  // Comments
  async getComments(submissionId: string) {
    return this.request(`/submissions/${submissionId}/comments`);
  }

  async addComment(submissionId: string, content: string) {
    return this.request(`/submissions/${submissionId}/comments`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }),
    });
  }

  async deleteComment(submissionId: string, commentId: string) {
    return this.request(
      `/submissions/${submissionId}/comments/${commentId}`,
      { method: "DELETE" }
    );
  }

  // Webhooks
  async getWebhooks() {
    return this.request("/webhooks");
  }

  async createWebhook(url: string, events: string[], secret?: string) {
    return this.request("/webhooks", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, events, secret }),
    });
  }

  async deleteWebhook(id: string) {
    return this.request(`/webhooks/${id}`, { method: "DELETE" });
  }

  // Network Analysis (enriched)
  async getNetworkAnalysis(
    submissionId: string,
    analysisId: string
  ): Promise<NetworkAnalysisResponse> {
    return this.request<NetworkAnalysisResponse>(
      `/submissions/${submissionId}/analyses/${analysisId}/network`
    );
  }

  async getNetworkIOCs(
    submissionId: string,
    analysisId: string
  ): Promise<NetworkIOCsResponse> {
    return this.request<NetworkIOCsResponse>(
      `/submissions/${submissionId}/analyses/${analysisId}/network/iocs`
    );
  }

  // YARA Rule Management
  async getYaraRules(): Promise<YaraRuleFile[]> {
    return this.request<YaraRuleFile[]>("/yara/rules");
  }

  async getYaraRuleContent(filename: string): Promise<YaraRuleContent> {
    return this.request<YaraRuleContent>(`/yara/rules/${filename}`);
  }

  async uploadYaraRule(
    filename: string,
    content: string
  ): Promise<YaraRuleFile> {
    return this.request<YaraRuleFile>("/yara/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename, content }),
    });
  }

  async updateYaraRule(
    filename: string,
    content: string
  ): Promise<YaraRuleFile> {
    return this.request<YaraRuleFile>(`/yara/rules/${filename}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename, content }),
    });
  }

  async deleteYaraRule(filename: string): Promise<void> {
    await this.request(`/yara/rules/${filename}`, { method: "DELETE" });
  }

  async validateYaraRule(content: string): Promise<YaraValidateResponse> {
    return this.request<YaraValidateResponse>("/yara/rules/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }),
    });
  }

  // HTML Report
  getHtmlReportUrl(submissionId: string): string {
    return `${API_BASE}/submissions/${submissionId}/report/download`;
  }

  // Auto-tag
  async autoTag(submissionId: string) {
    return this.request(`/submissions/${submissionId}/auto-tag`, {
      method: "POST",
    });
  }

  // Settings
  async getFeatureFlags() {
    return this.request("/settings/features");
  }

  // Teams
  async getTeams() {
    return this.request("/teams");
  }

  async createTeam(name: string, description?: string) {
    return this.request("/teams", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, description }),
    });
  }
}

export const api = new ApiClient();
