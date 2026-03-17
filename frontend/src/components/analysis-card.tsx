"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "@/lib/api";
import type { AnalysisResult, IDSAlert, IDSSummary, YaraMatch, YaraResults } from "@/lib/types";
import {
  useAnalysisStream,
  type TelemetryEvent,
} from "@/hooks/use-analysis-stream";
import { MitreAttackCard } from "@/components/mitre-attack-card";
import { ProcessTree } from "@/components/process-tree";
import { ScreenshotGallery } from "@/components/screenshot-gallery";
import { VNCViewer } from "@/components/vnc-viewer";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface ProcessEvent {
  pid: number;
  ppid?: number;
  command: string;
  args?: string[];
}

interface NetworkEvent {
  protocol: string;
  address: string;
  port: number;
}

interface FileEvent {
  path: string;
  size?: number;
}

interface DNSQuery {
  query: string;
  type: string;
  response: string;
}

interface PcapConnection {
  src: string;
  dst: string;
  protocol: string;
  bytes: number;
}

interface PcapData {
  dns_queries: DNSQuery[];
  connections: PcapConnection[];
  http_hosts: string[];
  total_packets: number;
  total_bytes: number;
  pcap_size: number;
}

const POLL_INTERVAL_MS = 3000;

function StatusBadge({ status }: { status: string }) {
  const variant =
    status === "completed"
      ? "outline"
      : status === "failed"
        ? "destructive"
        : "default";
  return <Badge variant={variant}>{status}</Badge>;
}

function Spinner() {
  return (
    <svg
      className="animate-spin h-4 w-4 text-muted-foreground"
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  );
}

function CollapsiblePre({ label, content }: { label: string; content: string }) {
  const [open, setOpen] = useState(false);
  if (!content) return null;
  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="text-sm font-medium text-muted-foreground hover:text-foreground"
      >
        {open ? "- " : "+ "}
        {label}
      </button>
      {open && (
        <pre className="mt-1 text-xs bg-muted rounded p-2 overflow-x-auto max-h-48 overflow-y-auto whitespace-pre-wrap">
          {content}
        </pre>
      )}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const val = bytes / Math.pow(1024, i);
  return `${val.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function isTerminalStatus(status: string): boolean {
  return status === "completed" || status === "failed";
}

function severityColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "bg-red-700 text-white hover:bg-red-800";
    case "high":
      return "bg-red-600 text-white hover:bg-red-700";
    case "medium":
      return "bg-orange-500 text-white hover:bg-orange-600";
    case "low":
      return "bg-yellow-500 text-white hover:bg-yellow-600";
    default:
      return "";
  }
}

function YaraMatchTable({ matches }: { matches: YaraMatch[] }) {
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Rule</TableHead>
          <TableHead>Tags</TableHead>
          <TableHead>Description</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Strings</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {matches.map((m, i) => (
          <TableRow key={i}>
            <TableCell className="font-mono text-xs font-medium">
              {m.rule}
            </TableCell>
            <TableCell>
              <div className="flex flex-wrap gap-1">
                {m.tags.map((tag, j) => (
                  <Badge key={j} variant="secondary" className="text-xs">
                    {tag}
                  </Badge>
                ))}
              </div>
            </TableCell>
            <TableCell className="text-xs max-w-xs truncate" title={m.meta?.description || ""}>
              {m.meta?.description || "-"}
            </TableCell>
            <TableCell>
              {m.meta?.severity ? (
                <Badge className={severityColor(m.meta.severity)}>
                  {m.meta.severity}
                </Badge>
              ) : (
                <span className="text-xs text-muted-foreground">-</span>
              )}
            </TableCell>
            <TableCell>
              {m.strings.length > 0 ? (
                <button
                  onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                  className="text-xs text-blue-600 hover:text-blue-800 underline"
                >
                  {expandedRow === i ? "Hide" : `${m.strings.length} match${m.strings.length !== 1 ? "es" : ""}`}
                </button>
              ) : (
                <span className="text-xs text-muted-foreground">-</span>
              )}
              {expandedRow === i && (
                <pre className="mt-1 text-xs bg-muted rounded p-2 overflow-x-auto max-h-32 overflow-y-auto whitespace-pre-wrap font-mono">
                  {m.strings.join("\n")}
                </pre>
              )}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

const EVENT_COLORS: Record<string, string> = {
  process: "text-blue-600 dark:text-blue-400",
  network: "text-orange-600 dark:text-orange-400",
  file: "text-green-600 dark:text-green-400",
  status: "text-gray-500 dark:text-gray-400",
  complete: "text-gray-400 dark:text-gray-500",
};

const EVENT_LABELS: Record<string, string> = {
  process: "PROC",
  network: "NET",
  file: "FILE",
  status: "STATUS",
  complete: "DONE",
};

function eventSummary(e: TelemetryEvent): string {
  switch (e.type) {
    case "process":
      return `PID ${e.pid} ${e.command ?? ""} ${(e.args ?? []).join(" ")}`.trim();
    case "network":
      return `PID ${e.pid} ${e.protocol ?? "tcp"} -> ${e.address ?? "?"}:${e.port ?? "?"}`;
    case "file":
      return `PID ${e.pid} ${e.operation ?? "access"} ${e.path ?? ""}`;
    case "status":
      return `${e.message ?? "status"} (exit ${e.exit_code ?? "?"})`;
    case "complete":
      return "Analysis complete";
    default:
      return JSON.stringify(e);
  }
}

function LiveEventLog({ events }: { events: TelemetryEvent[] }) {
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events.length]);

  if (events.length === 0) {
    return (
      <div className="text-xs text-muted-foreground italic">
        Waiting for events...
      </div>
    );
  }

  return (
    <div className="rounded border bg-muted/40 p-2 max-h-56 overflow-y-auto font-mono text-xs space-y-0.5">
      {events.map((e, i) => {
        const color = EVENT_COLORS[e.type] ?? "text-gray-500";
        const label = EVENT_LABELS[e.type] ?? e.type.toUpperCase();
        return (
          <div key={i} className="flex gap-2 leading-relaxed">
            <span className="text-muted-foreground w-14 text-right shrink-0">
              {e.timestamp != null ? `${e.timestamp.toFixed(2)}s` : ""}
            </span>
            <span className={`font-semibold w-12 shrink-0 ${color}`}>
              {label}
            </span>
            <span className="truncate">{eventSummary(e)}</span>
          </div>
        );
      })}
      <div ref={endRef} />
    </div>
  );
}

export function AnalysisCard({ submissionId }: { submissionId: string }) {
  const [analyses, setAnalyses] = useState<AnalysisResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollingIdRef = useRef<string | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    pollingIdRef.current = null;
  }, []);

  const fetchAnalyses = useCallback(async () => {
    try {
      const res = await api.getAnalyses(submissionId);
      setAnalyses(res.items);
    } catch {
      // no analyses yet
    }
  }, [submissionId]);

  // Poll a specific analysis until it reaches a terminal status
  const startPolling = useCallback(
    (analysisId: string) => {
      stopPolling();
      pollingIdRef.current = analysisId;

      pollRef.current = setInterval(async () => {
        try {
          const updated = await api.getAnalysis(submissionId, analysisId);

          setAnalyses((prev) =>
            prev.map((a) => (a.id === analysisId ? updated : a))
          );

          if (isTerminalStatus(updated.status)) {
            stopPolling();
            setRunning(false);
          }
        } catch {
          // If the poll fails, keep trying until terminal
        }
      }, POLL_INTERVAL_MS);
    },
    [submissionId, stopPolling]
  );

  useEffect(() => {
    setLoading(true);
    fetchAnalyses().finally(() => setLoading(false));
  }, [fetchAnalyses]);

  // Resume polling if the latest analysis is still in progress on mount
  useEffect(() => {
    if (analyses.length > 0) {
      const latest = analyses[0];
      if (!isTerminalStatus(latest.status) && !pollRef.current) {
        setRunning(true);
        startPolling(latest.id);
      }
    }
  }, [analyses.length > 0 && analyses[0]?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  // Cleanup polling on unmount
  useEffect(() => {
    return () => stopPolling();
  }, [stopPolling]);

  const handleRun = useCallback(async () => {
    setRunning(true);
    setError(null);
    try {
      const analysis = await api.startAnalysis(submissionId);
      setAnalyses((prev) => [analysis, ...prev]);
      // Start polling for the new analysis
      startPolling(analysis.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed");
      setRunning(false);
    }
  }, [submissionId, startPolling]);

  const latest = analyses[0];
  const latestInProgress = latest && !isTerminalStatus(latest.status);

  // Connect to the WebSocket for real-time telemetry when analysis is running
  const { events: liveEvents } = useAnalysisStream(
    submissionId,
    latestInProgress ? latest.id : null,
    !!latestInProgress,
  );

  const result = latest?.result as Record<string, unknown> | undefined;
  const execution = result?.execution as
    | { exit_code?: number; duration_seconds?: number; timed_out?: boolean }
    | undefined;
  const processes = (result?.processes as ProcessEvent[]) || [];
  const network = (result?.network as NetworkEvent[]) || [];
  const filesCreated = (result?.files_created as FileEvent[]) || [];
  const filesModified = (result?.files_modified as FileEvent[]) || [];
  const filesDeleted = (result?.files_deleted as FileEvent[]) || [];
  const allFiles = [
    ...filesCreated.map((f) => ({ ...f, op: "created" })),
    ...filesModified.map((f) => ({ ...f, op: "modified" })),
    ...filesDeleted.map((f) => ({ ...f, op: "deleted" })),
  ];
  const stdout = (result?.stdout as string) || "";
  const stderr = (result?.stderr as string) || "";
  const resultError = result?.error as string | undefined;
  const pcap = result?.pcap as PcapData | undefined;
  const dnsQueries = pcap?.dns_queries || [];
  const pcapConnections = pcap?.connections || [];
  const httpHosts = pcap?.http_hosts || [];
  const idsAlerts = (result?.ids_alerts as IDSAlert[]) || [];
  const idsSummary = result?.ids_summary as IDSSummary | undefined;
  const yaraData = result?.yara as YaraResults | undefined;
  const yaraSampleMatches = yaraData?.sample_matches || [];
  const yaraDroppedMatches = yaraData?.dropped_file_matches || [];
  const yaraTotalMatches = yaraData?.total_matches || 0;
  const yaraRulesLoaded = yaraData?.rules_loaded || 0;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">Dynamic Analysis</CardTitle>
          <Button
            variant="outline"
            size="sm"
            onClick={handleRun}
            disabled={running}
          >
            {running ? "Analyzing..." : latest ? "Re-run" : "Run Analysis"}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && <p className="text-sm text-destructive">{error}</p>}

        {loading && !latest && (
          <p className="text-sm text-muted-foreground">Loading...</p>
        )}

        {!latest && !loading && !running && (
          <p className="text-sm text-muted-foreground">
            Run dynamic analysis to execute this file in an isolated sandbox and
            observe its behavior.
          </p>
        )}

        {latestInProgress && (
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Spinner />
              <span>
                {latest.status === "queued"
                  ? "Queued -- waiting for a worker..."
                  : "Running -- executing in sandbox..."}
              </span>
            </div>
            {latest.status !== "queued" && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-1">
                  Live Telemetry
                </p>
                <LiveEventLog events={liveEvents} />
              </div>
            )}
          </div>
        )}

        {latest && (
          <>
            <div className="flex items-center gap-3 text-sm">
              <StatusBadge status={latest.status} />
              {latest.duration_seconds != null && (
                <span className="text-muted-foreground">
                  {latest.duration_seconds}s
                </span>
              )}
              {execution?.timed_out && (
                <Badge variant="secondary">timed out</Badge>
              )}
              {execution?.exit_code != null && (
                <span className="text-muted-foreground">
                  exit code: {execution.exit_code}
                </span>
              )}
            </div>

            {resultError && (
              <p className="text-sm text-destructive">{resultError}</p>
            )}

            {processes.length > 0 && (
              <ProcessTree processes={processes} />
            )}

            {latestInProgress && (
              <VNCViewer
                submissionId={submissionId}
                analysisId={latest?.id ?? null}
                isRunning={!!latestInProgress}
              />
            )}

            {network.length > 0 && (
              <div>
                <p className="text-sm font-medium mb-1">Network Connections</p>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Protocol</TableHead>
                      <TableHead>Address</TableHead>
                      <TableHead>Port</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {network.map((n, i) => (
                      <TableRow key={i}>
                        <TableCell>{n.protocol}</TableCell>
                        <TableCell className="font-mono">{n.address}</TableCell>
                        <TableCell>{n.port}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}

            {allFiles.length > 0 && (
              <div>
                <p className="text-sm font-medium mb-1">File Activity</p>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Operation</TableHead>
                      <TableHead>Path</TableHead>
                      <TableHead>Size</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {allFiles.map((f, i) => (
                      <TableRow key={i}>
                        <TableCell>
                          <Badge
                            variant={
                              f.op === "deleted" ? "destructive" : "outline"
                            }
                          >
                            {f.op}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {f.path}
                        </TableCell>
                        <TableCell>
                          {f.size != null ? `${f.size} B` : "-"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}

            {pcap && (
              <div>
                <div className="flex items-center justify-between mb-1">
                  <p className="text-sm font-medium">PCAP Summary</p>
                  {latest && (
                    <a
                      href={api.getPcapDownloadUrl(submissionId, latest.id)}
                      download
                      className="text-xs text-blue-600 hover:text-blue-800 underline"
                    >
                      Download PCAP
                    </a>
                  )}
                </div>
                <div className="grid grid-cols-3 gap-4 text-sm mb-3">
                  <div>
                    <span className="text-muted-foreground">Packets: </span>
                    <span className="font-mono">{pcap.total_packets}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Traffic: </span>
                    <span className="font-mono">{formatBytes(pcap.total_bytes)}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">PCAP Size: </span>
                    <span className="font-mono">{formatBytes(pcap.pcap_size)}</span>
                  </div>
                </div>

                {httpHosts.length > 0 && (
                  <div className="mb-3">
                    <p className="text-xs font-medium text-muted-foreground mb-1">HTTP Hosts</p>
                    <div className="flex flex-wrap gap-1">
                      {httpHosts.map((host, i) => (
                        <Badge key={i} variant="secondary" className="font-mono text-xs">
                          {host}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {dnsQueries.length > 0 && (
                  <div className="mb-3">
                    <p className="text-xs font-medium text-muted-foreground mb-1">DNS Queries</p>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Domain</TableHead>
                          <TableHead>Type</TableHead>
                          <TableHead>Response</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {dnsQueries.map((dns, i) => (
                          <TableRow key={i}>
                            <TableCell className="font-mono text-xs">{dns.query}</TableCell>
                            <TableCell className="text-xs">{dns.type}</TableCell>
                            <TableCell className="font-mono text-xs">
                              {dns.response || "-"}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}

                {pcapConnections.length > 0 && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1">
                      Captured Connections
                    </p>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Source</TableHead>
                          <TableHead>Destination</TableHead>
                          <TableHead>Protocol</TableHead>
                          <TableHead>Bytes</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {pcapConnections.map((conn, i) => (
                          <TableRow key={i}>
                            <TableCell className="font-mono text-xs">{conn.src}</TableCell>
                            <TableCell className="font-mono text-xs">{conn.dst}</TableCell>
                            <TableCell className="text-xs uppercase">{conn.protocol}</TableCell>
                            <TableCell className="font-mono text-xs">
                              {formatBytes(conn.bytes)}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </div>
            )}

            {idsAlerts.length > 0 && (
              <div>
                <div className="flex items-center justify-between mb-1">
                  <p className="text-sm font-medium">IDS Alerts</p>
                  {idsSummary && (
                    <div className="flex items-center gap-2">
                      {idsSummary.high_severity > 0 && (
                        <Badge className="bg-red-600 text-white hover:bg-red-700">
                          {idsSummary.high_severity} High
                        </Badge>
                      )}
                      {idsSummary.medium_severity > 0 && (
                        <Badge className="bg-orange-500 text-white hover:bg-orange-600">
                          {idsSummary.medium_severity} Medium
                        </Badge>
                      )}
                      {idsSummary.low_severity > 0 && (
                        <Badge className="bg-yellow-500 text-white hover:bg-yellow-600">
                          {idsSummary.low_severity} Low
                        </Badge>
                      )}
                    </div>
                  )}
                </div>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Severity</TableHead>
                      <TableHead>Signature</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Destination</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {idsAlerts.map((alert, i) => (
                      <TableRow key={i}>
                        <TableCell>
                          <Badge
                            className={
                              alert.severity === 1
                                ? "bg-red-600 text-white hover:bg-red-700"
                                : alert.severity === 2
                                  ? "bg-orange-500 text-white hover:bg-orange-600"
                                  : "bg-yellow-500 text-white hover:bg-yellow-600"
                            }
                          >
                            {alert.severity === 1
                              ? "High"
                              : alert.severity === 2
                                ? "Medium"
                                : "Low"}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs max-w-xs truncate" title={alert.signature}>
                          {alert.signature}
                        </TableCell>
                        <TableCell className="text-xs">
                          {alert.category}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {alert.src_ip}:{alert.src_port}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {alert.dst_ip}:{alert.dst_port}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {idsSummary && idsSummary.categories.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {idsSummary.categories.map((cat, i) => (
                      <Badge key={i} variant="secondary" className="text-xs">
                        {cat}
                      </Badge>
                    ))}
                  </div>
                )}
              </div>
            )}

            {yaraData && (
              <div>
                <div className="flex items-center justify-between mb-1">
                  <p className="text-sm font-medium">YARA Matches</p>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <span>{yaraRulesLoaded} rules loaded</span>
                    {yaraTotalMatches > 0 ? (
                      <Badge className="bg-red-600 text-white hover:bg-red-700">
                        {yaraTotalMatches} match{yaraTotalMatches !== 1 ? "es" : ""}
                      </Badge>
                    ) : (
                      <Badge variant="outline">No matches</Badge>
                    )}
                  </div>
                </div>

                {yaraTotalMatches === 0 && (
                  <p className="text-sm text-muted-foreground">
                    No YARA rules matched -- no known malware signatures detected.
                  </p>
                )}

                {yaraSampleMatches.length > 0 && (
                  <div className="mb-3">
                    <p className="text-xs font-medium text-muted-foreground mb-1">
                      Sample Matches
                    </p>
                    <YaraMatchTable matches={yaraSampleMatches} />
                  </div>
                )}

                {yaraDroppedMatches.length > 0 && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1">
                      Dropped File Matches
                    </p>
                    {yaraDroppedMatches.map((df, i) => (
                      <div key={i} className="mb-2">
                        <p className="text-xs font-mono text-muted-foreground mb-1">
                          {df.file}
                        </p>
                        <YaraMatchTable matches={df.matches} />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {latest && isTerminalStatus(latest.status) && (
              <MitreAttackCard
                submissionId={submissionId}
                analysisId={latest.id}
              />
            )}

            {latest && isTerminalStatus(latest.status) && (
              <ScreenshotGallery
                submissionId={submissionId}
                analysisId={latest.id}
              />
            )}

            <CollapsiblePre label="stdout" content={stdout} />
            <CollapsiblePre label="stderr" content={stderr} />
          </>
        )}
      </CardContent>
    </Card>
  );
}
