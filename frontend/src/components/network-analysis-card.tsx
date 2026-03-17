"use client";

import { useState } from "react";

import { useNetworkAnalysis } from "@/hooks/use-network-analysis";
import type { NetworkAnalysisResponse, NetworkIOCsResponse } from "@/lib/types";
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

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

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

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1
  );
  const val = bytes / Math.pow(1024, i);
  return `${val.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/* -------------------------------------------------------------------------- */
/*  Connection summary cards                                                   */
/* -------------------------------------------------------------------------- */

function SummaryStats({
  summary,
}: {
  summary: NetworkAnalysisResponse["connection_summary"];
}) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      <div className="rounded border p-3 text-center">
        <p className="text-2xl font-bold">{summary.total}</p>
        <p className="text-xs text-muted-foreground">Total Connections</p>
      </div>
      <div className="rounded border p-3 text-center">
        <p className="text-2xl font-bold text-red-600">{summary.external}</p>
        <p className="text-xs text-muted-foreground">External</p>
      </div>
      <div className="rounded border p-3 text-center">
        <p className="text-2xl font-bold text-blue-600">{summary.internal}</p>
        <p className="text-xs text-muted-foreground">Internal</p>
      </div>
      <div className="rounded border p-3 text-center">
        <p className="text-2xl font-bold">{summary.unique_ips.length}</p>
        <p className="text-xs text-muted-foreground">Unique IPs</p>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Connections table                                                          */
/* -------------------------------------------------------------------------- */

function ConnectionsTable({
  connections,
}: {
  connections: NetworkAnalysisResponse["connections"];
}) {
  if (connections.length === 0) return null;

  return (
    <div>
      <p className="text-sm font-medium mb-2">Connections</p>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Protocol</TableHead>
            <TableHead>Address</TableHead>
            <TableHead>Port</TableHead>
            <TableHead>Service</TableHead>
            <TableHead>Type</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {connections.map((conn, i) => (
            <TableRow key={i}>
              <TableCell className="text-xs uppercase">
                {conn.protocol}
              </TableCell>
              <TableCell className="font-mono text-xs">
                {conn.address}
              </TableCell>
              <TableCell className="font-mono text-xs">{conn.port}</TableCell>
              <TableCell>
                <Badge variant="secondary" className="text-xs">
                  {conn.service}
                </Badge>
              </TableCell>
              <TableCell>
                {conn.is_private ? (
                  <Badge variant="outline" className="text-xs">
                    Internal
                  </Badge>
                ) : (
                  <Badge
                    className="text-xs bg-red-600 text-white hover:bg-red-700"
                  >
                    External
                  </Badge>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  DNS analysis section                                                       */
/* -------------------------------------------------------------------------- */

function DNSSection({
  dns,
}: {
  dns: NetworkAnalysisResponse["dns_analysis"];
}) {
  if (dns.total_queries === 0) return null;

  const queryTypes = Object.entries(dns.query_types);

  return (
    <div>
      <p className="text-sm font-medium mb-2">DNS Analysis</p>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-3">
        <div className="rounded border p-2 text-center">
          <p className="text-lg font-bold">{dns.total_queries}</p>
          <p className="text-xs text-muted-foreground">Total Queries</p>
        </div>
        <div className="rounded border p-2 text-center">
          <p className="text-lg font-bold">{dns.unique_domains.length}</p>
          <p className="text-xs text-muted-foreground">Unique Domains</p>
        </div>
        {queryTypes.length > 0 && (
          <div className="rounded border p-2 text-center">
            <p className="text-lg font-bold">{queryTypes.length}</p>
            <p className="text-xs text-muted-foreground">Query Types</p>
          </div>
        )}
      </div>

      {queryTypes.length > 0 && (
        <div className="mb-3">
          <p className="text-xs font-medium text-muted-foreground mb-1">
            Query Type Breakdown
          </p>
          <div className="flex flex-wrap gap-1">
            {queryTypes.map(([qtype, count]) => (
              <Badge key={qtype} variant="secondary" className="text-xs">
                {qtype}: {count}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {dns.unique_domains.length > 0 && (
        <div>
          <p className="text-xs font-medium text-muted-foreground mb-1">
            Resolved Domains
          </p>
          <div className="flex flex-wrap gap-1">
            {dns.unique_domains.map((domain) => (
              <Badge
                key={domain}
                variant="outline"
                className="font-mono text-xs"
              >
                {domain}
              </Badge>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Suspicious indicators                                                      */
/* -------------------------------------------------------------------------- */

function SuspiciousIndicators({ indicators }: { indicators: string[] }) {
  if (indicators.length === 0) return null;

  return (
    <div>
      <p className="text-sm font-medium mb-2">Suspicious Indicators</p>
      <div className="space-y-1">
        {indicators.map((indicator, i) => (
          <div
            key={i}
            className="flex items-start gap-2 rounded border border-yellow-300 dark:border-yellow-700 bg-yellow-50 dark:bg-yellow-950 p-2"
          >
            <span className="text-yellow-600 dark:text-yellow-400 text-sm shrink-0">
              !
            </span>
            <p className="text-xs font-mono break-all">{indicator}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  IOC summary                                                               */
/* -------------------------------------------------------------------------- */

function IOCSummary({ iocs }: { iocs: NetworkIOCsResponse }) {
  const [expanded, setExpanded] = useState(false);

  if (iocs.total === 0 && iocs.private_ips.length === 0) return null;

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <p className="text-sm font-medium">
          Network IOCs
          <Badge variant="secondary" className="ml-2 text-xs">
            {iocs.total} indicator{iocs.total !== 1 ? "s" : ""}
          </Badge>
        </p>
        {(iocs.ips.length > 5 ||
          iocs.domains.length > 5 ||
          iocs.urls.length > 3) && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? "Collapse" : "Expand"}
          </Button>
        )}
      </div>

      <div className="space-y-2">
        {iocs.ips.length > 0 && (
          <div>
            <p className="text-xs font-medium text-muted-foreground mb-1">
              External IPs ({iocs.ips.length})
            </p>
            <div className="flex flex-wrap gap-1">
              {(expanded ? iocs.ips : iocs.ips.slice(0, 10)).map((ip) => (
                <Badge key={ip} variant="outline" className="font-mono text-xs">
                  {ip}
                </Badge>
              ))}
              {!expanded && iocs.ips.length > 10 && (
                <Badge variant="secondary" className="text-xs">
                  +{iocs.ips.length - 10} more
                </Badge>
              )}
            </div>
          </div>
        )}

        {iocs.domains.length > 0 && (
          <div>
            <p className="text-xs font-medium text-muted-foreground mb-1">
              Domains ({iocs.domains.length})
            </p>
            <div className="flex flex-wrap gap-1">
              {(expanded ? iocs.domains : iocs.domains.slice(0, 10)).map(
                (domain) => (
                  <Badge
                    key={domain}
                    variant="outline"
                    className="font-mono text-xs"
                  >
                    {domain}
                  </Badge>
                )
              )}
              {!expanded && iocs.domains.length > 10 && (
                <Badge variant="secondary" className="text-xs">
                  +{iocs.domains.length - 10} more
                </Badge>
              )}
            </div>
          </div>
        )}

        {iocs.urls.length > 0 && (
          <div>
            <p className="text-xs font-medium text-muted-foreground mb-1">
              URLs ({iocs.urls.length})
            </p>
            <div className="space-y-1">
              {(expanded ? iocs.urls : iocs.urls.slice(0, 5)).map((url) => (
                <p key={url} className="text-xs font-mono break-all text-muted-foreground">
                  {url}
                </p>
              ))}
              {!expanded && iocs.urls.length > 5 && (
                <p className="text-xs text-muted-foreground">
                  +{iocs.urls.length - 5} more
                </p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Main card                                                                  */
/* -------------------------------------------------------------------------- */

export function NetworkAnalysisCard({
  submissionId,
  analysisId,
}: {
  submissionId: string;
  analysisId: string;
}) {
  const { data, iocs, loading, error, refresh } = useNetworkAnalysis(
    submissionId,
    analysisId
  );

  const hasData =
    data &&
    (data.connections.length > 0 ||
      data.dns_analysis.total_queries > 0 ||
      data.suspicious_indicators.length > 0);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">Network Analysis</CardTitle>
          <div className="flex items-center gap-2">
            {data && data.pcap_stats.total_packets > 0 && (
              <span className="text-xs text-muted-foreground">
                {data.pcap_stats.total_packets} packets / {formatBytes(data.pcap_stats.total_bytes)}
              </span>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={refresh}
              disabled={loading}
            >
              {loading ? "Loading..." : "Refresh"}
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-5">
        {/* Loading */}
        {loading && !data && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Spinner />
            <span>Analyzing network data...</span>
          </div>
        )}

        {/* Error */}
        {error && !loading && (
          <p className="text-sm text-destructive">{error}</p>
        )}

        {/* Empty state */}
        {!loading && !error && !hasData && (
          <p className="text-sm text-muted-foreground">
            No network activity was captured during analysis.
          </p>
        )}

        {/* Content */}
        {data && hasData && (
          <>
            <SummaryStats summary={data.connection_summary} />

            {data.http_hosts.length > 0 && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-1">
                  HTTP Hosts
                </p>
                <div className="flex flex-wrap gap-1">
                  {data.http_hosts.map((host) => (
                    <Badge
                      key={host}
                      variant="secondary"
                      className="font-mono text-xs"
                    >
                      {host}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {data.connection_summary.services.length > 0 && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-1">
                  Observed Services
                </p>
                <div className="flex flex-wrap gap-1">
                  {data.connection_summary.services.map((svc) => (
                    <Badge key={svc} variant="secondary" className="text-xs">
                      {svc}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            <ConnectionsTable connections={data.connections} />
            <DNSSection dns={data.dns_analysis} />
            <SuspiciousIndicators indicators={data.suspicious_indicators} />
            {iocs && <IOCSummary iocs={iocs} />}
          </>
        )}
      </CardContent>
    </Card>
  );
}
