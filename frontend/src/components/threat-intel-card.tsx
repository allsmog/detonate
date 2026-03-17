"use client";

import { useCallback, useEffect, useState } from "react";

import { api } from "@/lib/api";
import { useThreatIntel } from "@/hooks/use-threat-intel";
import type {
  ThreatIntelProviderResult,
  ThreatIntelProviderStatus,
} from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function detectionColor(malicious: number, total: number): string {
  if (total === 0) return "bg-gray-200 dark:bg-gray-700";
  const ratio = malicious / total;
  if (ratio >= 0.5) return "bg-red-600";
  if (ratio >= 0.2) return "bg-orange-500";
  if (ratio > 0) return "bg-yellow-500";
  return "bg-green-600";
}

function abuseScoreColor(score: number): string {
  if (score >= 75) return "bg-red-600";
  if (score >= 50) return "bg-orange-500";
  if (score >= 25) return "bg-yellow-500";
  return "bg-green-600";
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

/* -------------------------------------------------------------------------- */
/*  VirusTotal result section                                                  */
/* -------------------------------------------------------------------------- */

function VirusTotalSection({ result }: { result: ThreatIntelProviderResult }) {
  if (result.error) {
    return (
      <p className="text-xs text-muted-foreground italic">
        Error: {result.error}
      </p>
    );
  }
  if (!result.data) {
    return (
      <p className="text-xs text-muted-foreground">No data available</p>
    );
  }

  const d = result.data;
  const malicious = (d.malicious ?? 0) as number;
  const total = (d.total ?? 0) as number;
  const pct = total > 0 ? Math.round((malicious / total) * 100) : 0;
  const engines = (d.detected_engines ?? []) as string[];
  const threatLabel = d.threat_classification as string | null;

  return (
    <div className="space-y-2">
      {/* Detection ratio bar */}
      <div>
        <div className="flex items-center justify-between text-xs mb-1">
          <span className="font-medium">
            {malicious} / {total} engines detected
          </span>
          {result.cached && (
            <Badge variant="outline" className="text-[10px] px-1 py-0">
              cached
            </Badge>
          )}
        </div>
        <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${detectionColor(malicious, total)}`}
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      {threatLabel && (
        <p className="text-xs">
          <span className="text-muted-foreground">Classification: </span>
          <span className="font-medium">{threatLabel}</span>
        </p>
      )}

      {engines.length > 0 && (
        <div>
          <p className="text-xs text-muted-foreground mb-1">
            Detected by:
          </p>
          <div className="flex flex-wrap gap-1">
            {engines.slice(0, 12).map((e) => (
              <Badge
                key={e}
                variant="secondary"
                className="text-[10px] px-1.5 py-0"
              >
                {e}
              </Badge>
            ))}
            {engines.length > 12 && (
              <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                +{engines.length - 12} more
              </Badge>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  AbuseIPDB result section                                                   */
/* -------------------------------------------------------------------------- */

function AbuseIPDBSection({
  ip,
  result,
}: {
  ip: string;
  result: ThreatIntelProviderResult;
}) {
  if (result.error) {
    return (
      <p className="text-xs text-muted-foreground italic">
        Error: {result.error}
      </p>
    );
  }
  if (!result.data) return null;

  const d = result.data;
  const score = (d.abuse_confidence_score ?? 0) as number;

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs mb-1">
        <span className="font-mono">{ip}</span>
        {result.cached && (
          <Badge variant="outline" className="text-[10px] px-1 py-0">
            cached
          </Badge>
        )}
      </div>
      {/* Abuse score bar */}
      <div>
        <div className="flex items-center justify-between text-xs mb-0.5">
          <span className="text-muted-foreground">Abuse Confidence</span>
          <span className="font-medium">{score}%</span>
        </div>
        <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${abuseScoreColor(score)}`}
            style={{ width: `${score}%` }}
          />
        </div>
      </div>
      <div className="grid grid-cols-2 gap-x-4 text-xs">
        {!!d.country_code && (
          <div>
            <span className="text-muted-foreground">Country: </span>
            {String(d.country_code)}
          </div>
        )}
        {!!d.isp && (
          <div>
            <span className="text-muted-foreground">ISP: </span>
            {String(d.isp)}
          </div>
        )}
        {d.total_reports != null && (
          <div>
            <span className="text-muted-foreground">Reports: </span>
            {String(d.total_reports)}
          </div>
        )}
        {!!d.usage_type && (
          <div>
            <span className="text-muted-foreground">Usage: </span>
            {String(d.usage_type)}
          </div>
        )}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  OTX result section                                                         */
/* -------------------------------------------------------------------------- */

function OTXSection({ result }: { result: ThreatIntelProviderResult }) {
  if (result.error) {
    return (
      <p className="text-xs text-muted-foreground italic">
        Error: {result.error}
      </p>
    );
  }
  if (!result.data) {
    return (
      <p className="text-xs text-muted-foreground">No data available</p>
    );
  }

  const d = result.data;
  const pulseCount = (d.pulse_count ?? 0) as number;
  const tags = (d.tags ?? []) as string[];

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <p className="text-xs">
          <span className="text-muted-foreground">Pulses: </span>
          <span className="font-medium">{pulseCount}</span>
        </p>
        {result.cached && (
          <Badge variant="outline" className="text-[10px] px-1 py-0">
            cached
          </Badge>
        )}
      </div>
      {tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {tags.slice(0, 15).map((tag) => (
            <Badge
              key={tag}
              variant="secondary"
              className="text-[10px] px-1.5 py-0"
            >
              {tag}
            </Badge>
          ))}
          {tags.length > 15 && (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0">
              +{tags.length - 15} more
            </Badge>
          )}
        </div>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Provider status indicator                                                  */
/* -------------------------------------------------------------------------- */

function ProviderStatusDot({ configured }: { configured: boolean }) {
  return (
    <span
      className={`inline-block h-2 w-2 rounded-full ${
        configured
          ? "bg-green-500"
          : "bg-gray-300 dark:bg-gray-600"
      }`}
      title={configured ? "Configured" : "Not configured"}
    />
  );
}

/* -------------------------------------------------------------------------- */
/*  Main card                                                                  */
/* -------------------------------------------------------------------------- */

export function ThreatIntelCard({
  submissionId,
}: {
  submissionId: string;
}) {
  const { data, loading, error, refresh } = useThreatIntel(submissionId);
  const [statuses, setStatuses] = useState<ThreatIntelProviderStatus[]>([]);

  useEffect(() => {
    api.getThreatIntelStatus().then((res) => setStatuses(res.providers)).catch(() => {});
  }, []);

  const statusMap = Object.fromEntries(
    statuses.map((s) => [s.name, s.configured])
  );

  // Helpers to pick a provider result from a list
  const pick = useCallback(
    (results: ThreatIntelProviderResult[], name: string) =>
      results.find((r) => r.provider === name),
    []
  );

  const hashResults = data?.hash_results ?? [];
  const ipResults = data?.ip_results ?? {};
  const domainResults = data?.domain_results ?? {};

  const vtHash = pick(hashResults, "virustotal");
  const otxHash = pick(hashResults, "otx");

  const hasAnyData =
    hashResults.length > 0 ||
    Object.keys(ipResults).length > 0 ||
    Object.keys(domainResults).length > 0;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <CardTitle className="text-base">Threat Intelligence</CardTitle>
            <div className="flex items-center gap-2">
              {statuses.map((s) => (
                <div key={s.name} className="flex items-center gap-1 text-xs text-muted-foreground">
                  <ProviderStatusDot configured={s.configured} />
                  <span>{s.name}</span>
                </div>
              ))}
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={refresh}
            disabled={loading}
          >
            {loading ? "Loading..." : "Refresh"}
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-5">
        {/* Loading */}
        {loading && !data && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Spinner />
            <span>Querying threat intelligence providers...</span>
          </div>
        )}

        {/* Error */}
        {error && !loading && (
          <p className="text-sm text-destructive">{error}</p>
        )}

        {/* Empty */}
        {!loading && !error && !hasAnyData && (
          <p className="text-sm text-muted-foreground">
            No threat intelligence providers are configured. Add API keys for
            VirusTotal, AbuseIPDB, or OTX to enable enrichment.
          </p>
        )}

        {/* VirusTotal hash results */}
        {vtHash && vtHash.data && (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <ProviderStatusDot configured={statusMap["virustotal"] ?? false} />
              <p className="text-sm font-medium">VirusTotal</p>
            </div>
            <VirusTotalSection result={vtHash} />
          </div>
        )}

        {/* OTX hash results */}
        {otxHash && otxHash.data && (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <ProviderStatusDot configured={statusMap["otx"] ?? false} />
              <p className="text-sm font-medium">AlienVault OTX</p>
            </div>
            <OTXSection result={otxHash} />
          </div>
        )}

        {/* IP results */}
        {Object.keys(ipResults).length > 0 && (
          <div>
            <p className="text-sm font-medium mb-2">IP Address Lookups</p>
            <div className="space-y-3">
              {Object.entries(ipResults).map(([ip, results]) => {
                const abuseResult = pick(results, "abuseipdb");
                const vtIp = pick(results, "virustotal");
                const otxIp = pick(results, "otx");
                return (
                  <div
                    key={ip}
                    className="rounded border p-3 space-y-2"
                  >
                    {/* AbuseIPDB */}
                    {abuseResult && abuseResult.data && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">
                          AbuseIPDB
                        </p>
                        <AbuseIPDBSection ip={ip} result={abuseResult} />
                      </div>
                    )}
                    {/* VT IP */}
                    {vtIp && vtIp.data && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">
                          VirusTotal
                        </p>
                        <div className="text-xs">
                          <span className="text-muted-foreground">
                            Malicious:{" "}
                          </span>
                          <span className="font-medium">
                            {String(vtIp.data.malicious ?? 0)} /{" "}
                            {String(vtIp.data.total ?? 0)}
                          </span>
                          {!!vtIp.data.country && (
                            <>
                              <span className="text-muted-foreground ml-3">
                                Country:{" "}
                              </span>
                              {String(vtIp.data.country)}
                            </>
                          )}
                          {!!vtIp.data.as_owner && (
                            <>
                              <span className="text-muted-foreground ml-3">
                                AS:{" "}
                              </span>
                              {String(vtIp.data.as_owner)}
                            </>
                          )}
                        </div>
                      </div>
                    )}
                    {/* OTX IP */}
                    {otxIp && otxIp.data && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">
                          OTX
                        </p>
                        <div className="text-xs">
                          <span className="text-muted-foreground">
                            Pulses:{" "}
                          </span>
                          <span className="font-medium">
                            {String(otxIp.data.pulse_count ?? 0)}
                          </span>
                          {!!otxIp.data.country_name && (
                            <>
                              <span className="text-muted-foreground ml-3">
                                Country:{" "}
                              </span>
                              {String(otxIp.data.country_name)}
                            </>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Domain results */}
        {Object.keys(domainResults).length > 0 && (
          <div>
            <p className="text-sm font-medium mb-2">Domain Lookups</p>
            <div className="space-y-2">
              {Object.entries(domainResults).map(([domain, results]) => {
                const vtDomain = pick(results, "virustotal");
                const otxDomain = pick(results, "otx");
                return (
                  <div
                    key={domain}
                    className="rounded border p-3 space-y-1"
                  >
                    <p className="text-xs font-mono font-medium">{domain}</p>
                    {vtDomain && vtDomain.data && (
                      <div className="text-xs">
                        <span className="text-muted-foreground">VT: </span>
                        <span className="font-medium">
                          {String(vtDomain.data.malicious ?? 0)} /{" "}
                          {String(vtDomain.data.total ?? 0)} malicious
                        </span>
                        {!!vtDomain.data.registrar && (
                          <>
                            <span className="text-muted-foreground ml-3">
                              Registrar:{" "}
                            </span>
                            {String(vtDomain.data.registrar)}
                          </>
                        )}
                      </div>
                    )}
                    {otxDomain && otxDomain.data && (
                      <div className="text-xs">
                        <span className="text-muted-foreground">OTX: </span>
                        <span className="font-medium">
                          {String(otxDomain.data.pulse_count ?? 0)} pulses
                        </span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
