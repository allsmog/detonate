"use client";

import { useCallback, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

/* -------------------------------------------------------------------------- */
/*  Constants                                                                  */
/* -------------------------------------------------------------------------- */

const API_BASE = "/api/v1";

type ReportStatus = "idle" | "generating" | "done" | "error";

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                     */
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

function statusBadge(status: ReportStatus) {
  switch (status) {
    case "generating":
      return (
        <Badge variant="secondary">
          <Spinner />
          <span className="ml-1">Generating</span>
        </Badge>
      );
    case "done":
      return <Badge variant="outline">Ready</Badge>;
    case "error":
      return <Badge variant="destructive">Error</Badge>;
    default:
      return null;
  }
}

/* -------------------------------------------------------------------------- */
/*  Component                                                                  */
/* -------------------------------------------------------------------------- */

export function ReportDownloadCard({
  submissionId,
}: {
  submissionId: string;
}) {
  const [htmlStatus, setHtmlStatus] = useState<ReportStatus>("idle");
  const [csvStatus, setCsvStatus] = useState<ReportStatus>("idle");
  const [autoTagStatus, setAutoTagStatus] = useState<ReportStatus>("idle");
  const [autoTagResult, setAutoTagResult] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  /* ---- HTML report download ---- */
  const handleDownloadHtml = useCallback(async () => {
    setHtmlStatus("generating");
    setError(null);
    try {
      const res = await fetch(
        `${API_BASE}/submissions/${submissionId}/report/download`
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(body.detail || `Request failed: ${res.status}`);
      }

      // Trigger browser download from response blob
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;

      // Extract filename from Content-Disposition header if available
      const disposition = res.headers.get("Content-Disposition");
      let filename = `detonate-report-${submissionId}.html`;
      if (disposition) {
        const match = disposition.match(/filename="?([^"]+)"?/);
        if (match) filename = match[1];
      }
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);

      setHtmlStatus("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate report");
      setHtmlStatus("error");
    }
  }, [submissionId]);

  /* ---- View HTML report in new tab ---- */
  const handleViewHtml = useCallback(() => {
    window.open(
      `${API_BASE}/submissions/${submissionId}/report/html`,
      "_blank"
    );
  }, [submissionId]);

  /* ---- CSV IOC download ---- */
  const handleDownloadCsv = useCallback(async () => {
    setCsvStatus("generating");
    setError(null);
    try {
      const res = await fetch(
        `${API_BASE}/submissions/${submissionId}/report/iocs`
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(body.detail || `Request failed: ${res.status}`);
      }

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;

      const disposition = res.headers.get("Content-Disposition");
      let filename = `detonate-iocs-${submissionId}.csv`;
      if (disposition) {
        const match = disposition.match(/filename="?([^"]+)"?/);
        if (match) filename = match[1];
      }
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);

      setCsvStatus("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to export IOCs");
      setCsvStatus("error");
    }
  }, [submissionId]);

  /* ---- Auto-tag ---- */
  const handleAutoTag = useCallback(async () => {
    setAutoTagStatus("generating");
    setError(null);
    try {
      const res = await fetch(
        `${API_BASE}/submissions/${submissionId}/auto-tag`,
        { method: "POST" }
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(body.detail || `Request failed: ${res.status}`);
      }
      const data = await res.json();
      setAutoTagResult(data.tags ?? []);
      setAutoTagStatus("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Auto-tagging failed");
      setAutoTagStatus("error");
    }
  }, [submissionId]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Reports &amp; Export</CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* HTML report actions */}
        <div>
          <p className="text-sm text-muted-foreground mb-2">
            Generate a comprehensive HTML threat report with file metadata,
            analysis results, IDS alerts, YARA matches, and IOCs.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleDownloadHtml}
              disabled={htmlStatus === "generating"}
            >
              {htmlStatus === "generating" ? "Generating..." : "Download HTML Report"}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleViewHtml}
            >
              View in Browser
            </Button>
            {statusBadge(htmlStatus)}
          </div>
        </div>

        {/* CSV IOC export */}
        <div>
          <p className="text-sm text-muted-foreground mb-2">
            Export indicators of compromise (hashes, IPs, domains, dropped
            files) as a CSV file for integration with other tools.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleDownloadCsv}
              disabled={csvStatus === "generating"}
            >
              {csvStatus === "generating" ? "Exporting..." : "Download CSV IOCs"}
            </Button>
            {statusBadge(csvStatus)}
          </div>
        </div>

        {/* Auto-tag */}
        <div>
          <p className="text-sm text-muted-foreground mb-2">
            Automatically analyze file type and dynamic analysis results to
            apply descriptive tags to this submission.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleAutoTag}
              disabled={autoTagStatus === "generating"}
            >
              {autoTagStatus === "generating" ? "Tagging..." : "Auto-Tag"}
            </Button>
            {statusBadge(autoTagStatus)}
          </div>
          {autoTagResult && autoTagResult.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {autoTagResult.map((tag) => (
                <Badge key={tag} variant="secondary" className="text-xs">
                  {tag}
                </Badge>
              ))}
            </div>
          )}
          {autoTagResult && autoTagResult.length === 0 && (
            <p className="mt-2 text-xs text-muted-foreground">
              No tags could be inferred. Run dynamic analysis first.
            </p>
          )}
        </div>

        {/* Error display */}
        {error && (
          <p className="text-sm text-destructive">{error}</p>
        )}
      </CardContent>
    </Card>
  );
}
