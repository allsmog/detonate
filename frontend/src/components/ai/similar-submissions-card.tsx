"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

const API_BASE = "/api/v1";

interface SimilarSubmission {
  id: string;
  filename: string | null;
  similarity_score: number;
  shared_iocs: string[];
  verdict: string | null;
  submitted_at: string | null;
}

function scoreBadgeVariant(
  score: number
): "default" | "secondary" | "destructive" {
  if (score > 0.8) return "default";
  if (score > 0.5) return "secondary";
  return "destructive";
}

function verdictBadgeVariant(
  verdict: string | null
): "default" | "secondary" | "destructive" | "outline" {
  switch (verdict) {
    case "malicious":
      return "destructive";
    case "suspicious":
      return "secondary";
    case "clean":
      return "outline";
    default:
      return "default";
  }
}

/**
 * Returns a human-readable IOC type prefix label.
 *   "IP:1.2.3.4"     -> "IP"
 *   "Domain:evil.com" -> "Domain"
 *   "SHA256:abc..."   -> "SHA256"
 *   "YARA:rule_name"  -> "YARA"
 */
function iocLabel(ioc: string): { type: string; value: string } {
  const idx = ioc.indexOf(":");
  if (idx === -1) return { type: "", value: ioc };
  return { type: ioc.slice(0, idx), value: ioc.slice(idx + 1) };
}

export function SimilarSubmissionsCard({
  submissionId,
}: {
  submissionId: string;
}) {
  const [submissions, setSubmissions] = useState<SimilarSubmission[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchSimilar() {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(
          `${API_BASE}/submissions/${submissionId}/similar`
        );
        if (!res.ok) {
          const body = await res
            .json()
            .catch(() => ({ detail: res.statusText }));
          throw new Error(body.detail || `Request failed: ${res.status}`);
        }
        const data: { items: SimilarSubmission[] } = await res.json();
        if (!cancelled) {
          setSubmissions(data.items);
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : "Failed to fetch similar submissions"
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    fetchSimilar();
    return () => {
      cancelled = true;
    };
  }, [submissionId]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Similar Submissions</CardTitle>
      </CardHeader>
      <CardContent>
        {error && <p className="text-destructive text-sm mb-2">{error}</p>}

        {loading && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <svg
              className="h-4 w-4 animate-spin"
              viewBox="0 0 24 24"
              fill="none"
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
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
              />
            </svg>
            Searching for correlated submissions...
          </div>
        )}

        {!loading && !error && submissions.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No similar submissions found. Submissions sharing file hashes,
            network IOCs, or YARA signatures will appear here.
          </p>
        )}

        {!loading && submissions.length > 0 && (
          <div className="space-y-3">
            {submissions.map((sub) => (
              <div
                key={sub.id}
                className="flex flex-col gap-2 rounded-lg border border-border p-3"
              >
                {/* Top row: filename + badges */}
                <div className="flex items-start justify-between gap-2">
                  <Link
                    href={`/submissions/${sub.id}`}
                    className="text-sm font-medium text-primary hover:underline underline-offset-2 truncate max-w-[60%]"
                    title={sub.filename || sub.id}
                  >
                    {sub.filename || sub.id}
                  </Link>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <Badge variant={scoreBadgeVariant(sub.similarity_score)}>
                      {Math.round(sub.similarity_score * 100)}% match
                    </Badge>
                    {sub.verdict && (
                      <Badge variant={verdictBadgeVariant(sub.verdict)}>
                        {sub.verdict}
                      </Badge>
                    )}
                  </div>
                </div>

                {/* Shared IOCs */}
                {sub.shared_iocs.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {sub.shared_iocs.slice(0, 8).map((ioc, idx) => {
                      const { type, value } = iocLabel(ioc);
                      return (
                        <Badge
                          key={idx}
                          variant="outline"
                          className="text-[10px] font-mono"
                        >
                          {type && (
                            <span className="font-semibold mr-0.5">
                              {type}:
                            </span>
                          )}
                          {value.length > 30
                            ? value.slice(0, 27) + "..."
                            : value}
                        </Badge>
                      );
                    })}
                    {sub.shared_iocs.length > 8 && (
                      <Badge variant="outline" className="text-[10px]">
                        +{sub.shared_iocs.length - 8} more
                      </Badge>
                    )}
                  </div>
                )}

                {/* Submitted date */}
                {sub.submitted_at && (
                  <p className="text-xs text-muted-foreground">
                    Submitted{" "}
                    {new Date(sub.submitted_at).toLocaleDateString(undefined, {
                      year: "numeric",
                      month: "short",
                      day: "numeric",
                    })}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
