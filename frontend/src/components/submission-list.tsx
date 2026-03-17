"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import type { Submission, SubmissionListResponse } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

function VerdictBadge({ verdict }: { verdict: string }) {
  const variant =
    verdict === "malicious"
      ? "destructive"
      : verdict === "suspicious"
        ? "secondary"
        : verdict === "clean"
          ? "outline"
          : "default";

  return <Badge variant={variant}>{verdict}</Badge>;
}

export function SubmissionList() {
  const [data, setData] = useState<SubmissionListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const limit = 20;

  useEffect(() => {
    setLoading(true);
    api
      .getSubmissions(limit, offset)
      .then(setData)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [offset]);

  if (loading) return <p className="text-center text-muted-foreground">Loading...</p>;
  if (error) return <p className="text-center text-destructive">{error}</p>;
  if (!data || data.items.length === 0)
    return <p className="text-center text-muted-foreground">No submissions yet.</p>;

  return (
    <div className="space-y-4">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Filename</TableHead>
            <TableHead>SHA256</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Verdict</TableHead>
            <TableHead>Submitted</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.items.map((s: Submission) => (
            <TableRow key={s.id}>
              <TableCell>
                <Link
                  href={`/submissions/${s.id}`}
                  className="font-medium hover:underline"
                >
                  {s.filename || "N/A"}
                </Link>
              </TableCell>
              <TableCell className="font-mono text-xs">
                {s.file_hash_sha256.substring(0, 16)}...
              </TableCell>
              <TableCell className="text-sm">
                {s.file_type?.split(",")[0] || "Unknown"}
              </TableCell>
              <TableCell>
                <VerdictBadge verdict={s.verdict} />
              </TableCell>
              <TableCell className="text-sm text-muted-foreground">
                {s.submitted_at
                  ? new Date(s.submitted_at).toLocaleString()
                  : "N/A"}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <div className="flex justify-between">
        <Button
          variant="outline"
          size="sm"
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - limit))}
        >
          Previous
        </Button>
        <span className="text-sm text-muted-foreground">
          {offset + 1}-{Math.min(offset + limit, data.total)} of {data.total}
        </span>
        <Button
          variant="outline"
          size="sm"
          disabled={offset + limit >= data.total}
          onClick={() => setOffset(offset + limit)}
        >
          Next
        </Button>
      </div>
    </div>
  );
}
