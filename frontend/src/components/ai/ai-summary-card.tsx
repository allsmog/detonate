"use client";

import { useCallback, useEffect, useState } from "react";

import { api } from "@/lib/api";
import type { Submission } from "@/lib/types";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export function AISummaryCard({
  submission,
  onUpdate,
}: {
  submission: Submission;
  onUpdate?: () => void;
}) {
  const [summary, setSummary] = useState<string | null>(submission.ai_summary);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setSummary(submission.ai_summary);
  }, [submission.ai_summary]);

  const handleGenerate = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const task = await api.requestSummary(submission.id);
      if (task.status === "completed" && task.output_data) {
        const output = task.output_data as { summary?: string };
        setSummary(output.summary || null);
        onUpdate?.();
      } else if (task.status === "failed") {
        setError(task.error || "Summary generation failed");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate summary");
    } finally {
      setLoading(false);
    }
  }, [submission.id, onUpdate]);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">AI Summary</CardTitle>
          {!summary && (
            <Button
              variant="outline"
              size="sm"
              onClick={handleGenerate}
              disabled={loading}
            >
              {loading ? "Generating..." : "Generate"}
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {error && <p className="text-destructive text-sm">{error}</p>}
        {summary ? (
          <p className="text-sm whitespace-pre-wrap">{summary}</p>
        ) : !loading ? (
          <p className="text-sm text-muted-foreground">
            No summary yet. Click Generate to create one.
          </p>
        ) : (
          <p className="text-sm text-muted-foreground">Analyzing file...</p>
        )}
      </CardContent>
    </Card>
  );
}
