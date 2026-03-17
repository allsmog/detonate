"use client";

import { useCallback, useState } from "react";

import { api } from "@/lib/api";
import type { AITask } from "@/lib/types";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

interface ToolCall {
  iteration: number;
  tool: string;
  arguments: Record<string, unknown>;
  result_preview?: string;
}

export function AgentRunCard({
  submissionId,
  onComplete,
}: {
  submissionId: string;
  onComplete?: () => void;
}) {
  const [task, setTask] = useState<AITask | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleRun = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const t = await api.requestAgentAnalysis(submissionId);
      setTask(t);
      if (t.status === "completed" || t.status === "failed") {
        setLoading(false);
        if (t.status === "completed") onComplete?.();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run analysis");
      setLoading(false);
    }
  }, [submissionId, onComplete]);

  const outputData = task?.output_data as Record<string, unknown> | null;
  const toolCalls = outputData?.tool_calls as ToolCall[] | undefined;
  const verdict = outputData?.verdict as
    | { verdict?: string; score?: number; reasoning?: string }
    | undefined;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">AI Agent Analysis</CardTitle>
          <Button
            variant="outline"
            size="sm"
            onClick={handleRun}
            disabled={loading}
          >
            {loading ? "Analyzing..." : task ? "Re-run" : "Run Analysis"}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {error && <p className="text-destructive text-sm">{error}</p>}

        {task?.status === "failed" && (
          <p className="text-destructive text-sm">
            Analysis failed: {task.error}
          </p>
        )}

        {toolCalls && toolCalls.length > 0 && (
          <div className="space-y-1">
            <p className="text-sm font-medium">Tool calls:</p>
            {toolCalls.map((tc, i) => (
              <div
                key={i}
                className="text-xs font-mono bg-muted rounded px-2 py-1"
              >
                {tc.iteration}. {tc.tool}(
                {Object.keys(tc.arguments || {}).length > 0
                  ? JSON.stringify(tc.arguments)
                  : ""}
                )
              </div>
            ))}
          </div>
        )}

        {verdict && (
          <div className="border-t pt-2">
            <p className="text-sm font-medium">
              Verdict:{" "}
              <span className="font-bold">
                {verdict.verdict ?? "unknown"} ({verdict.score ?? 0}/100)
              </span>
            </p>
            {verdict.reasoning && (
              <p className="text-sm text-muted-foreground mt-1">
                {verdict.reasoning}
              </p>
            )}
          </div>
        )}

        {!task && !loading && (
          <p className="text-sm text-muted-foreground">
            Run the AI agent to automatically analyze this file using multiple
            tools.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
