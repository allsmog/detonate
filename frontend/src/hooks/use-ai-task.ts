"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "@/lib/api";
import type { AITask } from "@/lib/types";

export function useAITask(submissionId: string) {
  const [task, setTask] = useState<AITask | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const pollTask = useCallback(
    (taskId: string) => {
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = setInterval(async () => {
        try {
          const updated = await api.getAITask(submissionId, taskId);
          setTask(updated);
          if (updated.status === "completed" || updated.status === "failed") {
            if (pollRef.current) clearInterval(pollRef.current);
            pollRef.current = null;
            setLoading(false);
          }
        } catch {
          if (pollRef.current) clearInterval(pollRef.current);
          pollRef.current = null;
          setLoading(false);
        }
      }, 2000);
    },
    [submissionId]
  );

  const requestSummary = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const t = await api.requestSummary(submissionId);
      setTask(t);
      if (t.status === "pending" || t.status === "running") {
        pollTask(t.id);
      } else {
        setLoading(false);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to request summary");
      setLoading(false);
    }
  }, [submissionId, pollTask]);

  const requestClassify = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const t = await api.requestClassify(submissionId);
      setTask(t);
      if (t.status === "pending" || t.status === "running") {
        pollTask(t.id);
      } else {
        setLoading(false);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to classify");
      setLoading(false);
    }
  }, [submissionId, pollTask]);

  const requestAgent = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const t = await api.requestAgentAnalysis(submissionId);
      setTask(t);
      if (t.status === "pending" || t.status === "running") {
        pollTask(t.id);
      } else {
        setLoading(false);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start analysis");
      setLoading(false);
    }
  }, [submissionId, pollTask]);

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  return {
    task,
    loading,
    error,
    requestSummary,
    requestClassify,
    requestAgent,
  };
}
