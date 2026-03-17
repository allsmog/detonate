"use client";

import { useCallback, useEffect, useState } from "react";

import type { StaticAnalysisResponse } from "@/lib/types";

const API_BASE = "/api/v1";

export function useStaticAnalysis(submissionId: string) {
  const [data, setData] = useState<StaticAnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetch = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token =
        typeof window !== "undefined"
          ? localStorage.getItem("detonate_token")
          : null;
      const headers: Record<string, string> = {};
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }

      const res = await globalThis.fetch(
        `${API_BASE}/submissions/${submissionId}/static`,
        { headers }
      );
      if (!res.ok) {
        const body = await res
          .json()
          .catch(() => ({ detail: res.statusText }));
        throw new Error(body.detail || `Request failed: ${res.status}`);
      }
      const result: StaticAnalysisResponse = await res.json();
      setData(result);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to fetch static analysis"
      );
    } finally {
      setLoading(false);
    }
  }, [submissionId]);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { data, loading, error, refresh: fetch };
}
