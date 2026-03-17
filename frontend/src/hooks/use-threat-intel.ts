"use client";

import { useCallback, useEffect, useState } from "react";

import { api } from "@/lib/api";
import type { ThreatIntelAggregateResponse } from "@/lib/types";

export function useThreatIntel(submissionId: string) {
  const [data, setData] = useState<ThreatIntelAggregateResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetch = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.getThreatIntel(submissionId);
      setData(result);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to fetch threat intel"
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
