"use client";

import { useCallback, useEffect, useState } from "react";

import { api } from "@/lib/api";

export interface MITRETechnique {
  technique_id: string;
  name: string;
  confidence: number;
  evidence: string;
  source: string;
}

export interface MITREData {
  techniques: MITRETechnique[];
  tactics_coverage: Record<string, number>;
}

interface UseMitreMappingReturn {
  /** The current MITRE mapping data (null until first fetch completes). */
  data: MITREData | null;
  /** True while a request is in-flight. */
  loading: boolean;
  /** Error message from the last failed request, if any. */
  error: string | null;
  /** Trigger a POST to run (or re-run) MITRE mapping. */
  runMapping: (useAI?: boolean) => Promise<void>;
  /** Re-fetch the cached GET data. */
  refresh: () => Promise<void>;
}

export function useMitreMapping(
  submissionId: string,
  analysisId: string | null,
): UseMitreMappingReturn {
  const [data, setData] = useState<MITREData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchMapping = useCallback(async () => {
    if (!analysisId) return;

    try {
      const result = await api.getMitreMapping(submissionId, analysisId);
      setData(result);
      setError(null);
    } catch (err) {
      // Not-found or empty mapping is not an error -- just means it hasn't been run
      setData(null);
    }
  }, [submissionId, analysisId]);

  // Fetch on mount / when IDs change
  useEffect(() => {
    if (analysisId) {
      fetchMapping();
    }
  }, [analysisId, fetchMapping]);

  const runMapping = useCallback(
    async (useAI = false) => {
      if (!analysisId) return;

      setLoading(true);
      setError(null);
      try {
        const result = await api.runMitreMapping(
          submissionId,
          analysisId,
          useAI,
        );
        setData(result);
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "Failed to run MITRE mapping";
        setError(message);
      } finally {
        setLoading(false);
      }
    },
    [submissionId, analysisId],
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      await fetchMapping();
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to fetch MITRE mapping";
      setError(message);
    } finally {
      setLoading(false);
    }
  }, [fetchMapping]);

  return { data, loading, error, runMapping, refresh };
}
