"use client";

import { useCallback, useEffect, useState } from "react";

import { api } from "@/lib/api";
import type {
  NetworkAnalysisResponse,
  NetworkIOCsResponse,
} from "@/lib/types";

/**
 * Fetches enriched network analysis data for a given analysis.
 */
export function useNetworkAnalysis(
  submissionId: string,
  analysisId: string | null
) {
  const [data, setData] = useState<NetworkAnalysisResponse | null>(null);
  const [iocs, setIocs] = useState<NetworkIOCsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    if (!analysisId) return;
    setLoading(true);
    setError(null);
    try {
      const [networkRes, iocsRes] = await Promise.all([
        api.getNetworkAnalysis(submissionId, analysisId),
        api.getNetworkIOCs(submissionId, analysisId),
      ]);
      setData(networkRes);
      setIocs(iocsRes);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to fetch network analysis"
      );
    } finally {
      setLoading(false);
    }
  }, [submissionId, analysisId]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  return { data, iocs, loading, error, refresh: fetchData };
}
