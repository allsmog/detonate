"use client";

import { useCallback, useEffect, useState } from "react";

export interface ScreenshotInfo {
  url: string;
  index: number;
  timestamp?: number;
}

export interface AnalysisMedia {
  screenshots: ScreenshotInfo[];
  video_url: string | null;
}

/**
 * Hook to fetch screenshot and video media for an analysis.
 *
 * Polls the `/media` endpoint once on mount or whenever the
 * submissionId/analysisId changes.  Provides a `refresh` callback
 * for manual re-fetching (e.g. after analysis completes).
 */
export function useAnalysisMedia(
  submissionId: string,
  analysisId: string | null,
) {
  const [data, setData] = useState<AnalysisMedia | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchMedia = useCallback(async () => {
    if (!analysisId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await window.fetch(
        `/api/v1/submissions/${submissionId}/analyses/${analysisId}/media`,
      );
      if (res.ok) {
        const json: AnalysisMedia = await res.json();
        setData(json);
      } else if (res.status === 404) {
        // No media available yet -- not an error
        setData({ screenshots: [], video_url: null });
      } else {
        const body = await res.json().catch(() => ({ detail: res.statusText }));
        setError(body.detail || `Failed to load media (${res.status})`);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load media");
    } finally {
      setLoading(false);
    }
  }, [submissionId, analysisId]);

  useEffect(() => {
    fetchMedia();
  }, [fetchMedia]);

  // Reset state when analysis changes
  useEffect(() => {
    setData(null);
    setError(null);
  }, [analysisId]);

  return { data, loading, error, refresh: fetchMedia };
}
