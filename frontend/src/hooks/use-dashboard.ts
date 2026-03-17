"use client";

import { useCallback, useEffect, useState } from "react";

export interface TypeCount {
  type: string;
  count: number;
}

export interface AnalysisStatusBreakdown {
  completed: number;
  failed: number;
  running: number;
  queued: number;
}

export interface DashboardStats {
  total_submissions: number;
  total_analyses: number;
  verdicts: {
    malicious: number;
    suspicious: number;
    clean: number;
    unknown: number;
  };
  submissions_today: number;
  submissions_this_week: number;
  submissions_this_month: number;
  average_score: number;
  top_file_types: TypeCount[];
  top_tags: TypeCount[];
  analysis_status_breakdown: AnalysisStatusBreakdown;
}

export interface TimelinePoint {
  date: string;
  count: number;
  malicious: number;
  suspicious: number;
  clean: number;
}

export interface TimelineResponse {
  points: TimelinePoint[];
  days: number;
  granularity: string;
}

export interface IOCEntry {
  value: string;
  count: number;
}

export interface TopIOCs {
  ips: IOCEntry[];
  domains: IOCEntry[];
}

export function useDashboard(timelineDays = 30) {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [timeline, setTimeline] = useState<TimelineResponse | null>(null);
  const [topIOCs, setTopIOCs] = useState<TopIOCs | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDashboard = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const [statsRes, timelineRes, iocsRes] = await Promise.all([
        fetch("/api/v1/dashboard/stats"),
        fetch(`/api/v1/dashboard/timeline?days=${timelineDays}&granularity=day`),
        fetch("/api/v1/dashboard/top-iocs?limit=20"),
      ]);

      if (!statsRes.ok) {
        const body = await statsRes.json().catch(() => ({ detail: statsRes.statusText }));
        throw new Error(body.detail || "Failed to fetch dashboard stats");
      }
      if (!timelineRes.ok) {
        const body = await timelineRes.json().catch(() => ({ detail: timelineRes.statusText }));
        throw new Error(body.detail || "Failed to fetch timeline");
      }
      if (!iocsRes.ok) {
        const body = await iocsRes.json().catch(() => ({ detail: iocsRes.statusText }));
        throw new Error(body.detail || "Failed to fetch top IOCs");
      }

      const [statsData, timelineData, iocsData] = await Promise.all([
        statsRes.json() as Promise<DashboardStats>,
        timelineRes.json() as Promise<TimelineResponse>,
        iocsRes.json() as Promise<TopIOCs>,
      ]);

      setStats(statsData);
      setTimeline(timelineData);
      setTopIOCs(iocsData);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard");
    } finally {
      setLoading(false);
    }
  }, [timelineDays]);

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  return {
    stats,
    timeline,
    topIOCs,
    loading,
    error,
    refresh: fetchDashboard,
  };
}
