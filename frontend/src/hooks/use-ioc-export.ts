"use client";

import { useCallback, useEffect, useState } from "react";

const API_BASE = "/api/v1";

export interface IOCHash {
  sha256: string | null;
  md5: string | null;
  sha1: string | null;
}

export interface IOCEntry {
  value: string;
  port?: number | null;
  source?: string;
  type?: string;
  size?: number | null;
}

export interface IOCData {
  hashes: IOCHash;
  ips: IOCEntry[];
  domains: IOCEntry[];
  urls: IOCEntry[];
  emails: IOCEntry[];
  file_paths: IOCEntry[];
  registry_keys: IOCEntry[];
  mutexes: IOCEntry[];
}

function getAuthHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const token = localStorage.getItem("detonate_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function downloadBlob(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function useIOCExport(submissionId: string) {
  const [iocs, setIOCs] = useState<IOCData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchIOCs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(
        `${API_BASE}/submissions/${submissionId}/iocs`,
        { headers: getAuthHeaders() }
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(body.detail || `Request failed: ${res.status}`);
      }
      const data: IOCData = await res.json();
      setIOCs(data);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to fetch IOCs"
      );
    } finally {
      setLoading(false);
    }
  }, [submissionId]);

  useEffect(() => {
    fetchIOCs();
  }, [fetchIOCs]);

  const exportCSV = useCallback(async () => {
    try {
      const res = await fetch(
        `${API_BASE}/submissions/${submissionId}/iocs/csv`,
        { headers: getAuthHeaders() }
      );
      if (!res.ok) throw new Error("CSV export failed");
      const text = await res.text();
      downloadBlob(text, `iocs-${submissionId.slice(0, 12)}.csv`, "text/csv");
    } catch (err) {
      setError(err instanceof Error ? err.message : "CSV export failed");
    }
  }, [submissionId]);

  const exportSTIX = useCallback(async () => {
    try {
      const res = await fetch(
        `${API_BASE}/submissions/${submissionId}/iocs/stix`,
        { headers: getAuthHeaders() }
      );
      if (!res.ok) throw new Error("STIX export failed");
      const data = await res.json();
      downloadBlob(
        JSON.stringify(data, null, 2),
        `iocs-${submissionId.slice(0, 12)}-stix.json`,
        "application/json"
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "STIX export failed");
    }
  }, [submissionId]);

  const exportJSON = useCallback(async () => {
    try {
      const res = await fetch(
        `${API_BASE}/submissions/${submissionId}/iocs/json`,
        { headers: getAuthHeaders() }
      );
      if (!res.ok) throw new Error("JSON export failed");
      const text = await res.text();
      downloadBlob(
        text,
        `iocs-${submissionId.slice(0, 12)}.json`,
        "application/json"
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "JSON export failed");
    }
  }, [submissionId]);

  return {
    iocs,
    loading,
    error,
    refresh: fetchIOCs,
    exportCSV,
    exportSTIX,
    exportJSON,
  };
}
