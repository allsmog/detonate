"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "@/lib/api";

export interface SearchFilters {
  q: string;
  verdict: string | null;
  file_type: string | null;
  tag: string | null;
  score_min: number | null;
  score_max: number | null;
  date_from: string | null;
  date_to: string | null;
  has_analysis: boolean | null;
  sort_by: string;
  sort_order: string;
}

export interface SubmissionSearchItem {
  id: string;
  filename: string | null;
  file_hash_sha256: string;
  file_hash_md5: string | null;
  file_hash_sha1: string | null;
  file_type: string | null;
  mime_type: string | null;
  verdict: string;
  score: number;
  tags: string[];
  submitted_at: string | null;
  file_size: number | null;
}

export interface SearchResult {
  items: SubmissionSearchItem[];
  total: number;
  limit: number;
  offset: number;
  query: string;
  filters: {
    verdict: string | null;
    file_type: string | null;
    tag: string | null;
    score_min: number | null;
    score_max: number | null;
    date_from: string | null;
    date_to: string | null;
    has_analysis: boolean | null;
  };
}

const DEFAULT_FILTERS: SearchFilters = {
  q: "",
  verdict: null,
  file_type: null,
  tag: null,
  score_min: null,
  score_max: null,
  date_from: null,
  date_to: null,
  has_analysis: null,
  sort_by: "submitted_at",
  sort_order: "desc",
};

const DEBOUNCE_MS = 300;

function buildSearchParams(filters: SearchFilters, limit: number, offset: number): string {
  const params = new URLSearchParams();
  if (filters.q) params.set("q", filters.q);
  if (filters.verdict) params.set("verdict", filters.verdict);
  if (filters.file_type) params.set("file_type", filters.file_type);
  if (filters.tag) params.set("tag", filters.tag);
  if (filters.score_min !== null) params.set("score_min", String(filters.score_min));
  if (filters.score_max !== null) params.set("score_max", String(filters.score_max));
  if (filters.date_from) params.set("date_from", filters.date_from);
  if (filters.date_to) params.set("date_to", filters.date_to);
  if (filters.has_analysis !== null) params.set("has_analysis", String(filters.has_analysis));
  params.set("sort_by", filters.sort_by);
  params.set("sort_order", filters.sort_order);
  params.set("limit", String(limit));
  params.set("offset", String(offset));
  return params.toString();
}

export function useSearch(pageSize = 20) {
  const [filters, setFiltersState] = useState<SearchFilters>(DEFAULT_FILTERS);
  const [results, setResults] = useState<SearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);

  // Debounce ref for text-based filters
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const fetchResults = useCallback(
    async (currentFilters: SearchFilters, currentOffset: number) => {
      // Cancel any in-flight request
      if (abortRef.current) {
        abortRef.current.abort();
      }
      const controller = new AbortController();
      abortRef.current = controller;

      setLoading(true);
      setError(null);

      try {
        const params = buildSearchParams(currentFilters, pageSize, currentOffset);
        const res = await fetch(`/api/v1/search?${params}`, {
          signal: controller.signal,
          headers: api["_getAuthHeaders"]
            ? (api as unknown as { _getAuthHeaders(): Record<string, string> })._getAuthHeaders()
            : {},
        });
        if (!res.ok) {
          const body = await res.json().catch(() => ({ detail: res.statusText }));
          throw new Error(body.detail || `Search failed: ${res.status}`);
        }
        const data: SearchResult = await res.json();
        setResults(data);
      } catch (err: unknown) {
        if (err instanceof Error && err.name === "AbortError") {
          return; // Request was cancelled, ignore
        }
        setError(err instanceof Error ? err.message : "Search failed");
      } finally {
        setLoading(false);
      }
    },
    [pageSize],
  );

  // Debounced fetch on filter changes
  useEffect(() => {
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }
    debounceRef.current = setTimeout(() => {
      fetchResults(filters, offset);
    }, DEBOUNCE_MS);

    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
    };
  }, [filters, offset, fetchResults]);

  // Clean up abort controller on unmount
  useEffect(() => {
    return () => {
      if (abortRef.current) {
        abortRef.current.abort();
      }
    };
  }, []);

  const setFilter = useCallback(
    <K extends keyof SearchFilters>(key: K, value: SearchFilters[K]) => {
      setFiltersState((prev) => ({ ...prev, [key]: value }));
      // Reset to first page when filters change
      if (key !== "sort_by" && key !== "sort_order") {
        setOffset(0);
      }
    },
    [],
  );

  const clearFilters = useCallback(() => {
    setFiltersState(DEFAULT_FILTERS);
    setOffset(0);
  }, []);

  const nextPage = useCallback(() => {
    if (results && offset + pageSize < results.total) {
      setOffset((prev) => prev + pageSize);
    }
  }, [results, offset, pageSize]);

  const prevPage = useCallback(() => {
    setOffset((prev) => Math.max(0, prev - pageSize));
  }, [pageSize]);

  const goToPage = useCallback(
    (page: number) => {
      setOffset(Math.max(0, (page - 1) * pageSize));
    },
    [pageSize],
  );

  return {
    results,
    loading,
    error,
    filters,
    offset,
    pageSize,
    setFilter,
    clearFilters,
    nextPage,
    prevPage,
    goToPage,
    refresh: () => fetchResults(filters, offset),
  };
}
