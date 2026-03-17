"use client";

import { useCallback } from "react";

import type { SearchFilters as SearchFiltersType } from "@/hooks/use-search";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface SearchFiltersProps {
  filters: SearchFiltersType;
  setFilter: <K extends keyof SearchFiltersType>(
    key: K,
    value: SearchFiltersType[K],
  ) => void;
  clearFilters: () => void;
  loading?: boolean;
}

const VERDICTS = [
  { label: "All", value: "" },
  { label: "Malicious", value: "malicious" },
  { label: "Suspicious", value: "suspicious" },
  { label: "Clean", value: "clean" },
  { label: "Unknown", value: "unknown" },
] as const;

export function SearchFilters({
  filters,
  setFilter,
  clearFilters,
  loading,
}: SearchFiltersProps) {
  const hasActiveFilters =
    filters.verdict !== null ||
    filters.file_type !== null ||
    filters.tag !== null ||
    filters.score_min !== null ||
    filters.score_max !== null ||
    filters.date_from !== null ||
    filters.date_to !== null ||
    filters.has_analysis !== null;

  const handleScoreMin = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const val = e.target.value;
      setFilter("score_min", val ? parseInt(val, 10) : null);
    },
    [setFilter],
  );

  const handleScoreMax = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const val = e.target.value;
      setFilter("score_max", val ? parseInt(val, 10) : null);
    },
    [setFilter],
  );

  return (
    <div className="space-y-4">
      {/* Search input */}
      <div>
        <Label htmlFor="search-q" className="sr-only">
          Search
        </Label>
        <Input
          id="search-q"
          type="text"
          placeholder="Search by hash, filename, tag, or IOC..."
          value={filters.q}
          onChange={(e) => setFilter("q", e.target.value)}
          className="h-10 text-base"
          disabled={loading}
        />
      </div>

      {/* Filter controls */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {/* Verdict */}
        <div className="space-y-1">
          <Label htmlFor="filter-verdict" className="text-xs text-muted-foreground">
            Verdict
          </Label>
          <select
            id="filter-verdict"
            value={filters.verdict || ""}
            onChange={(e) =>
              setFilter("verdict", e.target.value || null)
            }
            className="h-8 w-full rounded-lg border border-input bg-transparent px-2.5 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
            disabled={loading}
          >
            {VERDICTS.map((v) => (
              <option key={v.value} value={v.value}>
                {v.label}
              </option>
            ))}
          </select>
        </div>

        {/* File Type */}
        <div className="space-y-1">
          <Label htmlFor="filter-file-type" className="text-xs text-muted-foreground">
            File Type
          </Label>
          <Input
            id="filter-file-type"
            type="text"
            placeholder="e.g. PE, ELF"
            value={filters.file_type || ""}
            onChange={(e) =>
              setFilter("file_type", e.target.value || null)
            }
            disabled={loading}
          />
        </div>

        {/* Tag */}
        <div className="space-y-1">
          <Label htmlFor="filter-tag" className="text-xs text-muted-foreground">
            Tag
          </Label>
          <Input
            id="filter-tag"
            type="text"
            placeholder="e.g. trojan"
            value={filters.tag || ""}
            onChange={(e) =>
              setFilter("tag", e.target.value || null)
            }
            disabled={loading}
          />
        </div>

        {/* Score Min */}
        <div className="space-y-1">
          <Label htmlFor="filter-score-min" className="text-xs text-muted-foreground">
            Score Min
          </Label>
          <Input
            id="filter-score-min"
            type="number"
            min={0}
            max={100}
            placeholder="0"
            value={filters.score_min ?? ""}
            onChange={handleScoreMin}
            disabled={loading}
          />
        </div>

        {/* Score Max */}
        <div className="space-y-1">
          <Label htmlFor="filter-score-max" className="text-xs text-muted-foreground">
            Score Max
          </Label>
          <Input
            id="filter-score-max"
            type="number"
            min={0}
            max={100}
            placeholder="100"
            value={filters.score_max ?? ""}
            onChange={handleScoreMax}
            disabled={loading}
          />
        </div>

        {/* Has Analysis */}
        <div className="space-y-1">
          <Label htmlFor="filter-has-analysis" className="text-xs text-muted-foreground">
            Analyzed
          </Label>
          <select
            id="filter-has-analysis"
            value={
              filters.has_analysis === null
                ? ""
                : filters.has_analysis
                  ? "true"
                  : "false"
            }
            onChange={(e) => {
              const val = e.target.value;
              setFilter(
                "has_analysis",
                val === "" ? null : val === "true",
              );
            }}
            className="h-8 w-full rounded-lg border border-input bg-transparent px-2.5 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
            disabled={loading}
          >
            <option value="">All</option>
            <option value="true">Yes</option>
            <option value="false">No</option>
          </select>
        </div>
      </div>

      {/* Date range */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="space-y-1">
          <Label htmlFor="filter-date-from" className="text-xs text-muted-foreground">
            From Date
          </Label>
          <Input
            id="filter-date-from"
            type="date"
            value={filters.date_from || ""}
            onChange={(e) =>
              setFilter("date_from", e.target.value || null)
            }
            disabled={loading}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="filter-date-to" className="text-xs text-muted-foreground">
            To Date
          </Label>
          <Input
            id="filter-date-to"
            type="date"
            value={filters.date_to || ""}
            onChange={(e) =>
              setFilter("date_to", e.target.value || null)
            }
            disabled={loading}
          />
        </div>
      </div>

      {/* Active filter badges and clear button */}
      {hasActiveFilters && (
        <div className="flex flex-wrap items-center gap-2">
          {filters.verdict && (
            <Badge variant="secondary">
              Verdict: {filters.verdict}
              <button
                className="ml-1 text-xs opacity-60 hover:opacity-100"
                onClick={() => setFilter("verdict", null)}
                aria-label="Remove verdict filter"
              >
                x
              </button>
            </Badge>
          )}
          {filters.file_type && (
            <Badge variant="secondary">
              Type: {filters.file_type}
              <button
                className="ml-1 text-xs opacity-60 hover:opacity-100"
                onClick={() => setFilter("file_type", null)}
                aria-label="Remove file type filter"
              >
                x
              </button>
            </Badge>
          )}
          {filters.tag && (
            <Badge variant="secondary">
              Tag: {filters.tag}
              <button
                className="ml-1 text-xs opacity-60 hover:opacity-100"
                onClick={() => setFilter("tag", null)}
                aria-label="Remove tag filter"
              >
                x
              </button>
            </Badge>
          )}
          {filters.score_min !== null && (
            <Badge variant="secondary">
              Score &gt;= {filters.score_min}
              <button
                className="ml-1 text-xs opacity-60 hover:opacity-100"
                onClick={() => setFilter("score_min", null)}
                aria-label="Remove minimum score filter"
              >
                x
              </button>
            </Badge>
          )}
          {filters.score_max !== null && (
            <Badge variant="secondary">
              Score &lt;= {filters.score_max}
              <button
                className="ml-1 text-xs opacity-60 hover:opacity-100"
                onClick={() => setFilter("score_max", null)}
                aria-label="Remove maximum score filter"
              >
                x
              </button>
            </Badge>
          )}
          {filters.date_from && (
            <Badge variant="secondary">
              From: {filters.date_from}
              <button
                className="ml-1 text-xs opacity-60 hover:opacity-100"
                onClick={() => setFilter("date_from", null)}
                aria-label="Remove from date filter"
              >
                x
              </button>
            </Badge>
          )}
          {filters.date_to && (
            <Badge variant="secondary">
              To: {filters.date_to}
              <button
                className="ml-1 text-xs opacity-60 hover:opacity-100"
                onClick={() => setFilter("date_to", null)}
                aria-label="Remove to date filter"
              >
                x
              </button>
            </Badge>
          )}
          {filters.has_analysis !== null && (
            <Badge variant="secondary">
              Analyzed: {filters.has_analysis ? "Yes" : "No"}
              <button
                className="ml-1 text-xs opacity-60 hover:opacity-100"
                onClick={() => setFilter("has_analysis", null)}
                aria-label="Remove analysis filter"
              >
                x
              </button>
            </Badge>
          )}
          <Button
            variant="ghost"
            size="xs"
            onClick={clearFilters}
          >
            Clear all filters
          </Button>
        </div>
      )}
    </div>
  );
}
