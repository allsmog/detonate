"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";

import { useSearch } from "@/hooks/use-search";
import { SearchFilters } from "@/components/search-filters";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

function VerdictBadge({ verdict }: { verdict: string }) {
  const variant =
    verdict === "malicious"
      ? "destructive"
      : verdict === "suspicious"
        ? "secondary"
        : verdict === "clean"
          ? "outline"
          : "default";

  return <Badge variant={variant}>{verdict}</Badge>;
}

function ScoreBadge({ score }: { score: number }) {
  let color = "text-muted-foreground";
  if (score >= 70) color = "text-red-600 dark:text-red-400 font-semibold";
  else if (score >= 40) color = "text-yellow-600 dark:text-yellow-400";
  else if (score > 0) color = "text-green-600 dark:text-green-400";

  return <span className={`font-mono text-sm ${color}`}>{score}</span>;
}

const SORT_OPTIONS = [
  { label: "Date (newest)", sort_by: "submitted_at", sort_order: "desc" },
  { label: "Date (oldest)", sort_by: "submitted_at", sort_order: "asc" },
  { label: "Score (high)", sort_by: "score", sort_order: "desc" },
  { label: "Score (low)", sort_by: "score", sort_order: "asc" },
  { label: "Filename (A-Z)", sort_by: "filename", sort_order: "asc" },
  { label: "Filename (Z-A)", sort_by: "filename", sort_order: "desc" },
] as const;

export default function SearchPage() {
  const router = useRouter();
  const {
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
  } = useSearch();

  const currentSortKey = `${filters.sort_by}:${filters.sort_order}`;

  return (
    <div className="mx-auto max-w-5xl space-y-6 px-4 py-8">
      <div className="space-y-1">
        <h1 className="text-2xl font-bold tracking-tight">Search Submissions</h1>
        <p className="text-sm text-muted-foreground">
          Search by hash, filename, tag, or IOC. Use filters to narrow results.
        </p>
      </div>

      <Card>
        <CardContent className="pt-4">
          <SearchFilters
            filters={filters}
            setFilter={setFilter}
            clearFilters={clearFilters}
            loading={loading}
          />
        </CardContent>
      </Card>

      {/* Sort control + result count */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {loading ? (
            "Searching..."
          ) : results ? (
            <>
              {results.total} result{results.total !== 1 ? "s" : ""} found
              {results.query ? (
                <> for &quot;{results.query}&quot;</>
              ) : null}
            </>
          ) : null}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Sort:</span>
          <select
            value={currentSortKey}
            onChange={(e) => {
              const [sortBy, sortOrder] = e.target.value.split(":");
              setFilter("sort_by", sortBy);
              setFilter("sort_order", sortOrder);
            }}
            className="h-7 rounded-lg border border-input bg-transparent px-2 text-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
          >
            {SORT_OPTIONS.map((opt) => (
              <option key={`${opt.sort_by}:${opt.sort_order}`} value={`${opt.sort_by}:${opt.sort_order}`}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <Card>
          <CardContent className="py-8 text-center text-destructive">
            {error}
          </CardContent>
        </Card>
      )}

      {/* Results table */}
      {!error && results && results.items.length > 0 && (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Filename</TableHead>
                  <TableHead>Hash</TableHead>
                  <TableHead>Verdict</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Tags</TableHead>
                  <TableHead>Submitted</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {results.items.map((item) => (
                  <TableRow
                    key={item.id}
                    className="cursor-pointer"
                    onClick={() => router.push(`/submissions/${item.id}`)}
                  >
                    <TableCell>
                      <Link
                        href={`/submissions/${item.id}`}
                        className="font-medium hover:underline"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {item.filename || "N/A"}
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {item.file_hash_sha256.substring(0, 16)}...
                    </TableCell>
                    <TableCell>
                      <VerdictBadge verdict={item.verdict} />
                    </TableCell>
                    <TableCell>
                      <ScoreBadge score={item.score} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {item.file_type?.split(",")[0] || "Unknown"}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {(item.tags || []).slice(0, 3).map((tag) => (
                          <Badge key={tag} variant="outline" className="text-[10px]">
                            {tag}
                          </Badge>
                        ))}
                        {(item.tags || []).length > 3 && (
                          <span className="text-[10px] text-muted-foreground">
                            +{item.tags.length - 3}
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {item.submitted_at
                        ? new Date(item.submitted_at).toLocaleDateString()
                        : "N/A"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Empty state */}
      {!error && !loading && results && results.items.length === 0 && (
        <Card>
          <CardContent className="py-12 text-center">
            <p className="text-muted-foreground">
              No submissions match your search criteria.
            </p>
            <Button
              variant="ghost"
              size="sm"
              className="mt-2"
              onClick={clearFilters}
            >
              Clear all filters
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Loading skeleton */}
      {loading && !results && (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            Loading...
          </CardContent>
        </Card>
      )}

      {/* Pagination */}
      {results && results.total > pageSize && (
        <div className="flex items-center justify-between">
          <Button
            variant="outline"
            size="sm"
            disabled={offset === 0 || loading}
            onClick={prevPage}
          >
            Previous
          </Button>
          <span className="text-sm text-muted-foreground">
            {offset + 1}&ndash;{Math.min(offset + pageSize, results.total)} of{" "}
            {results.total}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={offset + pageSize >= results.total || loading}
            onClick={nextPage}
          >
            Next
          </Button>
        </div>
      )}
    </div>
  );
}
