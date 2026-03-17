"use client";

import { useDashboard } from "@/hooks/use-dashboard";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

function StatCard({
  title,
  value,
  description,
}: {
  title: string;
  value: string | number;
  description?: string;
}) {
  return (
    <Card size="sm">
      <CardHeader>
        <CardDescription>{title}</CardDescription>
        <CardTitle className="text-2xl tabular-nums">{value}</CardTitle>
      </CardHeader>
      {description && (
        <CardContent>
          <p className="text-xs text-muted-foreground">{description}</p>
        </CardContent>
      )}
    </Card>
  );
}

function VerdictBar({
  verdicts,
  total,
}: {
  verdicts: { malicious: number; suspicious: number; clean: number; unknown: number };
  total: number;
}) {
  if (total === 0) {
    return (
      <div className="h-6 w-full rounded-full bg-muted">
        <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
          No data
        </div>
      </div>
    );
  }

  const segments = [
    { key: "malicious", count: verdicts.malicious, color: "bg-red-500", label: "Malicious" },
    { key: "suspicious", count: verdicts.suspicious, color: "bg-yellow-500", label: "Suspicious" },
    { key: "clean", count: verdicts.clean, color: "bg-green-500", label: "Clean" },
    { key: "unknown", count: verdicts.unknown, color: "bg-gray-400", label: "Unknown" },
  ];

  return (
    <div className="space-y-2">
      <div className="flex h-6 w-full overflow-hidden rounded-full">
        {segments.map((seg) => {
          const pct = (seg.count / total) * 100;
          if (pct === 0) return null;
          return (
            <div
              key={seg.key}
              className={`${seg.color} transition-all`}
              style={{ width: `${pct}%` }}
              title={`${seg.label}: ${seg.count} (${pct.toFixed(1)}%)`}
            />
          );
        })}
      </div>
      <div className="flex flex-wrap gap-3 text-xs">
        {segments.map((seg) => (
          <div key={seg.key} className="flex items-center gap-1">
            <span className={`inline-block h-2.5 w-2.5 rounded-full ${seg.color}`} />
            <span className="text-muted-foreground">{seg.label}:</span>
            <span className="font-medium">{seg.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function TimelineChart({
  points,
}: {
  points: { date: string; count: number; malicious: number; suspicious: number; clean: number }[];
}) {
  if (points.length === 0) {
    return (
      <p className="py-8 text-center text-sm text-muted-foreground">
        No timeline data available.
      </p>
    );
  }

  const maxCount = Math.max(...points.map((p) => p.count), 1);

  return (
    <div className="space-y-2">
      <div className="flex items-end gap-px" style={{ height: "160px" }}>
        {points.map((point, idx) => {
          const totalPct = (point.count / maxCount) * 100;
          const malPct = point.count > 0 ? (point.malicious / point.count) * totalPct : 0;
          const susPct = point.count > 0 ? (point.suspicious / point.count) * totalPct : 0;
          const cleanPct = point.count > 0 ? (point.clean / point.count) * totalPct : 0;
          const otherPct = totalPct - malPct - susPct - cleanPct;

          return (
            <div
              key={idx}
              className="group relative flex flex-1 flex-col justify-end"
              style={{ height: "100%" }}
              title={`${point.date}: ${point.count} submissions`}
            >
              <div className="flex flex-col justify-end" style={{ height: `${totalPct}%`, minHeight: point.count > 0 ? "2px" : "0" }}>
                {otherPct > 0 && (
                  <div
                    className="w-full bg-gray-400 transition-colors group-hover:bg-gray-500"
                    style={{ height: `${(otherPct / totalPct) * 100}%`, minHeight: "1px" }}
                  />
                )}
                {cleanPct > 0 && (
                  <div
                    className="w-full bg-green-500 transition-colors group-hover:bg-green-600"
                    style={{ height: `${(cleanPct / totalPct) * 100}%`, minHeight: "1px" }}
                  />
                )}
                {susPct > 0 && (
                  <div
                    className="w-full bg-yellow-500 transition-colors group-hover:bg-yellow-600"
                    style={{ height: `${(susPct / totalPct) * 100}%`, minHeight: "1px" }}
                  />
                )}
                {malPct > 0 && (
                  <div
                    className="w-full bg-red-500 transition-colors group-hover:bg-red-600"
                    style={{ height: `${(malPct / totalPct) * 100}%`, minHeight: "1px" }}
                  />
                )}
              </div>
              {/* Tooltip on hover */}
              <div className="pointer-events-none absolute bottom-full left-1/2 z-10 mb-1 hidden -translate-x-1/2 whitespace-nowrap rounded bg-popover px-2 py-1 text-[10px] text-popover-foreground shadow ring-1 ring-foreground/10 group-hover:block">
                {point.date}: {point.count}
              </div>
            </div>
          );
        })}
      </div>
      {/* X-axis labels (show first, middle, last) */}
      {points.length > 0 && (
        <div className="flex justify-between text-[10px] text-muted-foreground">
          <span>{points[0].date}</span>
          {points.length > 2 && (
            <span>{points[Math.floor(points.length / 2)].date}</span>
          )}
          <span>{points[points.length - 1].date}</span>
        </div>
      )}
    </div>
  );
}

export default function DashboardPage() {
  const { stats, timeline, topIOCs, loading, error, refresh } = useDashboard();

  if (loading) {
    return (
      <div className="mx-auto max-w-5xl px-4 py-8">
        <p className="text-center text-muted-foreground">Loading dashboard...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="mx-auto max-w-5xl space-y-4 px-4 py-8">
        <p className="text-center text-destructive">{error}</p>
        <div className="text-center">
          <Button variant="outline" size="sm" onClick={refresh}>
            Retry
          </Button>
        </div>
      </div>
    );
  }

  if (!stats) return null;

  const maliciousPct =
    stats.total_submissions > 0
      ? ((stats.verdicts.malicious / stats.total_submissions) * 100).toFixed(1)
      : "0.0";

  return (
    <div className="mx-auto max-w-5xl space-y-6 px-4 py-8">
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-sm text-muted-foreground">
            Overview of submissions, analyses, and threat landscape.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={refresh}>
          Refresh
        </Button>
      </div>

      {/* Stats cards row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          title="Total Submissions"
          value={stats.total_submissions}
          description={`${stats.submissions_today} today, ${stats.submissions_this_week} this week`}
        />
        <StatCard
          title="Total Analyses"
          value={stats.total_analyses}
          description={`${stats.analysis_status_breakdown.completed} completed, ${stats.analysis_status_breakdown.running} running`}
        />
        <StatCard
          title="Average Score"
          value={stats.average_score.toFixed(1)}
          description="Across all submissions"
        />
        <StatCard
          title="Malicious Rate"
          value={`${maliciousPct}%`}
          description={`${stats.verdicts.malicious} of ${stats.total_submissions} submissions`}
        />
      </div>

      {/* Verdict breakdown */}
      <Card>
        <CardHeader>
          <CardTitle>Verdict Distribution</CardTitle>
          <CardDescription>Breakdown of submission verdicts</CardDescription>
        </CardHeader>
        <CardContent>
          <VerdictBar verdicts={stats.verdicts} total={stats.total_submissions} />
        </CardContent>
      </Card>

      {/* Timeline + Analysis Status */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Submission Timeline</CardTitle>
            <CardDescription>
              {timeline ? `Last ${timeline.days} days` : "Loading..."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {timeline ? (
              <TimelineChart points={timeline.points} />
            ) : (
              <p className="py-8 text-center text-sm text-muted-foreground">
                No timeline data.
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Analysis Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {[
                { label: "Completed", value: stats.analysis_status_breakdown.completed, color: "bg-green-500" },
                { label: "Running", value: stats.analysis_status_breakdown.running, color: "bg-blue-500" },
                { label: "Queued", value: stats.analysis_status_breakdown.queued, color: "bg-yellow-500" },
                { label: "Failed", value: stats.analysis_status_breakdown.failed, color: "bg-red-500" },
              ].map((item) => (
                <div key={item.label} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`inline-block h-2.5 w-2.5 rounded-full ${item.color}`} />
                    <span className="text-sm">{item.label}</span>
                  </div>
                  <span className="text-sm font-medium tabular-nums">{item.value}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Top File Types + Top Tags */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Top File Types</CardTitle>
          </CardHeader>
          <CardContent>
            {stats.top_file_types.length > 0 ? (
              <div className="space-y-2">
                {stats.top_file_types.map((ft) => {
                  const maxFT = stats.top_file_types[0]?.count || 1;
                  const pct = (ft.count / maxFT) * 100;
                  return (
                    <div key={ft.type} className="space-y-1">
                      <div className="flex items-center justify-between text-sm">
                        <span className="truncate">{ft.type}</span>
                        <span className="ml-2 font-medium tabular-nums">{ft.count}</span>
                      </div>
                      <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                        <div
                          className="h-full rounded-full bg-primary transition-all"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="py-4 text-center text-sm text-muted-foreground">
                No file type data yet.
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top Tags</CardTitle>
          </CardHeader>
          <CardContent>
            {stats.top_tags.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {stats.top_tags.map((t) => (
                  <Badge key={t.type} variant="secondary" className="text-sm">
                    {t.type}
                    <span className="ml-1 opacity-60">{t.count}</span>
                  </Badge>
                ))}
              </div>
            ) : (
              <p className="py-4 text-center text-sm text-muted-foreground">
                No tag data yet.
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Top IOCs */}
      {topIOCs && (topIOCs.ips.length > 0 || topIOCs.domains.length > 0) && (
        <div className="grid gap-4 lg:grid-cols-2">
          {topIOCs.ips.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Top IPs</CardTitle>
                <CardDescription>Most frequently observed external IPs</CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>IP Address</TableHead>
                      <TableHead className="text-right">Count</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {topIOCs.ips.slice(0, 10).map((ioc) => (
                      <TableRow key={ioc.value}>
                        <TableCell className="font-mono text-sm">{ioc.value}</TableCell>
                        <TableCell className="text-right font-medium tabular-nums">
                          {ioc.count}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}

          {topIOCs.domains.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Top Domains</CardTitle>
                <CardDescription>Most frequently queried domains</CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Domain</TableHead>
                      <TableHead className="text-right">Count</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {topIOCs.domains.slice(0, 10).map((ioc) => (
                      <TableRow key={ioc.value}>
                        <TableCell className="font-mono text-sm">{ioc.value}</TableCell>
                        <TableCell className="text-right font-medium tabular-nums">
                          {ioc.count}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
