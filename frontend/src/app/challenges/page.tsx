"use client";

import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
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
import { useChallenges } from "@/hooks/use-challenges";

const DIFFICULTY_COLORS: Record<string, string> = {
  beginner: "bg-green-500/15 text-green-600",
  intermediate: "bg-yellow-500/15 text-yellow-600",
  advanced: "bg-red-500/15 text-red-600",
};

export default function ChallengesPage() {
  const { data, leaderboard, loading, error } = useChallenges();

  const solved = data?.challenges.filter((c) => c.solved).length ?? 0;
  const earned =
    data?.challenges.reduce((sum, c) => sum + (c.solved ? c.points : 0), 0) ?? 0;

  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight">Challenges</h1>
        <p className="text-sm text-muted-foreground">
          Auto-graded CTF tied to the{" "}
          <a
            href="https://github.com/allsmog/detonate/tree/main/masterclass"
            className="underline"
          >
            Masterclass
          </a>
          . Do the lab, recover the value, submit it as the flag.
        </p>
      </div>

      {error && (
        <div className="mb-4 rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-600">
          {error}
        </div>
      )}

      {!loading && data && (
        <div className="mb-6 flex gap-4 text-sm">
          <Badge variant="secondary">
            {solved} / {data.total} solved
          </Badge>
          <Badge variant="secondary">
            {earned} / {data.total_points} points
          </Badge>
        </div>
      )}

      <div className="grid gap-6 md:grid-cols-3">
        <div className="md:col-span-2 space-y-3">
          {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
          {data?.challenges.map((c) => (
            <Link key={c.slug} href={`/challenges/${c.slug}`} className="block">
              <Card className="transition-colors hover:border-foreground/30">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base">
                      {c.solved && <span className="mr-1 text-green-600">✓</span>}
                      {c.title}
                    </CardTitle>
                    <span className="text-sm font-mono text-muted-foreground">
                      {c.points} pts
                    </span>
                  </div>
                  <CardDescription className="line-clamp-2">
                    {c.description}
                  </CardDescription>
                </CardHeader>
                <CardContent className="flex gap-2">
                  <Badge
                    className={DIFFICULTY_COLORS[c.difficulty] ?? ""}
                    variant="secondary"
                  >
                    {c.difficulty}
                  </Badge>
                  <Badge variant="outline">{c.category}</Badge>
                  <span className="ml-auto text-xs text-muted-foreground">
                    {c.solve_count} solves
                  </span>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>

        <div>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Leaderboard</CardTitle>
            </CardHeader>
            <CardContent>
              {leaderboard && leaderboard.entries.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Player</TableHead>
                      <TableHead className="text-right">Pts</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {leaderboard.entries.slice(0, 10).map((e) => (
                      <TableRow key={e.player}>
                        <TableCell className="truncate font-mono text-xs">
                          {e.player}
                        </TableCell>
                        <TableCell className="text-right font-medium">
                          {e.points}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <p className="text-sm text-muted-foreground">
                  No solves yet. Be the first.
                </p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
