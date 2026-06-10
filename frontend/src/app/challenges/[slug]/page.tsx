"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useChallenge } from "@/hooks/use-challenges";

export default function ChallengeDetailPage() {
  const params = useParams<{ slug: string }>();
  const slug = params.slug;
  const { challenge, loading, error, result, submit } = useChallenge(slug);
  const [flag, setFlag] = useState("");
  const [revealedHints, setRevealedHints] = useState(0);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!flag.trim()) return;
    setSubmitting(true);
    try {
      await submit(flag);
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) return <p className="p-8 text-sm text-muted-foreground">Loading…</p>;
  if (error || !challenge)
    return (
      <div className="mx-auto max-w-3xl px-4 py-8">
        <p className="text-sm text-red-600">{error ?? "Not found"}</p>
        <Link href="/challenges" className="text-sm underline">
          ← Back to challenges
        </Link>
      </div>
    );

  return (
    <div className="mx-auto max-w-3xl px-4 py-8">
      <Link href="/challenges" className="text-sm text-muted-foreground underline">
        ← Challenges
      </Link>

      <div className="mt-4 mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">
          {challenge.solved && <span className="mr-2 text-green-600">✓</span>}
          {challenge.title}
        </h1>
        <span className="font-mono text-sm text-muted-foreground">
          {challenge.points} pts
        </span>
      </div>

      <div className="mb-4 flex gap-2">
        <Badge variant="secondary">{challenge.difficulty}</Badge>
        <Badge variant="outline">{challenge.category}</Badge>
        {challenge.solved && (
          <Badge className="bg-green-500/15 text-green-600" variant="secondary">
            solved
          </Badge>
        )}
      </div>

      <Card className="mb-4">
        <CardContent className="pt-6">
          <p className="text-sm leading-relaxed">{challenge.description}</p>
          {challenge.module_ref && (
            <p className="mt-3 text-xs text-muted-foreground">
              Lab:{" "}
              <a
                className="underline"
                href={`https://github.com/allsmog/detonate/tree/main/${challenge.module_ref}`}
              >
                {challenge.module_ref}
              </a>
            </p>
          )}
        </CardContent>
      </Card>

      {challenge.hints.length > 0 && (
        <Card className="mb-4">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Hints</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {challenge.hints.slice(0, revealedHints).map((h, i) => (
              <p key={i} className="text-sm text-muted-foreground">
                {i + 1}. {h}
              </p>
            ))}
            {revealedHints < challenge.hints.length && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setRevealedHints((n) => n + 1)}
              >
                Reveal hint {revealedHints + 1} / {challenge.hints.length}
              </Button>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Submit flag</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} className="flex gap-2">
            <Input
              value={flag}
              onChange={(e) => setFlag(e.target.value)}
              placeholder="the value you recovered…"
              className="font-mono"
            />
            <Button type="submit" disabled={submitting}>
              {submitting ? "Checking…" : "Submit"}
            </Button>
          </form>
          {result && (
            <p
              className={`mt-3 text-sm ${
                result.correct ? "text-green-600" : "text-red-600"
              }`}
            >
              {result.message}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
