"use client";

import { Badge } from "@/components/ui/badge";

export function AIVerdictBadge({
  verdict,
  score,
}: {
  verdict: string | null;
  score: number | null;
}) {
  if (!verdict) return null;

  const variant =
    verdict === "malicious"
      ? "destructive"
      : verdict === "suspicious"
        ? "secondary"
        : verdict === "clean"
          ? "outline"
          : "default";

  return (
    <Badge variant={variant}>
      AI: {verdict} {score !== null && `(${score}/100)`}
    </Badge>
  );
}
