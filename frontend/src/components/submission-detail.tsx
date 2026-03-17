"use client";

import { useCallback, useEffect, useState } from "react";

import { api } from "@/lib/api";
import type { AIStatus, Submission } from "@/lib/types";
import { AgentRunCard } from "@/components/ai/agent-run-card";
import { AISummaryCard } from "@/components/ai/ai-summary-card";
import { AIVerdictBadge } from "@/components/ai/ai-verdict-badge";
import { GenerateReportCard } from "@/components/ai/generate-report-card";
import { SimilarSubmissionsCard } from "@/components/ai/similar-submissions-card";
import { AnalysisCard } from "@/components/analysis-card";
import { ChatPanel } from "@/components/chat/chat-panel";
import { CommentsSection } from "@/components/comments-section";
import { IOCExportCard } from "@/components/ioc-export-card";
import { ReportDownloadCard } from "@/components/report-download-card";
import { StaticAnalysisCard } from "@/components/static-analysis-card";
import { ThreatIntelCard } from "@/components/threat-intel-card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Button variant="ghost" size="sm" onClick={handleCopy} className="h-6 px-2 text-xs">
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

function HashRow({ label, value }: { label: string; value: string | null }) {
  if (!value) return null;
  return (
    <div className="flex items-center justify-between py-2 border-b last:border-0">
      <span className="text-sm text-muted-foreground w-16">{label}</span>
      <span className="font-mono text-sm flex-1 mx-2 break-all">{value}</span>
      <CopyButton text={value} />
    </div>
  );
}

export function SubmissionDetail({ id }: { id: string }) {
  const [submission, setSubmission] = useState<Submission | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [aiStatus, setAIStatus] = useState<AIStatus | null>(null);

  const refreshSubmission = useCallback(() => {
    api.getSubmission(id).then(setSubmission).catch(() => {});
  }, [id]);

  useEffect(() => {
    api
      .getSubmission(id)
      .then(setSubmission)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));

    api.getAIStatus().then(setAIStatus).catch(() => {});
  }, [id]);

  if (loading) return <p className="text-center text-muted-foreground">Loading...</p>;
  if (error) return <p className="text-center text-destructive">{error}</p>;
  if (!submission) return <p className="text-center text-muted-foreground">Not found.</p>;

  const verdictVariant =
    submission.verdict === "malicious"
      ? "destructive"
      : submission.verdict === "suspicious"
        ? "secondary"
        : submission.verdict === "clean"
          ? "outline"
          : "default";

  return (
    <div className="mx-auto max-w-2xl space-y-4">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>{submission.filename || "Unknown File"}</CardTitle>
            <div className="flex gap-2">
              <Badge variant={verdictVariant}>{submission.verdict}</Badge>
              {submission.ai_verdict && (
                <AIVerdictBadge
                  verdict={submission.ai_verdict}
                  score={submission.ai_score}
                />
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-muted-foreground">File Size</span>
              <p className="font-medium">
                {submission.file_size
                  ? `${(submission.file_size / 1024).toFixed(1)} KB`
                  : "N/A"}
              </p>
            </div>
            <div>
              <span className="text-muted-foreground">File Type</span>
              <p className="font-medium">{submission.file_type || "N/A"}</p>
            </div>
            <div>
              <span className="text-muted-foreground">MIME Type</span>
              <p className="font-medium">{submission.mime_type || "N/A"}</p>
            </div>
            <div>
              <span className="text-muted-foreground">Score</span>
              <p className="font-medium">{submission.score}/100</p>
            </div>
            <div>
              <span className="text-muted-foreground">Submitted</span>
              <p className="font-medium">
                {submission.submitted_at
                  ? new Date(submission.submitted_at).toLocaleString()
                  : "N/A"}
              </p>
            </div>
            <div>
              <span className="text-muted-foreground">Tags</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {submission.tags && submission.tags.length > 0 ? (
                  submission.tags.map((tag) => (
                    <Badge key={tag} variant="outline" className="text-xs">
                      {tag}
                    </Badge>
                  ))
                ) : (
                  <span className="text-muted-foreground text-sm">None</span>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Hashes</CardTitle>
        </CardHeader>
        <CardContent>
          <HashRow label="SHA256" value={submission.file_hash_sha256} />
          <HashRow label="MD5" value={submission.file_hash_md5} />
          <HashRow label="SHA1" value={submission.file_hash_sha1} />
        </CardContent>
      </Card>

      <StaticAnalysisCard submissionId={id} />

      <AnalysisCard submissionId={id} />

      <ThreatIntelCard submissionId={id} />

      <IOCExportCard submissionId={id} />

      <ReportDownloadCard submissionId={id} />

      <CommentsSection submissionId={id} />

      {aiStatus?.enabled && aiStatus?.configured && (
        <>
          <AISummaryCard submission={submission} onUpdate={refreshSubmission} />
          <AgentRunCard submissionId={id} onComplete={refreshSubmission} />
          <GenerateReportCard submissionId={id} />
          <SimilarSubmissionsCard submissionId={id} />
          <ChatPanel submissionId={id} />
        </>
      )}
    </div>
  );
}
