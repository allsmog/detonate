"use client";

import { useCallback, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

const API_BASE = "/api/v1";

/**
 * Renders a single line of markdown-like text into a React node with
 * basic inline formatting (bold, code, links).  This intentionally
 * avoids pulling in a full markdown library.
 */
function renderInline(text: string): React.ReactNode[] {
  const nodes: React.ReactNode[] = [];
  // Match **bold**, `code`, and [text](url)
  const re = /(\*\*(.+?)\*\*|`([^`]+)`|\[([^\]]+)\]\(([^)]+)\))/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = re.exec(text)) !== null) {
    if (match.index > lastIndex) {
      nodes.push(text.slice(lastIndex, match.index));
    }
    if (match[2]) {
      nodes.push(
        <strong key={match.index} className="font-semibold">
          {match[2]}
        </strong>
      );
    } else if (match[3]) {
      nodes.push(
        <code
          key={match.index}
          className="rounded bg-muted px-1 py-0.5 text-xs font-mono"
        >
          {match[3]}
        </code>
      );
    } else if (match[4] && match[5]) {
      nodes.push(
        <a
          key={match.index}
          href={match[5]}
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary underline underline-offset-2"
        >
          {match[4]}
        </a>
      );
    }
    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < text.length) {
    nodes.push(text.slice(lastIndex));
  }

  return nodes;
}

/**
 * Very lightweight Markdown renderer.  Handles headings, bullet lists,
 * tables, horizontal rules, code blocks, and inline formatting.
 */
function SimpleMarkdown({ content }: { content: string }) {
  const lines = content.split("\n");
  const elements: React.ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block
    if (line.startsWith("```")) {
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      i++; // skip closing ```
      elements.push(
        <pre
          key={`code-${i}`}
          className="overflow-x-auto rounded-md bg-muted p-3 text-xs font-mono"
        >
          <code>{codeLines.join("\n")}</code>
        </pre>
      );
      continue;
    }

    // Table: detect a line starting with "|"
    if (line.trim().startsWith("|")) {
      const tableLines: string[] = [];
      while (i < lines.length && lines[i].trim().startsWith("|")) {
        tableLines.push(lines[i]);
        i++;
      }
      const rows = tableLines
        .filter((l) => !/^\|[\s-:|]+\|$/.test(l.trim())) // skip separator rows
        .map((l) =>
          l
            .split("|")
            .filter((c) => c.trim() !== "")
            .map((c) => c.trim())
        );

      if (rows.length > 0) {
        const [header, ...body] = rows;
        elements.push(
          <div key={`table-${i}`} className="overflow-x-auto my-2">
            <table className="min-w-full text-xs border-collapse">
              <thead>
                <tr className="border-b border-border">
                  {header.map((cell, ci) => (
                    <th
                      key={ci}
                      className="px-2 py-1 text-left font-semibold"
                    >
                      {cell}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {body.map((row, ri) => (
                  <tr key={ri} className="border-b border-border/50">
                    {row.map((cell, ci) => (
                      <td key={ci} className="px-2 py-1">
                        {cell}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      }
      continue;
    }

    // Horizontal rule
    if (/^-{3,}$/.test(line.trim()) || /^\*{3,}$/.test(line.trim())) {
      elements.push(<hr key={`hr-${i}`} className="my-3 border-border" />);
      i++;
      continue;
    }

    // Headings
    if (line.startsWith("### ")) {
      elements.push(
        <h4 key={`h4-${i}`} className="mt-4 mb-1 text-sm font-semibold">
          {renderInline(line.slice(4))}
        </h4>
      );
      i++;
      continue;
    }
    if (line.startsWith("## ")) {
      elements.push(
        <h3 key={`h3-${i}`} className="mt-5 mb-1 text-base font-semibold">
          {renderInline(line.slice(3))}
        </h3>
      );
      i++;
      continue;
    }
    if (line.startsWith("# ")) {
      elements.push(
        <h2 key={`h2-${i}`} className="mt-6 mb-2 text-lg font-bold">
          {renderInline(line.slice(2))}
        </h2>
      );
      i++;
      continue;
    }

    // Bullet list item
    if (/^\s*[-*]\s/.test(line)) {
      const items: React.ReactNode[] = [];
      while (i < lines.length && /^\s*[-*]\s/.test(lines[i])) {
        const text = lines[i].replace(/^\s*[-*]\s+/, "");
        items.push(
          <li key={`li-${i}`} className="ml-4">
            {renderInline(text)}
          </li>
        );
        i++;
      }
      elements.push(
        <ul key={`ul-${i}`} className="list-disc space-y-0.5 text-sm my-1">
          {items}
        </ul>
      );
      continue;
    }

    // Empty line
    if (line.trim() === "") {
      i++;
      continue;
    }

    // Paragraph
    elements.push(
      <p key={`p-${i}`} className="text-sm my-1 leading-relaxed">
        {renderInline(line)}
      </p>
    );
    i++;
  }

  return <div className="space-y-1">{elements}</div>;
}

export function GenerateReportCard({
  submissionId,
}: {
  submissionId: string;
}) {
  const [report, setReport] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const downloadRef = useRef<HTMLAnchorElement>(null);

  const handleGenerate = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(
        `${API_BASE}/submissions/${submissionId}/ai/report`,
        { method: "POST" }
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(body.detail || `Request failed: ${res.status}`);
      }
      const data: { report: string } = await res.json();
      setReport(data.report);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to generate report"
      );
    } finally {
      setLoading(false);
    }
  }, [submissionId]);

  const handleDownload = useCallback(() => {
    if (!report) return;
    const blob = new Blob([report], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = downloadRef.current;
    if (a) {
      a.href = url;
      a.download = `threat-report-${submissionId}.md`;
      a.click();
      URL.revokeObjectURL(url);
    }
  }, [report, submissionId]);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">Threat Report</CardTitle>
          <div className="flex items-center gap-2">
            {report && (
              <Button variant="outline" size="sm" onClick={handleDownload}>
                Download .md
              </Button>
            )}
            <Button
              variant={report ? "secondary" : "outline"}
              size="sm"
              onClick={handleGenerate}
              disabled={loading}
            >
              {loading
                ? "Generating..."
                : report
                  ? "Regenerate"
                  : "Generate Report"}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {error && <p className="text-destructive text-sm mb-2">{error}</p>}

        {loading && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <svg
              className="h-4 w-4 animate-spin"
              viewBox="0 0 24 24"
              fill="none"
            >
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
              />
            </svg>
            Generating comprehensive threat report...
          </div>
        )}

        {report ? (
          <div className="prose-sm max-w-none">
            <SimpleMarkdown content={report} />
          </div>
        ) : (
          !loading && (
            <p className="text-sm text-muted-foreground">
              Generate a comprehensive AI-powered threat analysis report
              including static analysis, dynamic behavior, MITRE ATT&CK
              mapping, IOCs, and risk assessment.
            </p>
          )
        )}

        {/* Hidden anchor for downloads */}
        <a ref={downloadRef} className="hidden" aria-hidden="true" />
      </CardContent>
    </Card>
  );
}
