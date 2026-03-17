"use client";

import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  useMitreMapping,
  type MITRETechnique,
} from "@/hooks/use-mitre-mapping";

// ATT&CK tactics in kill-chain order, with human-readable labels
const TACTICS: { key: string; label: string }[] = [
  { key: "reconnaissance", label: "Reconnaissance" },
  { key: "resource-development", label: "Resource Development" },
  { key: "initial-access", label: "Initial Access" },
  { key: "execution", label: "Execution" },
  { key: "persistence", label: "Persistence" },
  { key: "privilege-escalation", label: "Privilege Escalation" },
  { key: "defense-evasion", label: "Defense Evasion" },
  { key: "credential-access", label: "Credential Access" },
  { key: "discovery", label: "Discovery" },
  { key: "lateral-movement", label: "Lateral Movement" },
  { key: "collection", label: "Collection" },
  { key: "command-and-control", label: "Command and Control" },
  { key: "exfiltration", label: "Exfiltration" },
  { key: "impact", label: "Impact" },
];

// Static mapping from technique IDs to their tactic(s) for the matrix view.
// In a real deployment this would come from the ATT&CK data API, but for the
// matrix we use the tactics_coverage from the API response plus a simple
// lookup helper.
function getTacticForTechnique(tech: MITRETechnique): string {
  // Common technique -> tactic mapping for well-known IDs
  const mapping: Record<string, string> = {
    "T1595": "reconnaissance",
    "T1592": "reconnaissance",
    "T1589": "reconnaissance",
    "T1583": "resource-development",
    "T1584": "resource-development",
    "T1587": "resource-development",
    "T1190": "initial-access",
    "T1566": "initial-access",
    "T1059": "execution",
    "T1059.001": "execution",
    "T1059.004": "execution",
    "T1059.006": "execution",
    "T1053": "persistence",
    "T1053.003": "persistence",
    "T1543": "persistence",
    "T1543.002": "persistence",
    "T1547": "persistence",
    "T1547.006": "persistence",
    "T1136": "persistence",
    "T1136.001": "persistence",
    "T1222": "privilege-escalation",
    "T1222.002": "privilege-escalation",
    "T1068": "privilege-escalation",
    "T1027": "defense-evasion",
    "T1070": "defense-evasion",
    "T1070.004": "defense-evasion",
    "T1562": "defense-evasion",
    "T1562.001": "defense-evasion",
    "T1497": "defense-evasion",
    "T1003": "credential-access",
    "T1110": "credential-access",
    "T1082": "discovery",
    "T1083": "discovery",
    "T1057": "discovery",
    "T1049": "discovery",
    "T1046": "discovery",
    "T1005": "collection",
    "T1071": "command-and-control",
    "T1071.001": "command-and-control",
    "T1071.004": "command-and-control",
    "T1105": "command-and-control",
    "T1041": "exfiltration",
    "T1048": "exfiltration",
    "T1485": "impact",
    "T1486": "impact",
    "T1498": "impact",
  };
  return mapping[tech.technique_id] || "";
}

function ConfidenceBadge({ confidence }: { confidence: number }) {
  if (confidence > 0.8) {
    return (
      <Badge className="bg-green-600/15 text-green-700 dark:bg-green-500/20 dark:text-green-400">
        High ({(confidence * 100).toFixed(0)}%)
      </Badge>
    );
  }
  if (confidence > 0.5) {
    return (
      <Badge className="bg-yellow-600/15 text-yellow-700 dark:bg-yellow-500/20 dark:text-yellow-400">
        Medium ({(confidence * 100).toFixed(0)}%)
      </Badge>
    );
  }
  return (
    <Badge className="bg-red-600/15 text-red-700 dark:bg-red-500/20 dark:text-red-400">
      Low ({(confidence * 100).toFixed(0)}%)
    </Badge>
  );
}

function SourceBadge({ source }: { source: string }) {
  if (source === "rule+ai") {
    return <Badge variant="outline">Rule + AI</Badge>;
  }
  if (source === "ai") {
    return <Badge variant="secondary">AI</Badge>;
  }
  return <Badge variant="outline">Rule</Badge>;
}

// ---------------------------------------------------------------------------
// Table View
// ---------------------------------------------------------------------------

function MitreTableView({ techniques }: { techniques: MITRETechnique[] }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Technique ID</TableHead>
          <TableHead>Name</TableHead>
          <TableHead>Tactic</TableHead>
          <TableHead>Confidence</TableHead>
          <TableHead className="max-w-[300px]">Evidence</TableHead>
          <TableHead>Source</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {techniques.map((tech) => {
          const tacticKey = getTacticForTechnique(tech);
          const tactic = TACTICS.find((t) => t.key === tacticKey);
          const mitreUrl = `https://attack.mitre.org/techniques/${tech.technique_id.replace(".", "/")}/`;

          return (
            <TableRow key={tech.technique_id}>
              <TableCell>
                <a
                  href={mitreUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-blue-600 hover:underline dark:text-blue-400"
                >
                  {tech.technique_id}
                </a>
              </TableCell>
              <TableCell className="font-medium">{tech.name}</TableCell>
              <TableCell>
                {tactic ? (
                  <span className="text-xs text-muted-foreground">
                    {tactic.label}
                  </span>
                ) : (
                  <span className="text-xs text-muted-foreground">--</span>
                )}
              </TableCell>
              <TableCell>
                <ConfidenceBadge confidence={tech.confidence} />
              </TableCell>
              <TableCell className="max-w-[300px] truncate text-xs text-muted-foreground">
                {tech.evidence || "--"}
              </TableCell>
              <TableCell>
                <SourceBadge source={tech.source} />
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

// ---------------------------------------------------------------------------
// Matrix View
// ---------------------------------------------------------------------------

function MitreMatrixView({ techniques }: { techniques: MITRETechnique[] }) {
  const [hoveredTech, setHoveredTech] = useState<MITRETechnique | null>(null);

  // Group techniques by tactic
  const byTactic: Record<string, MITRETechnique[]> = {};
  for (const tactic of TACTICS) {
    byTactic[tactic.key] = [];
  }
  for (const tech of techniques) {
    const tacticKey = getTacticForTechnique(tech);
    if (tacticKey && byTactic[tacticKey]) {
      byTactic[tacticKey].push(tech);
    }
  }

  return (
    <div className="space-y-3">
      <div className="overflow-x-auto">
        <div className="inline-flex min-w-full gap-1">
          {TACTICS.map((tactic) => {
            const techs = byTactic[tactic.key] || [];
            return (
              <div key={tactic.key} className="flex min-w-[120px] flex-col">
                <div className="mb-1 rounded-t-md bg-muted px-2 py-1.5 text-center text-[10px] font-semibold leading-tight">
                  {tactic.label}
                </div>
                <div className="flex flex-1 flex-col gap-0.5">
                  {techs.length === 0 ? (
                    <div className="flex-1 rounded-b-md border border-dashed border-muted-foreground/20 p-1" />
                  ) : (
                    techs.map((tech) => {
                      const bgClass =
                        tech.confidence > 0.8
                          ? "bg-green-600/20 border-green-600/30 hover:bg-green-600/30"
                          : tech.confidence > 0.5
                            ? "bg-yellow-600/20 border-yellow-600/30 hover:bg-yellow-600/30"
                            : "bg-red-600/20 border-red-600/30 hover:bg-red-600/30";
                      return (
                        <div
                          key={tech.technique_id}
                          className={`cursor-pointer rounded border px-1.5 py-1 text-[10px] leading-tight transition-colors ${bgClass}`}
                          onMouseEnter={() => setHoveredTech(tech)}
                          onMouseLeave={() => setHoveredTech(null)}
                        >
                          <div className="font-mono font-medium">
                            {tech.technique_id}
                          </div>
                          <div className="truncate text-muted-foreground">
                            {tech.name}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Hover detail panel */}
      {hoveredTech && (
        <div className="rounded-md border bg-muted/50 p-3 text-sm">
          <div className="flex items-center gap-2">
            <span className="font-mono font-semibold">
              {hoveredTech.technique_id}
            </span>
            <span className="font-medium">{hoveredTech.name}</span>
            <ConfidenceBadge confidence={hoveredTech.confidence} />
            <SourceBadge source={hoveredTech.source} />
          </div>
          {hoveredTech.evidence && (
            <p className="mt-1 text-xs text-muted-foreground">
              {hoveredTech.evidence}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Card
// ---------------------------------------------------------------------------

interface MitreAttackCardProps {
  submissionId: string;
  analysisId: string | null;
}

export function MitreAttackCard({
  submissionId,
  analysisId,
}: MitreAttackCardProps) {
  const { data, loading, error, runMapping } = useMitreMapping(
    submissionId,
    analysisId,
  );
  const [view, setView] = useState<"table" | "matrix">("table");

  const techniques = data?.techniques ?? [];
  const hasTechniques = techniques.length > 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>MITRE ATT&CK Mapping</CardTitle>
        <div className="flex items-center gap-2">
          {hasTechniques && (
            <div className="flex rounded-md border">
              <Button
                variant={view === "table" ? "secondary" : "ghost"}
                size="xs"
                onClick={() => setView("table")}
              >
                Table
              </Button>
              <Button
                variant={view === "matrix" ? "secondary" : "ghost"}
                size="xs"
                onClick={() => setView("matrix")}
              >
                Matrix
              </Button>
            </div>
          )}
          <Button
            size="sm"
            variant="outline"
            disabled={loading || !analysisId}
            onClick={() => runMapping(false)}
          >
            {loading ? "Mapping..." : "Run MITRE Mapping"}
          </Button>
          <Button
            size="sm"
            disabled={loading || !analysisId}
            onClick={() => runMapping(true)}
          >
            {loading ? "Mapping..." : "Run with AI"}
          </Button>
        </div>
      </CardHeader>

      <CardContent>
        {error && (
          <div className="mb-3 rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/50 dark:text-red-400">
            {error}
          </div>
        )}

        {loading && !hasTechniques && (
          <div className="flex items-center justify-center py-8 text-sm text-muted-foreground">
            Running MITRE ATT&CK mapping...
          </div>
        )}

        {!loading && !hasTechniques && !error && (
          <div className="flex flex-col items-center justify-center gap-2 py-8 text-sm text-muted-foreground">
            <p>No MITRE ATT&CK techniques mapped yet.</p>
            <p className="text-xs">
              Click &quot;Run MITRE Mapping&quot; to analyze behavioral
              indicators.
            </p>
          </div>
        )}

        {hasTechniques && (
          <>
            <div className="mb-3 flex items-center gap-4 text-xs text-muted-foreground">
              <span>
                {techniques.length} technique{techniques.length !== 1 && "s"}{" "}
                detected
              </span>
              {data?.tactics_coverage && (
                <span>
                  {Object.keys(data.tactics_coverage).length} tactic
                  {Object.keys(data.tactics_coverage).length !== 1 && "s"}{" "}
                  covered
                </span>
              )}
            </div>

            {view === "table" ? (
              <MitreTableView techniques={techniques} />
            ) : (
              <MitreMatrixView techniques={techniques} />
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
