"use client";

import { useMemo, useState } from "react";

import { useStaticAnalysis } from "@/hooks/use-static-analysis";
import type {
  StaticAnalysisResponse,
  PEAnalysis,
  PESection,
  PEExport,
  ELFAnalysis,
  InterestingStrings,
} from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function Spinner() {
  return (
    <svg
      className="animate-spin h-4 w-4 text-muted-foreground"
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
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
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  );
}

function entropyColor(value: number): string {
  if (value < 4) return "bg-green-500";
  if (value < 6) return "bg-yellow-500";
  return "bg-red-500";
}

function entropyLabel(value: number): string {
  if (value < 4) return "Low";
  if (value < 6) return "Medium";
  if (value < 7) return "High";
  return "Very High (likely packed/encrypted)";
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const val = bytes / Math.pow(1024, i);
  return `${val.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/* -------------------------------------------------------------------------- */
/*  Tab type                                                                   */
/* -------------------------------------------------------------------------- */

type TabId = "overview" | "pe" | "elf" | "strings";

/* -------------------------------------------------------------------------- */
/*  Overview tab                                                               */
/* -------------------------------------------------------------------------- */

function OverviewTab({ data }: { data: StaticAnalysisResponse }) {
  const entropy = data.entropy.overall;
  const pct = Math.min((entropy / 8) * 100, 100);

  return (
    <div className="space-y-4">
      {/* Entropy */}
      <div>
        <div className="flex items-center justify-between text-sm mb-1">
          <span className="font-medium">Shannon Entropy</span>
          <span className="font-mono">
            {entropy.toFixed(4)} / 8.0 - {entropyLabel(entropy)}
          </span>
        </div>
        <div className="h-3 w-full rounded-full bg-muted overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${entropyColor(entropy)}`}
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      {/* File info */}
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <span className="text-muted-foreground">File Size</span>
          <p className="font-medium">{formatBytes(data.file_size)}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Filename</span>
          <p className="font-medium font-mono text-xs break-all">
            {data.filename || "N/A"}
          </p>
        </div>
        <div>
          <span className="text-muted-foreground">File Format</span>
          <p className="font-medium">
            {data.pe ? "PE (Windows)" : data.elf ? "ELF (Linux)" : "Unknown"}
          </p>
        </div>
        <div>
          <span className="text-muted-foreground">Strings Found</span>
          <p className="font-medium">
            {data.strings.total_ascii} ASCII, {data.strings.total_wide} Wide
          </p>
        </div>
      </div>

      {/* Section entropy table (PE) */}
      {data.entropy.sections &&
        Object.keys(data.entropy.sections).length > 0 && (
          <div>
            <p className="text-sm font-medium mb-2">Section Entropy</p>
            <div className="space-y-1.5">
              {Object.entries(data.entropy.sections).map(([name, val]) => {
                const secPct = Math.min((val / 8) * 100, 100);
                return (
                  <div key={name} className="flex items-center gap-2">
                    <span className="text-xs font-mono w-20 shrink-0 text-right">
                      {name}
                    </span>
                    <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                      <div
                        className={`h-full rounded-full ${entropyColor(val)}`}
                        style={{ width: `${secPct}%` }}
                      />
                    </div>
                    <span className="text-xs font-mono w-12 text-right">
                      {val.toFixed(2)}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

      {/* Quick IOC summary */}
      {data.strings.interesting && (
        <IOCSummary interesting={data.strings.interesting} />
      )}
    </div>
  );
}

function IOCSummary({ interesting }: { interesting: InterestingStrings }) {
  const counts = [
    { label: "URLs", count: interesting.urls?.length ?? 0 },
    { label: "IPs", count: interesting.ips?.length ?? 0 },
    { label: "Emails", count: interesting.emails?.length ?? 0 },
    {
      label: "Registry Keys",
      count: interesting.registry_keys?.length ?? 0,
    },
    {
      label: "File Paths",
      count: interesting.file_paths?.length ?? 0,
    },
  ].filter((c) => c.count > 0);

  if (counts.length === 0) return null;

  return (
    <div>
      <p className="text-sm font-medium mb-2">Indicators of Compromise</p>
      <div className="flex flex-wrap gap-2">
        {counts.map((c) => (
          <Badge key={c.label} variant="secondary">
            {c.label}: {c.count}
          </Badge>
        ))}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  PE Analysis tab                                                            */
/* -------------------------------------------------------------------------- */

function PETab({ pe }: { pe: PEAnalysis }) {
  const [showAllImports, setShowAllImports] = useState(false);
  const importEntries = Object.entries(pe.imports || {});
  const displayedImports = showAllImports
    ? importEntries
    : importEntries.slice(0, 10);

  return (
    <div className="space-y-4">
      {/* Header info */}
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <span className="text-muted-foreground">Machine</span>
          <p className="font-mono font-medium">{pe.machine}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Type</span>
          <p className="font-medium">
            {pe.is_dll ? "DLL" : pe.is_exe ? "EXE" : "Unknown"}
          </p>
        </div>
        <div>
          <span className="text-muted-foreground">Entry Point</span>
          <p className="font-mono font-medium">{pe.entry_point ?? "N/A"}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Linker Version</span>
          <p className="font-medium">{pe.linker_version ?? "N/A"}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Signature</span>
          <Badge variant={pe.has_signature ? "outline" : "destructive"}>
            {pe.has_signature ? "Signed" : "Not Signed"}
          </Badge>
        </div>
        <div>
          <span className="text-muted-foreground">Total Imports</span>
          <p className="font-medium">{pe.import_count}</p>
        </div>
      </div>

      {/* Suspicious indicators */}
      {pe.suspicious_indicators && pe.suspicious_indicators.length > 0 && (
        <div>
          <p className="text-sm font-medium mb-2">Suspicious Indicators</p>
          <div className="flex flex-wrap gap-1.5">
            {pe.suspicious_indicators.map((indicator, i) => (
              <Badge key={i} variant="destructive">
                {indicator}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {/* Sections table */}
      {pe.sections && pe.sections.length > 0 && (
        <div>
          <p className="text-sm font-medium mb-2">Sections</p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Virtual Size</TableHead>
                <TableHead>Raw Size</TableHead>
                <TableHead>Entropy</TableHead>
                <TableHead>Flags</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pe.sections.map((section: PESection) => (
                <TableRow key={section.name}>
                  <TableCell className="font-mono text-xs">
                    {section.name}
                  </TableCell>
                  <TableCell className="text-xs">
                    {formatBytes(section.virtual_size)}
                  </TableCell>
                  <TableCell className="text-xs">
                    {formatBytes(section.raw_size)}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 rounded-full bg-muted overflow-hidden">
                        <div
                          className={`h-full rounded-full ${entropyColor(section.entropy)}`}
                          style={{
                            width: `${Math.min((section.entropy / 8) * 100, 100)}%`,
                          }}
                        />
                      </div>
                      <span className="text-xs font-mono">
                        {section.entropy.toFixed(2)}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {section.characteristics}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Imports table */}
      {importEntries.length > 0 && (
        <div>
          <p className="text-sm font-medium mb-2">
            Imports ({importEntries.length} DLLs, {pe.import_count} functions)
          </p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>DLL</TableHead>
                <TableHead>Functions</TableHead>
                <TableHead>Count</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {displayedImports.map(([dll, funcs]) => (
                <TableRow key={dll}>
                  <TableCell className="font-mono text-xs">{dll}</TableCell>
                  <TableCell className="text-xs max-w-xs truncate">
                    {funcs.slice(0, 5).join(", ")}
                    {funcs.length > 5 && ` ... +${funcs.length - 5} more`}
                  </TableCell>
                  <TableCell className="text-xs">{funcs.length}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {importEntries.length > 10 && (
            <Button
              variant="ghost"
              size="sm"
              className="mt-1"
              onClick={() => setShowAllImports(!showAllImports)}
            >
              {showAllImports
                ? "Show less"
                : `Show all ${importEntries.length} DLLs`}
            </Button>
          )}
        </div>
      )}

      {/* Exports table */}
      {pe.exports && pe.exports.length > 0 && (
        <div>
          <p className="text-sm font-medium mb-2">
            Exports ({pe.exports.length})
          </p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Ordinal</TableHead>
                <TableHead>Address</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pe.exports.slice(0, 50).map((exp: PEExport) => (
                <TableRow key={exp.ordinal}>
                  <TableCell className="font-mono text-xs">
                    {exp.name}
                  </TableCell>
                  <TableCell className="text-xs">{exp.ordinal}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {exp.address}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {pe.exports.length > 50 && (
            <p className="text-xs text-muted-foreground mt-1">
              Showing first 50 of {pe.exports.length} exports
            </p>
          )}
        </div>
      )}

      {/* Resources */}
      {pe.resources && pe.resources.length > 0 && (
        <div>
          <p className="text-sm font-medium mb-2">
            Resources ({pe.resources.length})
          </p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Type</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>Offset</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pe.resources.slice(0, 20).map((res, i) => (
                <TableRow key={i}>
                  <TableCell className="font-mono text-xs">
                    {res.type}
                  </TableCell>
                  <TableCell className="text-xs">
                    {formatBytes(res.size)}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {`0x${res.offset.toString(16)}`}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  ELF Analysis tab                                                           */
/* -------------------------------------------------------------------------- */

function ELFTab({ elf }: { elf: ELFAnalysis }) {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <span className="text-muted-foreground">Class</span>
          <p className="font-medium">{elf.class_}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Type</span>
          <p className="font-medium">{elf.type}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Machine</span>
          <p className="font-mono font-medium">{elf.machine}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Endianness</span>
          <p className="font-medium">{elf.endian}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Entry Point</span>
          <p className="font-mono font-medium">{elf.entry_point}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Program Headers</span>
          <p className="font-medium">{elf.program_headers}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Section Headers</span>
          <p className="font-medium">{elf.section_headers}</p>
        </div>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Strings tab                                                                */
/* -------------------------------------------------------------------------- */

function StringsTab({ data }: { data: StaticAnalysisResponse }) {
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState<string>("all");

  const interesting = data.strings.interesting;
  const categories = [
    { id: "all", label: "All Strings" },
    { id: "urls", label: `URLs (${interesting?.urls?.length ?? 0})` },
    { id: "ips", label: `IPs (${interesting?.ips?.length ?? 0})` },
    { id: "emails", label: `Emails (${interesting?.emails?.length ?? 0})` },
    {
      id: "registry_keys",
      label: `Registry (${interesting?.registry_keys?.length ?? 0})`,
    },
    {
      id: "file_paths",
      label: `Paths (${interesting?.file_paths?.length ?? 0})`,
    },
  ];

  const filteredStrings = useMemo(() => {
    let strings: string[];

    if (category === "all") {
      strings = [
        ...(data.strings.ascii_strings || []),
        ...(data.strings.wide_strings || []),
      ];
    } else {
      const interestingMap = interesting as unknown as Record<string, string[]>;
      strings = interestingMap?.[category] ?? [];
    }

    if (search) {
      const searchLower = search.toLowerCase();
      strings = strings.filter((s) => s.toLowerCase().includes(searchLower));
    }

    return strings;
  }, [data.strings, interesting, category, search]);

  const [displayCount, setDisplayCount] = useState(100);
  const displayed = filteredStrings.slice(0, displayCount);

  return (
    <div className="space-y-3">
      {/* Stats */}
      <div className="flex items-center gap-4 text-sm">
        <span className="text-muted-foreground">
          {data.strings.total_ascii} ASCII strings
        </span>
        <span className="text-muted-foreground">
          {data.strings.total_wide} Wide strings
        </span>
      </div>

      {/* Category filter */}
      <div className="flex flex-wrap gap-1.5">
        {categories.map((cat) => (
          <Button
            key={cat.id}
            variant={category === cat.id ? "default" : "outline"}
            size="sm"
            onClick={() => {
              setCategory(cat.id);
              setDisplayCount(100);
            }}
          >
            {cat.label}
          </Button>
        ))}
      </div>

      {/* Search input */}
      <Input
        type="text"
        placeholder="Search strings..."
        value={search}
        onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
          setSearch(e.target.value);
          setDisplayCount(100);
        }}
      />

      {/* Results count */}
      <p className="text-xs text-muted-foreground">
        {filteredStrings.length} result{filteredStrings.length !== 1 ? "s" : ""}
        {search && " matching filter"}
      </p>

      {/* String list */}
      <div className="max-h-96 overflow-y-auto rounded border">
        {displayed.length === 0 ? (
          <p className="p-4 text-sm text-muted-foreground text-center">
            No strings found
          </p>
        ) : (
          <div className="divide-y">
            {displayed.map((str, i) => (
              <div
                key={i}
                className="px-3 py-1.5 text-xs font-mono break-all hover:bg-muted/50"
              >
                {str}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Load more */}
      {filteredStrings.length > displayCount && (
        <Button
          variant="outline"
          size="sm"
          className="w-full"
          onClick={() => setDisplayCount((c) => c + 100)}
        >
          Show more ({filteredStrings.length - displayCount} remaining)
        </Button>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Main card                                                                  */
/* -------------------------------------------------------------------------- */

export function StaticAnalysisCard({
  submissionId,
}: {
  submissionId: string;
}) {
  const { data, loading, error, refresh } = useStaticAnalysis(submissionId);
  const [activeTab, setActiveTab] = useState<TabId>("overview");

  // Determine available tabs based on data
  const tabs = useMemo(() => {
    const available: { id: TabId; label: string }[] = [
      { id: "overview", label: "Overview" },
    ];
    if (data?.pe) {
      available.push({ id: "pe", label: "PE Analysis" });
    }
    if (data?.elf) {
      available.push({ id: "elf", label: "ELF Analysis" });
    }
    available.push({ id: "strings", label: "Strings" });
    return available;
  }, [data]);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">Static Analysis</CardTitle>
          <Button
            variant="outline"
            size="sm"
            onClick={refresh}
            disabled={loading}
          >
            {loading ? "Analyzing..." : "Refresh"}
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Loading */}
        {loading && !data && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Spinner />
            <span>Running static analysis...</span>
          </div>
        )}

        {/* Error */}
        {error && !loading && (
          <p className="text-sm text-destructive">{error}</p>
        )}

        {/* Content */}
        {data && (
          <>
            {/* Tab bar */}
            <div className="flex gap-1 border-b pb-px">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-3 py-1.5 text-sm rounded-t transition-colors ${
                    activeTab === tab.id
                      ? "bg-muted font-medium text-foreground"
                      : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab content */}
            {activeTab === "overview" && <OverviewTab data={data} />}
            {activeTab === "pe" && data.pe && <PETab pe={data.pe} />}
            {activeTab === "elf" && data.elf && <ELFTab elf={data.elf} />}
            {activeTab === "strings" && <StringsTab data={data} />}
          </>
        )}
      </CardContent>
    </Card>
  );
}
