"use client";

import { useCallback, useState } from "react";

import { useIOCExport } from "@/hooks/use-ioc-export";
import type { IOCEntry } from "@/hooks/use-ioc-export";
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

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Fallback for insecure contexts
      const textarea = document.createElement("textarea");
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  }, [text]);

  return (
    <Button
      variant="ghost"
      size="xs"
      onClick={handleCopy}
      className="h-5 px-1.5 text-[10px]"
    >
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

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

function IOCCountBadge({ count, label }: { count: number; label: string }) {
  if (count === 0) return null;
  return (
    <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
      {count} {label}
    </Badge>
  );
}

/* -------------------------------------------------------------------------- */
/*  IOC Table Section                                                          */
/* -------------------------------------------------------------------------- */

function IOCTableSection({
  title,
  entries,
  columns,
}: {
  title: string;
  entries: IOCEntry[];
  columns: { key: string; label: string }[];
}) {
  const [expanded, setExpanded] = useState(false);
  if (entries.length === 0) return null;

  const visible = expanded ? entries : entries.slice(0, 10);
  const hasMore = entries.length > 10;

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <p className="text-sm font-medium">{title}</p>
        <Badge variant="outline" className="text-[10px] px-1.5 py-0">
          {entries.length}
        </Badge>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            {columns.map((col) => (
              <TableHead key={col.key} className="text-xs">
                {col.label}
              </TableHead>
            ))}
            <TableHead className="text-xs w-14">Action</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {visible.map((entry, idx) => (
            <TableRow key={`${entry.value}-${idx}`}>
              {columns.map((col) => (
                <TableCell key={col.key} className="text-xs font-mono">
                  {col.key === "value"
                    ? entry.value
                    : col.key === "port"
                      ? entry.port ?? "-"
                      : col.key === "source"
                        ? entry.source ?? "-"
                        : col.key === "type"
                          ? entry.type ?? "-"
                          : col.key === "size"
                            ? entry.size != null
                              ? `${entry.size} B`
                              : "-"
                            : "-"}
                </TableCell>
              ))}
              <TableCell>
                <CopyButton text={entry.value} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {hasMore && (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setExpanded(!expanded)}
          className="mt-1 text-xs"
        >
          {expanded ? "Show less" : `Show all ${entries.length}`}
        </Button>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Main Card                                                                  */
/* -------------------------------------------------------------------------- */

export function IOCExportCard({
  submissionId,
}: {
  submissionId: string;
}) {
  const {
    iocs,
    loading,
    error,
    refresh,
    exportCSV,
    exportSTIX,
    exportJSON,
  } = useIOCExport(submissionId);

  const totalIOCs = iocs
    ? (iocs.hashes.sha256 ? 1 : 0) +
      (iocs.hashes.md5 ? 1 : 0) +
      (iocs.hashes.sha1 ? 1 : 0) +
      iocs.ips.length +
      iocs.domains.length +
      iocs.urls.length +
      iocs.file_paths.length +
      iocs.registry_keys.length +
      iocs.mutexes.length
    : 0;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <CardTitle className="text-base">
              Indicators of Compromise
            </CardTitle>
            {iocs && (
              <div className="flex items-center gap-1.5">
                <IOCCountBadge
                  count={Object.values(iocs.hashes).filter(Boolean).length}
                  label="hashes"
                />
                <IOCCountBadge count={iocs.ips.length} label="IPs" />
                <IOCCountBadge count={iocs.domains.length} label="domains" />
                <IOCCountBadge count={iocs.urls.length} label="URLs" />
                <IOCCountBadge count={iocs.file_paths.length} label="files" />
              </div>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <Button
              variant="outline"
              size="sm"
              onClick={refresh}
              disabled={loading}
            >
              {loading ? "Loading..." : "Refresh"}
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-5">
        {/* Loading */}
        {loading && !iocs && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Spinner />
            <span>Extracting IOCs...</span>
          </div>
        )}

        {/* Error */}
        {error && !loading && (
          <p className="text-sm text-destructive">{error}</p>
        )}

        {/* Empty state */}
        {!loading && !error && iocs && totalIOCs === 0 && (
          <p className="text-sm text-muted-foreground">
            No indicators of compromise found. Run a dynamic analysis to
            extract network IOCs, file system artifacts, and more.
          </p>
        )}

        {/* Hash section */}
        {iocs && Object.values(iocs.hashes).some(Boolean) && (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <p className="text-sm font-medium">File Hashes</p>
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs w-16">Type</TableHead>
                  <TableHead className="text-xs">Value</TableHead>
                  <TableHead className="text-xs w-14">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {iocs.hashes.sha256 && (
                  <TableRow>
                    <TableCell className="text-xs font-medium">
                      SHA-256
                    </TableCell>
                    <TableCell className="text-xs font-mono break-all">
                      {iocs.hashes.sha256}
                    </TableCell>
                    <TableCell>
                      <CopyButton text={iocs.hashes.sha256} />
                    </TableCell>
                  </TableRow>
                )}
                {iocs.hashes.md5 && (
                  <TableRow>
                    <TableCell className="text-xs font-medium">MD5</TableCell>
                    <TableCell className="text-xs font-mono break-all">
                      {iocs.hashes.md5}
                    </TableCell>
                    <TableCell>
                      <CopyButton text={iocs.hashes.md5} />
                    </TableCell>
                  </TableRow>
                )}
                {iocs.hashes.sha1 && (
                  <TableRow>
                    <TableCell className="text-xs font-medium">
                      SHA-1
                    </TableCell>
                    <TableCell className="text-xs font-mono break-all">
                      {iocs.hashes.sha1}
                    </TableCell>
                    <TableCell>
                      <CopyButton text={iocs.hashes.sha1} />
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        )}

        {/* IP addresses */}
        {iocs && (
          <IOCTableSection
            title="IP Addresses"
            entries={iocs.ips}
            columns={[
              { key: "value", label: "Address" },
              { key: "port", label: "Port" },
              { key: "source", label: "Source" },
            ]}
          />
        )}

        {/* Domains */}
        {iocs && (
          <IOCTableSection
            title="Domains"
            entries={iocs.domains}
            columns={[
              { key: "value", label: "Domain" },
              { key: "type", label: "Type" },
              { key: "source", label: "Source" },
            ]}
          />
        )}

        {/* URLs */}
        {iocs && (
          <IOCTableSection
            title="URLs"
            entries={iocs.urls}
            columns={[
              { key: "value", label: "URL" },
              { key: "source", label: "Source" },
            ]}
          />
        )}

        {/* File paths */}
        {iocs && (
          <IOCTableSection
            title="File Paths"
            entries={iocs.file_paths}
            columns={[
              { key: "value", label: "Path" },
              { key: "size", label: "Size" },
            ]}
          />
        )}

        {/* Registry keys */}
        {iocs && iocs.registry_keys.length > 0 && (
          <IOCTableSection
            title="Registry Keys"
            entries={iocs.registry_keys}
            columns={[
              { key: "value", label: "Key" },
              { key: "source", label: "Source" },
            ]}
          />
        )}

        {/* Mutexes */}
        {iocs && iocs.mutexes.length > 0 && (
          <IOCTableSection
            title="Mutexes"
            entries={iocs.mutexes}
            columns={[
              { key: "value", label: "Name" },
              { key: "source", label: "Source" },
            ]}
          />
        )}

        {/* Export buttons */}
        {iocs && totalIOCs > 0 && (
          <div className="flex items-center gap-2 pt-2 border-t">
            <p className="text-xs text-muted-foreground mr-2">Export:</p>
            <Button variant="outline" size="sm" onClick={exportCSV}>
              CSV
            </Button>
            <Button variant="outline" size="sm" onClick={exportSTIX}>
              STIX 2.1
            </Button>
            <Button variant="outline" size="sm" onClick={exportJSON}>
              JSON
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
