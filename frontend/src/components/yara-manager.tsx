"use client";

import { useCallback, useState } from "react";

import { useYaraRules } from "@/hooks/use-yara-rules";
import type { YaraRuleFile } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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

function formatDate(ts: number): string {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString();
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB"];
  const i = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1
  );
  const val = bytes / Math.pow(1024, i);
  return `${val.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/* -------------------------------------------------------------------------- */
/*  Editor panel                                                               */
/* -------------------------------------------------------------------------- */

function RuleEditor({
  filename,
  initialContent,
  isNew,
  onSave,
  onCancel,
  onValidate,
}: {
  filename: string;
  initialContent: string;
  isNew: boolean;
  onSave: (content: string) => Promise<boolean>;
  onCancel: () => void;
  onValidate: (content: string) => Promise<{ valid: boolean; error: string | null }>;
}) {
  const [content, setContent] = useState(initialContent);
  const [saving, setSaving] = useState(false);
  const [validating, setValidating] = useState(false);
  const [validation, setValidation] = useState<{
    valid: boolean;
    error: string | null;
  } | null>(null);

  const handleValidate = useCallback(async () => {
    setValidating(true);
    const result = await onValidate(content);
    setValidation(result);
    setValidating(false);
  }, [content, onValidate]);

  const handleSave = useCallback(async () => {
    setSaving(true);
    const ok = await onSave(content);
    setSaving(false);
    if (ok) {
      onCancel();
    }
  }, [content, onSave, onCancel]);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium font-mono">{filename}</p>
        <div className="flex items-center gap-2">
          {validation !== null && (
            validation.valid ? (
              <Badge variant="outline" className="text-xs text-green-600 border-green-300">
                Valid
              </Badge>
            ) : (
              <Badge variant="destructive" className="text-xs">
                Invalid
              </Badge>
            )
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={handleValidate}
            disabled={validating || !content.trim()}
          >
            {validating ? "Checking..." : "Validate"}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={onCancel}
          >
            Cancel
          </Button>
          <Button
            size="sm"
            onClick={handleSave}
            disabled={saving || !content.trim()}
          >
            {saving ? "Saving..." : isNew ? "Create" : "Save"}
          </Button>
        </div>
      </div>

      {validation && validation.error && (
        <div className="rounded border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-950 p-2">
          <p className="text-xs text-red-700 dark:text-red-400 font-mono break-all">
            {validation.error}
          </p>
        </div>
      )}

      <textarea
        className="w-full min-h-[300px] rounded border bg-muted p-3 font-mono text-xs leading-relaxed resize-y focus:outline-none focus:ring-2 focus:ring-ring"
        value={content}
        onChange={(e) => {
          setContent(e.target.value);
          setValidation(null);
        }}
        spellCheck={false}
        placeholder="rule example_rule {&#10;    meta:&#10;        description = &quot;Example YARA rule&quot;&#10;    strings:&#10;        $s1 = &quot;malware&quot;&#10;    condition:&#10;        $s1&#10;}"
      />
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Delete confirmation                                                        */
/* -------------------------------------------------------------------------- */

function DeleteConfirm({
  filename,
  onConfirm,
  onCancel,
}: {
  filename: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="flex items-center gap-3 rounded border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-950 p-3">
      <p className="text-sm flex-1">
        Delete <span className="font-mono font-medium">{filename}</span>?
        This cannot be undone.
      </p>
      <Button variant="outline" size="sm" onClick={onCancel}>
        Cancel
      </Button>
      <Button
        size="sm"
        className="bg-red-600 text-white hover:bg-red-700"
        onClick={onConfirm}
      >
        Delete
      </Button>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  New rule form                                                              */
/* -------------------------------------------------------------------------- */

function NewRuleForm({
  onSave,
  onCancel,
  onValidate,
}: {
  onSave: (filename: string, content: string) => Promise<boolean>;
  onCancel: () => void;
  onValidate: (content: string) => Promise<{ valid: boolean; error: string | null }>;
}) {
  const [filename, setFilename] = useState("");

  const handleSave = useCallback(
    async (content: string) => {
      const name = filename.endsWith(".yar") ? filename : `${filename}.yar`;
      return onSave(name, content);
    },
    [filename, onSave]
  );

  return (
    <div className="space-y-3">
      <div>
        <Label htmlFor="new-rule-filename">Filename</Label>
        <Input
          id="new-rule-filename"
          value={filename}
          onChange={(e) => setFilename(e.target.value)}
          placeholder="my_rules.yar"
          className="mt-1 font-mono"
        />
        <p className="text-xs text-muted-foreground mt-1">
          Must contain only letters, numbers, hyphens, and underscores
        </p>
      </div>

      <RuleEditor
        filename={filename || "new_rule.yar"}
        initialContent=""
        isNew
        onSave={handleSave}
        onCancel={onCancel}
        onValidate={onValidate}
      />
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Main card                                                                  */
/* -------------------------------------------------------------------------- */

export function YaraManager() {
  const {
    rules,
    loading,
    error,
    refresh,
    getRuleContent,
    uploadRule,
    updateRule,
    deleteRule,
    validateRule,
  } = useYaraRules();

  const [mode, setMode] = useState<
    | { type: "list" }
    | { type: "view"; filename: string; content: string }
    | { type: "new" }
  >({ type: "list" });

  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  const handleView = useCallback(
    async (filename: string) => {
      setActionLoading(true);
      const result = await getRuleContent(filename);
      setActionLoading(false);
      if (result) {
        setMode({ type: "view", filename: result.filename, content: result.content });
      }
    },
    [getRuleContent]
  );

  const handleDelete = useCallback(
    async (filename: string) => {
      setActionLoading(true);
      await deleteRule(filename);
      setActionLoading(false);
      setDeleteTarget(null);
      if (mode.type === "view" && mode.filename === filename) {
        setMode({ type: "list" });
      }
    },
    [deleteRule, mode]
  );

  const handleUpload = useCallback(
    async (filename: string, content: string) => {
      return uploadRule(filename, content);
    },
    [uploadRule]
  );

  const handleUpdate = useCallback(
    async (content: string) => {
      if (mode.type !== "view") return false;
      return updateRule(mode.filename, content);
    },
    [updateRule, mode]
  );

  const totalRules = rules.reduce((acc, r) => acc + r.rule_count, 0);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <CardTitle className="text-base">YARA Rules</CardTitle>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <span>
                {rules.length} file{rules.length !== 1 ? "s" : ""}
              </span>
              <span>/</span>
              <span>
                {totalRules} rule{totalRules !== 1 ? "s" : ""}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {mode.type !== "list" && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setMode({ type: "list" })}
              >
                Back to List
              </Button>
            )}
            {mode.type === "list" && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={refresh}
                  disabled={loading}
                >
                  {loading ? "Loading..." : "Refresh"}
                </Button>
                <Button
                  size="sm"
                  onClick={() => setMode({ type: "new" })}
                >
                  Add Rule
                </Button>
              </>
            )}
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Loading */}
        {loading && rules.length === 0 && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Spinner />
            <span>Loading YARA rules...</span>
          </div>
        )}

        {/* Error */}
        {error && (
          <p className="text-sm text-destructive">{error}</p>
        )}

        {/* Delete confirmation */}
        {deleteTarget && (
          <DeleteConfirm
            filename={deleteTarget}
            onConfirm={() => handleDelete(deleteTarget)}
            onCancel={() => setDeleteTarget(null)}
          />
        )}

        {/* List mode */}
        {mode.type === "list" && (
          <>
            {rules.length === 0 && !loading && (
              <p className="text-sm text-muted-foreground">
                No YARA rule files found. Click "Add Rule" to create one.
              </p>
            )}

            {rules.length > 0 && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Filename</TableHead>
                    <TableHead>Rules</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead>Last Modified</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rules.map((rule: YaraRuleFile) => (
                    <TableRow key={rule.filename}>
                      <TableCell className="font-mono text-xs font-medium">
                        {rule.filename}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-xs">
                          {rule.rule_count}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {formatBytes(rule.size_bytes)}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {formatDate(rule.last_modified)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleView(rule.filename)}
                            disabled={actionLoading}
                          >
                            {actionLoading ? "..." : "View"}
                          </Button>
                          {rule.filename !== "index.yar" && (
                            <Button
                              variant="outline"
                              size="sm"
                              className="text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-950"
                              onClick={() => setDeleteTarget(rule.filename)}
                              disabled={actionLoading}
                            >
                              Delete
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </>
        )}

        {/* View / Edit mode */}
        {mode.type === "view" && (
          <RuleEditor
            filename={mode.filename}
            initialContent={mode.content}
            isNew={false}
            onSave={handleUpdate}
            onCancel={() => setMode({ type: "list" })}
            onValidate={validateRule}
          />
        )}

        {/* New rule mode */}
        {mode.type === "new" && (
          <NewRuleForm
            onSave={handleUpload}
            onCancel={() => setMode({ type: "list" })}
            onValidate={validateRule}
          />
        )}
      </CardContent>
    </Card>
  );
}
