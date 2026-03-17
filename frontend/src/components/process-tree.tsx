"use client";

import { useMemo, useState } from "react";

import {
  buildProcessTree,
  flattenTree,
  type ProcessEvent,
  type ProcessNode,
} from "@/lib/process-tree";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

function ProcessTreeNode({
  node,
  expandedPids,
  toggleExpand,
}: {
  node: ProcessNode;
  expandedPids: Set<number>;
  toggleExpand: (pid: number) => void;
}) {
  const hasChildren = node.children.length > 0;
  const isExpanded = expandedPids.has(node.pid);

  return (
    <>
      <TableRow
        className={node.suspicious ? "border-l-2 border-l-red-500" : ""}
      >
        <TableCell className="font-mono text-xs">
          <span style={{ paddingLeft: `${node.depth * 20}px` }} className="flex items-center gap-1">
            {hasChildren ? (
              <button
                onClick={() => toggleExpand(node.pid)}
                className="w-4 h-4 flex items-center justify-center text-muted-foreground hover:text-foreground shrink-0"
              >
                {isExpanded ? "\u25BE" : "\u25B8"}
              </button>
            ) : (
              <span className="w-4 h-4 shrink-0" />
            )}
            <span>{node.pid}</span>
          </span>
        </TableCell>
        <TableCell className="font-mono text-xs">
          {node.ppid != null ? node.ppid : "-"}
        </TableCell>
        <TableCell className="font-mono text-xs">
          <span className="flex items-center gap-1">
            {node.command}
            {node.suspicious && (
              <Badge variant="destructive" className="text-[10px] px-1 py-0">
                suspicious
              </Badge>
            )}
          </span>
        </TableCell>
        <TableCell className="font-mono text-xs max-w-xs truncate">
          {node.args?.join(" ") || ""}
        </TableCell>
      </TableRow>
      {hasChildren &&
        isExpanded &&
        node.children.map((child) => (
          <ProcessTreeNode
            key={child.pid}
            node={child}
            expandedPids={expandedPids}
            toggleExpand={toggleExpand}
          />
        ))}
    </>
  );
}

export function ProcessTree({ processes }: { processes: ProcessEvent[] }) {
  const [view, setView] = useState<"tree" | "table">("tree");
  const [expandedPids, setExpandedPids] = useState<Set<number>>(new Set());

  const tree = useMemo(() => buildProcessTree(processes), [processes]);

  // Auto-expand all on first render
  useMemo(() => {
    const allPids = new Set<number>();
    function collect(nodes: ProcessNode[]) {
      for (const n of nodes) {
        if (n.children.length > 0) allPids.add(n.pid);
        collect(n.children);
      }
    }
    collect(tree);
    setExpandedPids(allPids);
  }, [tree]);

  const toggleExpand = (pid: number) => {
    setExpandedPids((prev) => {
      const next = new Set(prev);
      if (next.has(pid)) next.delete(pid);
      else next.add(pid);
      return next;
    });
  };

  const expandAll = () => {
    const allPids = new Set<number>();
    function collect(nodes: ProcessNode[]) {
      for (const n of nodes) {
        if (n.children.length > 0) allPids.add(n.pid);
        collect(n.children);
      }
    }
    collect(tree);
    setExpandedPids(allPids);
  };

  const collapseAll = () => setExpandedPids(new Set());

  if (processes.length === 0) return null;

  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <p className="text-sm font-medium">
          Processes ({processes.length})
        </p>
        <div className="flex items-center gap-1">
          <Button
            variant={view === "tree" ? "default" : "outline"}
            size="sm"
            className="h-6 px-2 text-xs"
            onClick={() => setView("tree")}
          >
            Tree
          </Button>
          <Button
            variant={view === "table" ? "default" : "outline"}
            size="sm"
            className="h-6 px-2 text-xs"
            onClick={() => setView("table")}
          >
            Table
          </Button>
          {view === "tree" && (
            <>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 px-2 text-xs"
                onClick={expandAll}
              >
                Expand All
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 px-2 text-xs"
                onClick={collapseAll}
              >
                Collapse All
              </Button>
            </>
          )}
        </div>
      </div>

      {view === "tree" ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-24">PID</TableHead>
              <TableHead className="w-20">PPID</TableHead>
              <TableHead>Command</TableHead>
              <TableHead>Args</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {tree.map((root) => (
              <ProcessTreeNode
                key={root.pid}
                node={root}
                expandedPids={expandedPids}
                toggleExpand={toggleExpand}
              />
            ))}
          </TableBody>
        </Table>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>PID</TableHead>
              <TableHead>PPID</TableHead>
              <TableHead>Command</TableHead>
              <TableHead>Args</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {processes.map((p, i) => (
              <TableRow key={i}>
                <TableCell className="font-mono">{p.pid}</TableCell>
                <TableCell className="font-mono">
                  {p.ppid != null ? p.ppid : "-"}
                </TableCell>
                <TableCell className="font-mono">{p.command}</TableCell>
                <TableCell className="font-mono text-xs">
                  {p.args?.join(" ") || ""}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}
