export interface ProcessEvent {
  pid: number;
  ppid?: number;
  command: string;
  args?: string[];
}

export interface ProcessNode extends ProcessEvent {
  children: ProcessNode[];
  depth: number;
  suspicious: boolean;
}

const SUSPICIOUS_PATTERNS = [
  /\bwget\b/,
  /\bcurl\b.*\|\s*sh/,
  /\bcurl\b.*\|\s*bash/,
  /\bbase64\s+-d\b/,
  /\bpowershell\b/i,
  /\bnc\b.*-e/,
  /\bncat\b/,
  /\bchmod\s+[0-7]*[7][0-7]*\b/,
  /\brm\s+-rf\s+\//,
  /\/etc\/shadow/,
  /\/etc\/passwd/,
  /\bcrontab\b/,
  /\bnmap\b/,
  /\bmasscan\b/,
];

function isSuspicious(process: ProcessEvent): boolean {
  const full = `${process.command} ${(process.args || []).join(" ")}`;
  return SUSPICIOUS_PATTERNS.some((p) => p.test(full));
}

export function buildProcessTree(processes: ProcessEvent[]): ProcessNode[] {
  if (!processes.length) return [];

  const nodeMap = new Map<number, ProcessNode>();
  const roots: ProcessNode[] = [];

  // Create nodes
  for (const proc of processes) {
    nodeMap.set(proc.pid, {
      ...proc,
      children: [],
      depth: 0,
      suspicious: isSuspicious(proc),
    });
  }

  // Build parent-child relationships
  for (const node of nodeMap.values()) {
    if (node.ppid != null && nodeMap.has(node.ppid)) {
      nodeMap.get(node.ppid)!.children.push(node);
    } else {
      roots.push(node);
    }
  }

  // Assign depths
  function setDepth(node: ProcessNode, depth: number) {
    node.depth = depth;
    for (const child of node.children) {
      setDepth(child, depth + 1);
    }
  }
  for (const root of roots) {
    setDepth(root, 0);
  }

  return roots;
}

export function flattenTree(roots: ProcessNode[]): ProcessNode[] {
  const result: ProcessNode[] = [];
  function walk(node: ProcessNode) {
    result.push(node);
    for (const child of node.children) {
      walk(child);
    }
  }
  for (const root of roots) {
    walk(root);
  }
  return result;
}
