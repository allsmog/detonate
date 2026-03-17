"use client";

import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { PoolStatus } from "@/lib/types";

export function PoolStatusIndicator() {
  const [status, setStatus] = useState<PoolStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const data = await api.getPoolStatus();
      setStatus(data);
      setError(null);
    } catch {
      // Pool might not be enabled -- silently ignore
      setStatus(null);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 15000); // Refresh every 15s
    return () => clearInterval(interval);
  }, [fetchStatus]);

  if (!status || !status.pool_enabled) {
    return null;
  }

  const availableColor =
    status.available > 0
      ? "text-green-600 dark:text-green-400"
      : "text-amber-600 dark:text-amber-400";

  const errorColor =
    status.error > 0
      ? "text-red-600 dark:text-red-400"
      : "text-muted-foreground";

  return (
    <div className="flex items-center gap-2 text-xs text-muted-foreground">
      <span className="flex items-center gap-1">
        <span
          className={`inline-block h-2 w-2 rounded-full ${
            status.available > 0 ? "bg-green-500" : "bg-amber-500"
          }`}
        />
        Pool
      </span>
      <span className={availableColor}>{status.available} ready</span>
      <span className="text-muted-foreground">{status.busy} busy</span>
      {status.error > 0 && (
        <span className={errorColor}>{status.error} err</span>
      )}
      <span className="text-muted-foreground/60">/ {status.total}</span>
    </div>
  );
}
