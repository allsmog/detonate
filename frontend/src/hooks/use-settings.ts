"use client";

import { useCallback, useEffect, useState } from "react";

export interface FeatureFlags {
  ai_enabled: boolean;
  yara_enabled: boolean;
  suricata_enabled: boolean;
  auth_enabled: boolean;
  screenshots_enabled: boolean;
  qemu_enabled: boolean;
  sandbox_pool_enabled: boolean;
}

export function useSettings() {
  const [features, setFeatures] = useState<FeatureFlags | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchFeatures = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/v1/settings/features");

      if (!res.ok) {
        const body = await res
          .json()
          .catch(() => ({ detail: res.statusText }));
        throw new Error(body.detail || "Failed to fetch feature flags");
      }

      const data: FeatureFlags = await res.json();
      setFeatures(data);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "Failed to load settings",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchFeatures();
  }, [fetchFeatures]);

  return { features, loading, error, refresh: fetchFeatures };
}
