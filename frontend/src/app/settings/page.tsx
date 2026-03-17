"use client";

import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useSettings } from "@/hooks/use-settings";

interface ProviderInfo {
  ai_provider: string | null;
  ai_model: string | null;
  threat_intel_providers: Record<string, boolean>[];
}

interface LimitsInfo {
  max_file_size: number;
  sandbox_pool_size: number;
  sandbox_platform: string;
}

interface FullSettings {
  features: ReturnType<typeof useSettings>["features"];
  providers: ProviderInfo;
  limits: LimitsInfo;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function StatusBadge({ enabled }: { enabled: boolean }) {
  return (
    <Badge variant={enabled ? "default" : "secondary"}>
      {enabled ? "Enabled" : "Disabled"}
    </Badge>
  );
}

export default function SettingsPage() {
  const { features, loading, error } = useSettings();
  const [fullSettings, setFullSettings] = useState<FullSettings | null>(null);
  const [fullError, setFullError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchFull() {
      try {
        const token =
          typeof window !== "undefined"
            ? localStorage.getItem("detonate_token")
            : null;
        const headers: Record<string, string> = token
          ? { Authorization: `Bearer ${token}` }
          : {};
        const res = await fetch("/api/v1/settings", { headers });
        if (res.ok) {
          const data: FullSettings = await res.json();
          setFullSettings(data);
        } else if (res.status === 401) {
          // Not authenticated -- feature flags are still available
          setFullError(null);
        } else {
          setFullError("Failed to load full settings");
        }
      } catch {
        // Silently fall back to feature-flags-only view
      }
    }
    fetchFull();
  }, []);

  if (loading) {
    return (
      <div className="mx-auto max-w-4xl px-4 py-8">
        <h1 className="mb-6 text-2xl font-bold">Settings</h1>
        <p className="text-muted-foreground">Loading configuration...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="mx-auto max-w-4xl px-4 py-8">
        <h1 className="mb-6 text-2xl font-bold">Settings</h1>
        <Card>
          <CardContent>
            <p className="text-destructive">{error}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const flags = fullSettings?.features ?? features;
  const providers = fullSettings?.providers ?? null;
  const limits = fullSettings?.limits ?? null;

  return (
    <div className="mx-auto max-w-4xl px-4 py-8">
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Runtime configuration for this Detonate instance. Settings are
          read-only and controlled via environment variables.
        </p>
      </div>

      <div className="grid gap-6">
        {/* Feature Flags */}
        <Card>
          <CardHeader>
            <CardTitle>Feature Flags</CardTitle>
            <CardDescription>
              Toggleable capabilities for this instance
            </CardDescription>
          </CardHeader>
          <CardContent>
            {flags ? (
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <FeatureRow label="AI Analysis" enabled={flags.ai_enabled} />
                <FeatureRow
                  label="YARA Scanning"
                  enabled={flags.yara_enabled}
                />
                <FeatureRow
                  label="Suricata IDS"
                  enabled={flags.suricata_enabled}
                />
                <FeatureRow
                  label="Authentication"
                  enabled={flags.auth_enabled}
                />
                <FeatureRow
                  label="Screenshots"
                  enabled={flags.screenshots_enabled}
                />
                <FeatureRow
                  label="QEMU Sandbox"
                  enabled={flags.qemu_enabled}
                />
                <FeatureRow
                  label="Machine Pool"
                  enabled={flags.sandbox_pool_enabled}
                />
              </div>
            ) : (
              <p className="text-muted-foreground">
                Feature flags unavailable.
              </p>
            )}
          </CardContent>
        </Card>

        {/* AI Provider */}
        {providers && (
          <Card>
            <CardHeader>
              <CardTitle>AI Provider</CardTitle>
              <CardDescription>
                LLM backend used for AI-powered analysis
              </CardDescription>
            </CardHeader>
            <CardContent>
              {providers.ai_provider ? (
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <InfoRow label="Provider" value={providers.ai_provider} />
                  <InfoRow
                    label="Model"
                    value={providers.ai_model ?? "Not set"}
                  />
                </div>
              ) : (
                <p className="text-muted-foreground">
                  AI features are disabled.
                </p>
              )}
            </CardContent>
          </Card>
        )}

        {/* Threat Intelligence */}
        {providers && (
          <Card>
            <CardHeader>
              <CardTitle>Threat Intelligence Providers</CardTitle>
              <CardDescription>
                External services used for IOC enrichment
              </CardDescription>
            </CardHeader>
            <CardContent>
              {providers.threat_intel_providers.length > 0 ? (
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  {providers.threat_intel_providers.map((entry) => {
                    const name = Object.keys(entry)[0];
                    const configured = entry[name];
                    return (
                      <div
                        key={name}
                        className="flex items-center justify-between rounded-md border px-3 py-2"
                      >
                        <span className="font-mono text-sm">{name}</span>
                        <StatusBadge enabled={configured} />
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-muted-foreground">
                  No threat intelligence providers registered.
                </p>
              )}
            </CardContent>
          </Card>
        )}

        {/* Sandbox Configuration */}
        {limits && (
          <Card>
            <CardHeader>
              <CardTitle>Sandbox Configuration</CardTitle>
              <CardDescription>
                Dynamic analysis environment settings
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <InfoRow label="Platform" value={limits.sandbox_platform} />
                <InfoRow
                  label="Pool Size"
                  value={String(limits.sandbox_pool_size)}
                />
              </div>
            </CardContent>
          </Card>
        )}

        {/* File Limits */}
        {limits && (
          <Card>
            <CardHeader>
              <CardTitle>File Limits</CardTitle>
              <CardDescription>
                Upload and processing constraints
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <InfoRow
                  label="Max File Size"
                  value={formatBytes(limits.max_file_size)}
                />
              </div>
            </CardContent>
          </Card>
        )}

        {/* Read-only notice */}
        <div className="rounded-md border border-dashed px-4 py-3 text-center text-sm text-muted-foreground">
          All settings are read-only and controlled via environment variables.
          Restart the API server after changing <code>.env</code> values.
        </div>
      </div>
    </div>
  );
}

function FeatureRow({
  label,
  enabled,
}: {
  label: string;
  enabled: boolean;
}) {
  return (
    <div className="flex items-center justify-between rounded-md border px-3 py-2">
      <span className="text-sm">{label}</span>
      <StatusBadge enabled={enabled} />
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between rounded-md border px-3 py-2">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="font-mono text-sm">{value}</span>
    </div>
  );
}
