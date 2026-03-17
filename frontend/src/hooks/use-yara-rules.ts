"use client";

import { useCallback, useEffect, useState } from "react";

import { api } from "@/lib/api";
import type {
  YaraRuleFile,
  YaraRuleContent,
  YaraValidateResponse,
} from "@/lib/types";

/**
 * Hook for YARA rule management: list, upload, update, delete, validate.
 */
export function useYaraRules() {
  const [rules, setRules] = useState<YaraRuleFile[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.getYaraRules();
      setRules(result);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to fetch YARA rules"
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const getRuleContent = useCallback(
    async (filename: string): Promise<YaraRuleContent | null> => {
      try {
        return await api.getYaraRuleContent(filename);
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to fetch rule content"
        );
        return null;
      }
    },
    []
  );

  const uploadRule = useCallback(
    async (filename: string, content: string): Promise<boolean> => {
      try {
        await api.uploadYaraRule(filename, content);
        await refresh();
        return true;
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to upload rule"
        );
        return false;
      }
    },
    [refresh]
  );

  const updateRule = useCallback(
    async (filename: string, content: string): Promise<boolean> => {
      try {
        await api.updateYaraRule(filename, content);
        await refresh();
        return true;
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to update rule"
        );
        return false;
      }
    },
    [refresh]
  );

  const deleteRule = useCallback(
    async (filename: string): Promise<boolean> => {
      try {
        await api.deleteYaraRule(filename);
        await refresh();
        return true;
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to delete rule"
        );
        return false;
      }
    },
    [refresh]
  );

  const validateRule = useCallback(
    async (content: string): Promise<YaraValidateResponse> => {
      try {
        return await api.validateYaraRule(content);
      } catch (err) {
        return {
          valid: false,
          error:
            err instanceof Error ? err.message : "Validation request failed",
        };
      }
    },
    []
  );

  return {
    rules,
    loading,
    error,
    refresh,
    getRuleContent,
    uploadRule,
    updateRule,
    deleteRule,
    validateRule,
  };
}
