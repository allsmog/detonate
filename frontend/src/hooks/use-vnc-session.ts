"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export interface VNCSessionInfo {
  ws_url: string;
  timeout: number;
  ws_port: number;
}

export interface VNCSessionStatus {
  active: boolean;
  ws_url: string | null;
  ws_port: number | null;
  timeout: number | null;
  elapsed_seconds: number | null;
}

interface UseVNCSessionReturn {
  /** Session info returned from the start endpoint. */
  session: VNCSessionInfo | null;
  /** True while the start request is in-flight. */
  connecting: boolean;
  /** True when a session has been established. */
  connected: boolean;
  /** Seconds remaining before automatic disconnect. */
  timeRemaining: number;
  /** Error message, if any. */
  error: string | null;
  /** Start a VNC session for the analysis. */
  connect: () => Promise<void>;
  /** Explicitly stop the VNC session. */
  disconnect: () => Promise<void>;
}

/**
 * Hook to manage a VNC interactive session for a running analysis.
 *
 * Handles:
 * - Starting/stopping the websockify bridge via the API
 * - A countdown timer with automatic disconnect at expiry
 * - Error state tracking
 */
export function useVNCSession(
  submissionId: string,
  analysisId: string | null,
): UseVNCSessionReturn {
  const [session, setSession] = useState<VNCSessionInfo | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [connected, setConnected] = useState(false);
  const [timeRemaining, setTimeRemaining] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Clear interval helper
  const clearTimer = useCallback(() => {
    if (timerRef.current !== null) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const disconnect = useCallback(async () => {
    clearTimer();

    if (analysisId && connected) {
      try {
        await fetch(
          `/api/v1/submissions/${submissionId}/analyses/${analysisId}/vnc/stop`,
          { method: "POST" },
        );
      } catch {
        // Best-effort -- the session may already be expired server-side
      }
    }

    setSession(null);
    setConnected(false);
    setTimeRemaining(0);
  }, [submissionId, analysisId, connected, clearTimer]);

  const connect = useCallback(async () => {
    if (!analysisId) return;

    setConnecting(true);
    setError(null);

    try {
      const res = await fetch(
        `/api/v1/submissions/${submissionId}/analyses/${analysisId}/vnc/start`,
        { method: "POST" },
      );

      if (!res.ok) {
        const body = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(body.detail || `Failed to start VNC (${res.status})`);
      }

      const data: VNCSessionInfo = await res.json();
      setSession(data);
      setTimeRemaining(data.timeout);
      setConnected(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to start VNC session");
      setSession(null);
      setConnected(false);
    } finally {
      setConnecting(false);
    }
  }, [submissionId, analysisId]);

  // Countdown timer -- starts when connected, stops when disconnected
  useEffect(() => {
    if (!connected || timeRemaining <= 0) {
      clearTimer();
      return;
    }

    timerRef.current = setInterval(() => {
      setTimeRemaining((prev) => {
        if (prev <= 1) {
          // Time is up -- disconnect
          disconnect();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearTimer();
  }, [connected, timeRemaining > 0]); // eslint-disable-line react-hooks/exhaustive-deps

  // Clean up on unmount or when analysis changes
  useEffect(() => {
    return () => {
      clearTimer();
    };
  }, [clearTimer]);

  // Reset when the analysis changes
  useEffect(() => {
    setSession(null);
    setConnected(false);
    setConnecting(false);
    setTimeRemaining(0);
    setError(null);
    clearTimer();
  }, [analysisId, clearTimer]);

  return {
    session,
    connecting,
    connected,
    timeRemaining,
    error,
    connect,
    disconnect,
  };
}
