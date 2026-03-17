"use client";

import { useCallback, useEffect, useRef, useState } from "react";

/**
 * A single telemetry event received from the analysis WebSocket.
 */
export interface TelemetryEvent {
  type: "process" | "network" | "file" | "status" | "complete";
  timestamp?: number;
  pid?: number;
  command?: string;
  args?: string[];
  protocol?: string;
  address?: string;
  port?: number;
  operation?: string;
  path?: string;
  message?: string;
  exit_code?: number;
}

interface UseAnalysisStreamReturn {
  /** Events received so far, ordered chronologically. */
  events: TelemetryEvent[];
  /** Whether the WebSocket is currently connected. */
  connected: boolean;
  /** Whether the analysis has signalled completion. */
  complete: boolean;
}

/**
 * Hook that connects to the analysis WebSocket and streams live events.
 *
 * @param submissionId  The submission UUID
 * @param analysisId    The analysis UUID (null to skip connecting)
 * @param enabled       Set to false to disable the connection (e.g. when the
 *                      analysis has already completed)
 */
export function useAnalysisStream(
  submissionId: string,
  analysisId: string | null,
  enabled: boolean = true,
): UseAnalysisStreamReturn {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [complete, setComplete] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!enabled || !analysisId) {
      return;
    }

    // Determine the WebSocket URL.  In the browser the Next.js dev proxy
    // rewrites /api/* to the FastAPI backend, but WebSocket connections
    // need an explicit ws:// URL.
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/api/v1/submissions/${submissionId}/analyses/${analysisId}/ws`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
    };

    ws.onmessage = (msg) => {
      try {
        const event: TelemetryEvent = JSON.parse(msg.data);
        if (event.type === "complete") {
          setComplete(true);
        }
        setEvents((prev) => [...prev, event]);
      } catch {
        // Ignore malformed messages
      }
    };

    ws.onerror = () => {
      // Errors are expected when the analysis finishes and the server
      // closes the connection.
    };

    ws.onclose = () => {
      setConnected(false);
    };

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [submissionId, analysisId, enabled]);

  // Reset state when the analysis changes
  useEffect(() => {
    setEvents([]);
    setComplete(false);
    setConnected(false);
  }, [analysisId]);

  return { events, connected, complete };
}
