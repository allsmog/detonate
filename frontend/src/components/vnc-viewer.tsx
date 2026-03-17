"use client";

import { useCallback, useRef, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useVNCSession } from "@/hooks/use-vnc-session";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTime(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

function Spinner() {
  return (
    <svg
      className="animate-spin h-4 w-4"
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

// ---------------------------------------------------------------------------
// Icons (inline SVGs to avoid external dependencies)
// ---------------------------------------------------------------------------

function ExpandIcon({ className }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="M8 3H5a2 2 0 0 0-2 2v3" />
      <path d="M21 8V5a2 2 0 0 0-2-2h-3" />
      <path d="M3 16v3a2 2 0 0 0 2 2h3" />
      <path d="M16 21h3a2 2 0 0 0 2-2v-3" />
    </svg>
  );
}

function ShrinkIcon({ className }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="M4 14h6v6" />
      <path d="M20 10h-6V4" />
      <path d="M14 10l7-7" />
      <path d="M3 21l7-7" />
    </svg>
  );
}

function MonitorIcon({ className }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <rect x="2" y="3" width="20" height="14" rx="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// VNC Viewer component
// ---------------------------------------------------------------------------

export function VNCViewer({
  submissionId,
  analysisId,
  isRunning,
}: {
  submissionId: string;
  analysisId: string | null;
  isRunning: boolean;
}) {
  const {
    session,
    connecting,
    connected,
    timeRemaining,
    error,
    connect,
    disconnect,
  } = useVNCSession(submissionId, analysisId);

  const [isFullscreen, setIsFullscreen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const toggleFullscreen = useCallback(async () => {
    if (!containerRef.current) return;

    if (!document.fullscreenElement) {
      try {
        await containerRef.current.requestFullscreen();
        setIsFullscreen(true);
      } catch {
        // Fullscreen not supported or denied
      }
    } else {
      await document.exitFullscreen();
      setIsFullscreen(false);
    }
  }, []);

  // Listen for fullscreen exit via Escape key
  // (the browser handles Escape natively for fullscreen)
  const handleFullscreenChange = useCallback(() => {
    setIsFullscreen(!!document.fullscreenElement);
  }, []);

  // Attach fullscreen change listener
  if (typeof document !== "undefined") {
    document.addEventListener("fullscreenchange", handleFullscreenChange);
  }

  const isWarning = timeRemaining > 0 && timeRemaining <= 60;

  // Don't show anything if no analysis is selected
  if (!analysisId) return null;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <MonitorIcon className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-base">Interactive Session</CardTitle>
          </div>
          <div className="flex items-center gap-2">
            {connected && (
              <Badge variant={isWarning ? "destructive" : "default"}>
                {formatTime(timeRemaining)}
              </Badge>
            )}
            {connected && (
              <Badge variant="outline" className="text-green-600">
                Connected
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Error display */}
        {error && (
          <div className="rounded-lg border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm text-destructive">
            {error}
          </div>
        )}

        {/* Not running state */}
        {!isRunning && !connected && (
          <div className="flex flex-col items-center gap-3 py-8 text-center">
            <MonitorIcon className="h-8 w-8 text-muted-foreground" />
            <div>
              <p className="text-sm font-medium">Interactive session unavailable</p>
              <p className="text-sm text-muted-foreground">
                Start a dynamic analysis to enable VNC interactive access to the
                sandbox.
              </p>
            </div>
          </div>
        )}

        {/* Ready to connect */}
        {isRunning && !connected && !connecting && (
          <div className="flex flex-col items-center gap-3 py-8 text-center">
            <MonitorIcon className="h-8 w-8 text-muted-foreground" />
            <div>
              <p className="text-sm font-medium">
                Sandbox is running
              </p>
              <p className="text-sm text-muted-foreground">
                Connect to the live sandbox desktop to interact with the sample
                in real time. Sessions are limited to 5 minutes.
              </p>
            </div>
            <Button onClick={connect} disabled={connecting}>
              Go Interactive
            </Button>
          </div>
        )}

        {/* Connecting */}
        {connecting && (
          <div className="flex flex-col items-center gap-3 py-8 text-center">
            <Spinner />
            <p className="text-sm text-muted-foreground">
              Starting VNC session...
            </p>
          </div>
        )}

        {/* Connected -- VNC canvas area */}
        {connected && session && (
          <div ref={containerRef} className="space-y-3">
            {/* Timeout warning */}
            {isWarning && (
              <div className="rounded-lg border border-orange-400/50 bg-orange-50 px-4 py-2 text-sm text-orange-700 dark:border-orange-400/30 dark:bg-orange-950/30 dark:text-orange-400">
                Session expiring in {formatTime(timeRemaining)} -- save any
                findings before the session ends.
              </div>
            )}

            {/* VNC display area */}
            <div className="relative overflow-hidden rounded-lg border border-border bg-black">
              {/*
                noVNC canvas placeholder.

                In a full deployment, this would embed a noVNC RFB client
                connected to session.ws_url.  Since @novnc/novnc may not
                be installed, we use an iframe pointing at the websockify
                web client (websockify serves a built-in noVNC page) or
                show connection info for manual connection.
              */}
              <div className="flex aspect-video items-center justify-center bg-neutral-900">
                <div className="text-center space-y-3">
                  <MonitorIcon className="mx-auto h-12 w-12 text-neutral-600" />
                  <div className="space-y-1">
                    <p className="text-sm font-medium text-neutral-300">
                      VNC Session Active
                    </p>
                    <p className="text-xs text-neutral-500 font-mono">
                      WebSocket: {session.ws_url}
                    </p>
                    <p className="text-xs text-neutral-500">
                      Port: {session.ws_port}
                    </p>
                  </div>
                  <div className="pt-2">
                    <a
                      href={`http://localhost:${session.ws_port}/vnc.html?autoconnect=true`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 rounded-lg border border-neutral-700 bg-neutral-800 px-3 py-1.5 text-xs text-neutral-300 hover:bg-neutral-700 hover:text-white transition-colors"
                    >
                      Open noVNC in new tab
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        className="h-3 w-3"
                      >
                        <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                        <polyline points="15 3 21 3 21 9" />
                        <line x1="10" y1="14" x2="21" y2="3" />
                      </svg>
                    </a>
                  </div>
                </div>
              </div>
            </div>

            {/* Control bar */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={toggleFullscreen}
                  title={isFullscreen ? "Exit fullscreen" : "Enter fullscreen"}
                >
                  {isFullscreen ? (
                    <ShrinkIcon className="h-4 w-4" />
                  ) : (
                    <ExpandIcon className="h-4 w-4" />
                  )}
                  <span className="ml-1.5">
                    {isFullscreen ? "Exit Fullscreen" : "Fullscreen"}
                  </span>
                </Button>

                <Button
                  variant="outline"
                  size="sm"
                  title="Send Ctrl+Alt+Del to the sandbox"
                >
                  Ctrl+Alt+Del
                </Button>
              </div>

              <Button
                variant="destructive"
                size="sm"
                onClick={disconnect}
              >
                Disconnect
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
