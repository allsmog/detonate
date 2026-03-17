"use client";

import { useCallback, useEffect, useState } from "react";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  useAnalysisMedia,
  type ScreenshotInfo,
} from "@/hooks/use-analysis-media";

// ---------------------------------------------------------------------------
// Lightbox overlay (no dialog component -- pure div overlay)
// ---------------------------------------------------------------------------

function Lightbox({
  screenshots,
  index,
  onClose,
  onPrev,
  onNext,
}: {
  screenshots: ScreenshotInfo[];
  index: number;
  onClose: () => void;
  onPrev: () => void;
  onNext: () => void;
}) {
  const shot = screenshots[index];
  const hasPrev = index > 0;
  const hasNext = index < screenshots.length - 1;

  // Keyboard navigation
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
      if (e.key === "ArrowLeft" && hasPrev) onPrev();
      if (e.key === "ArrowRight" && hasNext) onNext();
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [onClose, onPrev, onNext, hasPrev, hasNext]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Screenshot lightbox"
    >
      {/* Close button */}
      <button
        onClick={(e) => {
          e.stopPropagation();
          onClose();
        }}
        className="absolute top-4 right-4 z-10 flex h-10 w-10 items-center justify-center rounded-full bg-white/10 text-white hover:bg-white/20 transition-colors"
        aria-label="Close lightbox"
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="h-5 w-5"
        >
          <line x1="18" y1="6" x2="6" y2="18" />
          <line x1="6" y1="6" x2="18" y2="18" />
        </svg>
      </button>

      {/* Previous button */}
      {hasPrev && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onPrev();
          }}
          className="absolute left-4 z-10 flex h-12 w-12 items-center justify-center rounded-full bg-white/10 text-white hover:bg-white/20 transition-colors"
          aria-label="Previous screenshot"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="h-6 w-6"
          >
            <polyline points="15 18 9 12 15 6" />
          </svg>
        </button>
      )}

      {/* Next button */}
      {hasNext && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onNext();
          }}
          className="absolute right-4 z-10 flex h-12 w-12 items-center justify-center rounded-full bg-white/10 text-white hover:bg-white/20 transition-colors"
          aria-label="Next screenshot"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="h-6 w-6"
          >
            <polyline points="9 18 15 12 9 6" />
          </svg>
        </button>
      )}

      {/* Image */}
      <div
        className="relative max-h-[85vh] max-w-[90vw]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src={shot.url}
          alt={`Screenshot ${shot.index + 1}`}
          className="max-h-[85vh] max-w-[90vw] rounded-lg object-contain shadow-2xl"
        />
        <div className="absolute bottom-0 left-0 right-0 flex items-center justify-center rounded-b-lg bg-black/50 px-4 py-2 text-sm text-white">
          <span>
            {index + 1} / {screenshots.length}
          </span>
          {shot.timestamp != null && (
            <span className="ml-4 text-white/70">
              {shot.timestamp.toFixed(1)}s
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function ScreenshotGallery({
  submissionId,
  analysisId,
}: {
  submissionId: string;
  analysisId: string | null;
}) {
  const { data, loading, error, refresh } = useAnalysisMedia(
    submissionId,
    analysisId,
  );
  const [lightboxIndex, setLightboxIndex] = useState<number | null>(null);

  const openLightbox = useCallback((idx: number) => {
    setLightboxIndex(idx);
  }, []);

  const closeLightbox = useCallback(() => {
    setLightboxIndex(null);
  }, []);

  const goToPrev = useCallback(() => {
    setLightboxIndex((prev) =>
      prev !== null && prev > 0 ? prev - 1 : prev,
    );
  }, []);

  const goToNext = useCallback(() => {
    setLightboxIndex((prev) => {
      if (prev === null || !data) return prev;
      return prev < data.screenshots.length - 1 ? prev + 1 : prev;
    });
  }, [data]);

  const screenshots = data?.screenshots ?? [];
  const videoUrl = data?.video_url ?? null;
  const hasMedia = screenshots.length > 0 || videoUrl !== null;

  // Don't render the card at all if there is no analysis selected
  if (!analysisId) return null;

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">Screenshots & Video</CardTitle>
            {hasMedia && (
              <Button variant="outline" size="sm" onClick={refresh}>
                Refresh
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Loading state */}
          {loading && !data && (
            <p className="text-sm text-muted-foreground">Loading media...</p>
          )}

          {/* Error state */}
          {error && (
            <div className="space-y-2">
              <p className="text-sm text-destructive">{error}</p>
              <Button variant="outline" size="sm" onClick={refresh}>
                Retry
              </Button>
            </div>
          )}

          {/* Empty state */}
          {!loading && !error && data && !hasMedia && (
            <p className="text-sm text-muted-foreground">
              No screenshots or video captured for this analysis.
            </p>
          )}

          {/* Screenshot thumbnail grid */}
          {screenshots.length > 0 && (
            <div>
              <p className="text-sm font-medium mb-2">
                Screenshots ({screenshots.length})
              </p>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
                {screenshots.map((shot, idx) => (
                  <button
                    key={shot.index}
                    onClick={() => openLightbox(idx)}
                    className="group relative aspect-video overflow-hidden rounded-lg border border-border bg-muted transition-all hover:ring-2 hover:ring-ring focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                      src={shot.url}
                      alt={`Screenshot ${shot.index + 1}`}
                      className="h-full w-full object-cover transition-transform group-hover:scale-105"
                      loading="lazy"
                    />
                    <div className="absolute inset-0 bg-black/0 transition-colors group-hover:bg-black/10" />
                    <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/60 to-transparent px-2 py-1">
                      <span className="text-xs text-white">
                        #{shot.index + 1}
                        {shot.timestamp != null && (
                          <span className="ml-1 text-white/70">
                            {shot.timestamp.toFixed(1)}s
                          </span>
                        )}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Video player */}
          {videoUrl && (
            <div>
              <p className="text-sm font-medium mb-2">Recording</p>
              <div className="relative overflow-hidden rounded-lg border border-border bg-black">
                <video
                  controls
                  preload="metadata"
                  className="w-full"
                  src={videoUrl}
                >
                  <track kind="captions" />
                  Your browser does not support the video element.
                </video>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Lightbox overlay */}
      {lightboxIndex !== null && screenshots.length > 0 && (
        <Lightbox
          screenshots={screenshots}
          index={lightboxIndex}
          onClose={closeLightbox}
          onPrev={goToPrev}
          onNext={goToNext}
        />
      )}
    </>
  );
}
