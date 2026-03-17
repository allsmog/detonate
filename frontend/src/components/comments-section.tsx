"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { useComments } from "@/hooks/use-comments";
import type { CommentData } from "@/hooks/use-comments";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

const AUTO_REFRESH_INTERVAL = 30_000; // 30 seconds

function UserAvatar({ name }: { name: string }) {
  const letter = (name || "?")[0].toUpperCase();
  return (
    <div className="flex size-8 shrink-0 items-center justify-center rounded-full bg-primary/10 text-sm font-medium text-primary">
      {letter}
    </div>
  );
}

function RelativeTime({ dateStr }: { dateStr: string | null }) {
  if (!dateStr) return <span className="text-xs text-muted-foreground">just now</span>;

  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMin = Math.floor(diffMs / 60_000);
  const diffHr = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHr / 24);

  let label: string;
  if (diffMin < 1) {
    label = "just now";
  } else if (diffMin < 60) {
    label = `${diffMin}m ago`;
  } else if (diffHr < 24) {
    label = `${diffHr}h ago`;
  } else if (diffDay < 30) {
    label = `${diffDay}d ago`;
  } else {
    label = date.toLocaleDateString();
  }

  return (
    <time
      dateTime={dateStr}
      title={date.toLocaleString()}
      className="text-xs text-muted-foreground"
    >
      {label}
    </time>
  );
}

function CommentItem({
  comment,
  currentUserId,
  onEdit,
  onDelete,
}: {
  comment: CommentData;
  currentUserId: string | null;
  onEdit: (id: string, content: string) => void;
  onDelete: (id: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [editContent, setEditContent] = useState(comment.content);
  const [saving, setSaving] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const isAuthor = currentUserId !== null && comment.user_id === currentUserId;
  const displayName = comment.user_display_name || comment.user_email;
  const wasEdited =
    comment.updated_at &&
    comment.created_at &&
    comment.updated_at !== comment.created_at;

  useEffect(() => {
    if (editing && textareaRef.current) {
      textareaRef.current.focus();
      textareaRef.current.selectionStart = textareaRef.current.value.length;
    }
  }, [editing]);

  const handleSave = useCallback(async () => {
    const trimmed = editContent.trim();
    if (!trimmed || trimmed === comment.content) {
      setEditing(false);
      setEditContent(comment.content);
      return;
    }
    setSaving(true);
    try {
      onEdit(comment.id, trimmed);
      setEditing(false);
    } finally {
      setSaving(false);
    }
  }, [editContent, comment.id, comment.content, onEdit]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        handleSave();
      }
      if (e.key === "Escape") {
        setEditing(false);
        setEditContent(comment.content);
      }
    },
    [handleSave, comment.content]
  );

  return (
    <div className="flex gap-3 py-3 first:pt-0 last:pb-0">
      <UserAvatar name={displayName} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium truncate">{displayName}</span>
          <RelativeTime dateStr={comment.created_at} />
          {wasEdited && (
            <span className="text-xs text-muted-foreground">(edited)</span>
          )}
        </div>
        {editing ? (
          <div className="mt-1.5 space-y-2">
            <textarea
              ref={textareaRef}
              value={editContent}
              onChange={(e) => setEditContent(e.target.value)}
              onKeyDown={handleKeyDown}
              className="w-full min-h-[60px] rounded-lg border border-input bg-transparent px-3 py-2 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 resize-y"
              disabled={saving}
            />
            <div className="flex gap-2">
              <Button
                size="xs"
                onClick={handleSave}
                disabled={saving || !editContent.trim()}
              >
                {saving ? "Saving..." : "Save"}
              </Button>
              <Button
                size="xs"
                variant="ghost"
                onClick={() => {
                  setEditing(false);
                  setEditContent(comment.content);
                }}
                disabled={saving}
              >
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <p className="mt-0.5 text-sm whitespace-pre-wrap break-words text-foreground/90">
            {comment.content}
          </p>
        )}
        {isAuthor && !editing && (
          <div className="mt-1 flex gap-2">
            <button
              type="button"
              onClick={() => setEditing(true)}
              className="text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              Edit
            </button>
            <button
              type="button"
              onClick={() => onDelete(comment.id)}
              className="text-xs text-muted-foreground hover:text-destructive transition-colors"
            >
              Delete
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function AddCommentForm({
  onSubmit,
}: {
  onSubmit: (content: string) => Promise<void>;
}) {
  const [content, setContent] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      const trimmed = content.trim();
      if (!trimmed) return;

      setSubmitting(true);
      setError(null);
      try {
        await onSubmit(trimmed);
        setContent("");
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to add comment"
        );
      } finally {
        setSubmitting(false);
      }
    },
    [content, onSubmit]
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if (e.key === "Enter" && (e.metaKey || e.ctrlKey) && content.trim()) {
        e.preventDefault();
        handleSubmit(e as unknown as React.FormEvent);
      }
    },
    [content, handleSubmit]
  );

  return (
    <form onSubmit={handleSubmit} className="space-y-2">
      <textarea
        value={content}
        onChange={(e) => setContent(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="Add a comment..."
        className="w-full min-h-[80px] rounded-lg border border-input bg-transparent px-3 py-2 text-sm outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 resize-y"
        disabled={submitting}
      />
      {error && <p className="text-xs text-destructive">{error}</p>}
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">
          Ctrl+Enter to submit
        </span>
        <Button
          type="submit"
          size="sm"
          disabled={submitting || !content.trim()}
        >
          {submitting ? "Posting..." : "Comment"}
        </Button>
      </div>
    </form>
  );
}

export function CommentsSection({ submissionId }: { submissionId: string }) {
  const {
    comments,
    total,
    loading,
    error,
    addComment,
    editComment,
    deleteComment,
    refresh,
  } = useComments(submissionId);

  // Read current user ID from localStorage for author checks
  const [currentUserId, setCurrentUserId] = useState<string | null>(null);
  useEffect(() => {
    // Try to parse user info from localStorage (set during login)
    try {
      const stored = localStorage.getItem("detonate_user");
      if (stored) {
        const user = JSON.parse(stored);
        setCurrentUserId(user.id || null);
      }
    } catch {
      // Ignore parse errors
    }
  }, []);

  // Auto-refresh comments periodically
  useEffect(() => {
    const interval = setInterval(refresh, AUTO_REFRESH_INTERVAL);
    return () => clearInterval(interval);
  }, [refresh]);

  const handleAdd = useCallback(
    async (content: string) => {
      await addComment(content);
    },
    [addComment]
  );

  const handleEdit = useCallback(
    (commentId: string, content: string) => {
      editComment(commentId, content).catch(() => {
        // Refresh to restore state on error
        refresh();
      });
    },
    [editComment, refresh]
  );

  const handleDelete = useCallback(
    (commentId: string) => {
      deleteComment(commentId).catch(() => {
        refresh();
      });
    },
    [deleteComment, refresh]
  );

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">
            Comments{total > 0 ? ` (${total})` : ""}
          </CardTitle>
          <Button
            variant="ghost"
            size="xs"
            onClick={refresh}
            disabled={loading}
          >
            {loading ? "Loading..." : "Refresh"}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <p className="text-sm text-destructive">{error}</p>
        )}

        {!loading && comments.length === 0 && !error && (
          <p className="text-sm text-muted-foreground">
            No comments yet. Be the first to add one.
          </p>
        )}

        {comments.length > 0 && (
          <div className="divide-y">
            {comments.map((comment) => (
              <CommentItem
                key={comment.id}
                comment={comment}
                currentUserId={currentUserId}
                onEdit={handleEdit}
                onDelete={handleDelete}
              />
            ))}
          </div>
        )}

        <div className="border-t pt-4">
          <AddCommentForm onSubmit={handleAdd} />
        </div>
      </CardContent>
    </Card>
  );
}
