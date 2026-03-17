"use client";

import { useCallback, useEffect, useState } from "react";

export interface CommentData {
  id: string;
  submission_id: string;
  user_id: string;
  user_email: string;
  user_display_name: string | null;
  content: string;
  created_at: string | null;
  updated_at: string | null;
}

interface CommentsState {
  comments: CommentData[];
  total: number;
  loading: boolean;
  error: string | null;
}

interface CommentsListResponse {
  items: CommentData[];
  total: number;
}

const API_BASE = "/api/v1";

function getAuthHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const token = localStorage.getItem("detonate_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function commentsRequest<T>(
  path: string,
  init?: RequestInit
): Promise<T> {
  const authHeaders = getAuthHeaders();
  const headers = { ...authHeaders, ...(init?.headers || {}) };
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || `Request failed: ${res.status}`);
  }
  // Handle 204 No Content
  if (res.status === 204) {
    return undefined as T;
  }
  return res.json();
}

export function useComments(submissionId: string) {
  const [state, setState] = useState<CommentsState>({
    comments: [],
    total: 0,
    loading: true,
    error: null,
  });

  const fetchComments = useCallback(async () => {
    setState((prev) => ({ ...prev, loading: true, error: null }));
    try {
      const result = await commentsRequest<CommentsListResponse>(
        `/submissions/${submissionId}/comments`
      );
      setState({
        comments: result.items,
        total: result.total,
        loading: false,
        error: null,
      });
    } catch (err) {
      setState((prev) => ({
        ...prev,
        loading: false,
        error: err instanceof Error ? err.message : "Failed to load comments",
      }));
    }
  }, [submissionId]);

  useEffect(() => {
    fetchComments();
  }, [fetchComments]);

  const addComment = useCallback(
    async (content: string) => {
      const newComment = await commentsRequest<CommentData>(
        `/submissions/${submissionId}/comments`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content }),
        }
      );
      setState((prev) => ({
        ...prev,
        comments: [...prev.comments, newComment],
        total: prev.total + 1,
      }));
      return newComment;
    },
    [submissionId]
  );

  const editComment = useCallback(
    async (commentId: string, content: string) => {
      const updated = await commentsRequest<CommentData>(
        `/submissions/${submissionId}/comments/${commentId}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content }),
        }
      );
      setState((prev) => ({
        ...prev,
        comments: prev.comments.map((c) =>
          c.id === commentId ? updated : c
        ),
      }));
      return updated;
    },
    [submissionId]
  );

  const deleteComment = useCallback(
    async (commentId: string) => {
      await commentsRequest<void>(
        `/submissions/${submissionId}/comments/${commentId}`,
        { method: "DELETE" }
      );
      setState((prev) => ({
        ...prev,
        comments: prev.comments.filter((c) => c.id !== commentId),
        total: prev.total - 1,
      }));
    },
    [submissionId]
  );

  return {
    comments: state.comments,
    total: state.total,
    loading: state.loading,
    error: state.error,
    addComment,
    editComment,
    deleteComment,
    refresh: fetchComments,
  };
}
