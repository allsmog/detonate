"use client";

import { useCallback, useState } from "react";

import { api } from "@/lib/api";
import type { ChatMessage, Conversation } from "@/lib/types";

export function useChat(submissionId: string) {
  const [conversation, setConversation] = useState<Conversation | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [streaming, setStreaming] = useState(false);
  const [streamContent, setStreamContent] = useState("");
  const [error, setError] = useState<string | null>(null);

  const initConversation = useCallback(async () => {
    try {
      // Try to get existing conversations
      const { items } = await api.getConversations(submissionId);
      if (items.length > 0) {
        const conv = items[0];
        setConversation(conv);
        const msgs = await api.getMessages(submissionId, conv.id);
        setMessages(msgs);
      } else {
        const conv = await api.createConversation(submissionId);
        setConversation(conv);
        setMessages([]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to init chat");
    }
  }, [submissionId]);

  const sendMessage = useCallback(
    async (content: string) => {
      if (!conversation || streaming) return;

      setError(null);
      // Add optimistic user message
      const userMsg: ChatMessage = {
        id: `temp-${Date.now()}`,
        conversation_id: conversation.id,
        role: "user",
        content,
        created_at: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, userMsg]);
      setStreaming(true);
      setStreamContent("");

      try {
        let accumulated = "";
        await api.streamMessage(
          submissionId,
          conversation.id,
          content,
          (delta, done) => {
            if (done) return;
            accumulated += delta;
            setStreamContent(accumulated);
          }
        );

        // Add completed assistant message
        const assistantMsg: ChatMessage = {
          id: `temp-assistant-${Date.now()}`,
          conversation_id: conversation.id,
          role: "assistant",
          content: accumulated,
          created_at: new Date().toISOString(),
        };
        setMessages((prev) => [...prev, assistantMsg]);
        setStreamContent("");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to send message");
      } finally {
        setStreaming(false);
      }
    },
    [conversation, streaming, submissionId]
  );

  return {
    conversation,
    messages,
    streaming,
    streamContent,
    error,
    initConversation,
    sendMessage,
  };
}
