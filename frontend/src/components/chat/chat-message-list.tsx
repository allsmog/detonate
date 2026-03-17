"use client";

import { useEffect, useRef } from "react";

import type { ChatMessage } from "@/lib/types";

import { ChatMessageBubble } from "./chat-message";

export function ChatMessageList({
  messages,
  streamContent,
  streaming,
}: {
  messages: ChatMessage[];
  streamContent: string;
  streaming: boolean;
}) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, streamContent]);

  return (
    <div className="flex-1 overflow-y-auto p-3 space-y-3">
      {messages.length === 0 && !streaming && (
        <p className="text-center text-muted-foreground text-sm py-8">
          Ask a question about this file to get started.
        </p>
      )}
      {messages.map((msg) => (
        <ChatMessageBubble key={msg.id} role={msg.role} content={msg.content} />
      ))}
      {streaming && streamContent && (
        <ChatMessageBubble role="assistant" content={streamContent} />
      )}
      {streaming && !streamContent && (
        <div className="flex justify-start">
          <div className="bg-muted rounded-lg px-3 py-2 text-sm text-muted-foreground">
            Thinking...
          </div>
        </div>
      )}
      <div ref={bottomRef} />
    </div>
  );
}
