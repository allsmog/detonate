"use client";

import { useCallback, useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useChat } from "@/hooks/use-chat";

import { ChatInput } from "./chat-input";
import { ChatMessageList } from "./chat-message-list";

export function ChatPanel({ submissionId }: { submissionId: string }) {
  const [open, setOpen] = useState(false);
  const [quickAsk, setQuickAsk] = useState("");
  const {
    messages,
    streaming,
    streamContent,
    error,
    initConversation,
    sendMessage,
  } = useChat(submissionId);

  useEffect(() => {
    if (open) {
      initConversation();
    }
  }, [open, initConversation]);

  const handleQuickAsk = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Enter" && quickAsk.trim()) {
        const msg = quickAsk.trim();
        setQuickAsk("");
        setOpen(true);
        // Send message after conversation is initialized
        setTimeout(() => sendMessage(msg), 500);
      }
    },
    [quickAsk, sendMessage]
  );

  if (!open) {
    return (
      <div className="flex gap-2">
        <Input
          placeholder="Quick ask about this file..."
          value={quickAsk}
          onChange={(e) => setQuickAsk(e.target.value)}
          onKeyDown={handleQuickAsk}
          className="flex-1"
        />
        <Button variant="outline" onClick={() => setOpen(true)} className="shrink-0">
          Open Chat
        </Button>
      </div>
    );
  }

  return (
    <Card className="flex flex-col" style={{ height: "500px" }}>
      <CardHeader className="border-b py-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">AI Chat</CardTitle>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setOpen(false)}
            className="h-6 px-2 text-xs"
          >
            Close
          </Button>
        </div>
      </CardHeader>
      <CardContent className="flex-1 flex flex-col p-0 overflow-hidden">
        {error && (
          <p className="text-destructive text-sm px-3 pt-2">{error}</p>
        )}
        <ChatMessageList
          messages={messages}
          streamContent={streamContent}
          streaming={streaming}
        />
        <ChatInput onSend={sendMessage} disabled={streaming} />
      </CardContent>
    </Card>
  );
}
