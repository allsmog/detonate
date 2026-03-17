"use client";

import Link from "next/link";

import { useAuth } from "@/lib/auth-context";
import { Button } from "@/components/ui/button";

export function UserMenu() {
  const { user, loading, logout } = useAuth();

  if (loading) {
    return (
      <div className="h-8 w-20 animate-pulse rounded-lg bg-muted" />
    );
  }

  if (!user) {
    return (
      <Link href="/login">
        <Button variant="outline" size="sm">
          Log in
        </Button>
      </Link>
    );
  }

  return (
    <div className="flex items-center gap-3">
      <span className="text-sm text-muted-foreground">
        {user.display_name || user.email}
      </span>
      <Button variant="ghost" size="sm" onClick={logout}>
        Log out
      </Button>
    </div>
  );
}
