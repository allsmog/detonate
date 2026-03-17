"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { UserMenu } from "@/components/auth/user-menu";
import { PoolStatusIndicator } from "@/components/pool-status";

export function Nav() {
  const pathname = usePathname();

  return (
    <nav className="border-b bg-background">
      <div className="mx-auto flex h-14 max-w-5xl items-center px-4">
        <Link href="/" className="mr-8 text-lg font-bold tracking-tight">
          Detonate
        </Link>
        <div className="flex gap-4">
          <Link
            href="/"
            className={`text-sm transition-colors hover:text-foreground ${
              pathname === "/" ? "text-foreground font-medium" : "text-muted-foreground"
            }`}
          >
            Submit
          </Link>
          <Link
            href="/submissions"
            className={`text-sm transition-colors hover:text-foreground ${
              pathname.startsWith("/submissions")
                ? "text-foreground font-medium"
                : "text-muted-foreground"
            }`}
          >
            Submissions
          </Link>
          <Link
            href="/search"
            className={`text-sm transition-colors hover:text-foreground ${
              pathname.startsWith("/search")
                ? "text-foreground font-medium"
                : "text-muted-foreground"
            }`}
          >
            Search
          </Link>
          <Link
            href="/dashboard"
            className={`text-sm transition-colors hover:text-foreground ${
              pathname.startsWith("/dashboard")
                ? "text-foreground font-medium"
                : "text-muted-foreground"
            }`}
          >
            Dashboard
          </Link>
        </div>
        <div className="ml-auto flex items-center gap-3">
          <PoolStatusIndicator />
          <UserMenu />
        </div>
      </div>
    </nav>
  );
}
