"use client";

import { useCallback, useEffect, useState } from "react";

import { api } from "@/lib/api";
import type {
  ChallengeListResponse,
  ChallengeSummary,
  FlagSubmitResponse,
  LeaderboardResponse,
} from "@/lib/types";

const PLAYER_KEY = "detonate_ctf_player";

/** A stable anonymous handle so the leaderboard works without auth. */
export function getPlayerHandle(): string {
  if (typeof window === "undefined") return "anonymous";
  let p = localStorage.getItem(PLAYER_KEY);
  if (!p) {
    p = `player-${Math.random().toString(36).slice(2, 8)}`;
    localStorage.setItem(PLAYER_KEY, p);
  }
  return p;
}

export function setPlayerHandle(name: string): void {
  if (typeof window === "undefined") return;
  const clean = name.trim().slice(0, 64);
  if (clean) localStorage.setItem(PLAYER_KEY, clean);
}

export function useChallenges() {
  const [data, setData] = useState<ChallengeListResponse | null>(null);
  const [leaderboard, setLeaderboard] = useState<LeaderboardResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const player = getPlayerHandle();
      const [list, lb] = await Promise.all([
        api.getChallenges(player),
        api.getLeaderboard(),
      ]);
      setData(list);
      setLeaderboard(lb);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load challenges");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { data, leaderboard, loading, error, refresh };
}

export function useChallenge(slug: string) {
  const [challenge, setChallenge] = useState<ChallengeSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<FlagSubmitResponse | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setChallenge(await api.getChallenge(slug, getPlayerHandle()));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load challenge");
    } finally {
      setLoading(false);
    }
  }, [slug]);

  useEffect(() => {
    load();
  }, [load]);

  const submit = useCallback(
    async (flag: string) => {
      const res = await api.submitFlag(slug, flag, getPlayerHandle());
      setResult(res);
      if (res.correct) await load();
      return res;
    },
    [slug, load]
  );

  return { challenge, loading, error, result, submit };
}
