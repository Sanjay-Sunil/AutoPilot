/** Exponential backoff with full jitter: 0.5s, 1s, 2s ... capped at 30s. */
export function backoffMs(attempt: number, rand: () => number = Math.random): number {
  const base = Math.min(30_000, 500 * 2 ** Math.min(attempt, 10));
  return Math.round(base / 2 + rand() * (base / 2));
}
