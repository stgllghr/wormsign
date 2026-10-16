import { UsageError } from "./types.js";

const UNIT_MS: Record<string, number> = {
  s: 1000, sec: 1000, secs: 1000, second: 1000, seconds: 1000,
  m: 60_000, min: 60_000, mins: 60_000, minute: 60_000, minutes: 60_000,
  h: 3_600_000, hr: 3_600_000, hrs: 3_600_000, hour: 3_600_000, hours: 3_600_000,
  d: 86_400_000, day: 86_400_000, days: 86_400_000,
  w: 604_800_000, week: 604_800_000, weeks: 604_800_000,
};

/** "72h", "3d", "1 week", "90m" -> milliseconds. A bare number is rejected: the unit would be a guess. */
export function parseDuration(input: string): number {
  const m = /^\s*(\d+(?:\.\d+)?)\s*([a-z]+)\s*$/i.exec(input);
  const unit = m ? UNIT_MS[(m[2] as string).toLowerCase()] : undefined;
  if (!m || unit === undefined) throw new UsageError(`invalid duration "${input}" (examples: 72h, 3d, 1w)`);
  const ms = Math.round(Number(m[1]) * unit);
  if (ms <= 0) throw new UsageError(`duration must be positive: "${input}"`);
  return ms;
}

export function formatDuration(ms: number): string {
  const h = ms / 3_600_000;
  return h >= 48 ? `${(h / 24).toFixed(1)}d` : h >= 1 ? `${h.toFixed(1)}h` : `${Math.round(ms / 60_000)}m`;
}
