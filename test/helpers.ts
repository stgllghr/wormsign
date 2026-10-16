import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { makeContext } from "../src/checks/context.js";
import { loadIocDir } from "../src/iocs.js";
import type { IO } from "../src/main.js";

export const FIXTURES = fileURLToPath(new URL("../../test/fixtures/", import.meta.url));
export const GOLDEN = fileURLToPath(new URL("../../test/golden/", import.meta.url));
export const fx = (...p: string[]): string => join(FIXTURES, ...p);

export const testIocs = () => loadIocDir(fx("iocs"));
export const testCtx = (extra: Parameters<typeof makeContext>[1] = {}) => makeContext(testIocs(), extra);

export const NOW = new Date("2026-10-01T12:00:00Z");

export function fakeIO(over: Partial<IO> = {}): IO & { out: string; err: string } {
  const io = {
    out: "",
    err: "",
    stdout(s: string) {
      io.out += s;
    },
    stderr(s: string) {
      io.err += s;
    },
    env: {} as Record<string, string | undefined>,
    now: () => NOW,
    // No real waits in tests: soak's registry retry would otherwise sleep for seconds.
    sleep: async () => undefined,
    ...over,
  };
  return io;
}
