#!/usr/bin/env node
import { EXIT, run } from "./main.js";
import { neutralise } from "./report.js";

// An exception thrown from an event callback (Node 24's undici on a socket the server reset, for one) or a promise
// nobody awaits escapes run()'s own catch, and Node would end the process with code 1, which here means findings at
// the threshold, with no report. It is an internal error: exit 2, as run() gives one.
const crash = (e: unknown): void => {
  const message = e instanceof Error ? e.message : String(e);
  process.stderr.write(`wormsign: internal error: ${message.split("\n").map(neutralise).join("\n")}\n`);
  process.exit(EXIT.ERROR);
};
process.on("uncaughtException", crash);
process.on("unhandledRejection", crash);

const code = await run(process.argv.slice(2), {
  stdout: (s) => void process.stdout.write(s),
  stderr: (s) => void process.stderr.write(s),
  env: process.env,
  now: () => new Date(),
  stdoutIsTTY: process.stdout.isTTY === true,
});
process.exitCode = code;
