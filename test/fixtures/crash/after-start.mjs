// Preload for test/cli-output.test.ts (node --import): once wormsign's CLI has set its process-level handlers, throw
// from a callback (CRASH=throw) or reject a promise nobody awaits (CRASH=reject), as a socket callback can. Without
// handlers it throws after two seconds anyway, so Node's own exit code shows.
const start = Date.now();
const t = setInterval(() => {
  if (process.listenerCount("uncaughtException") === 0 && Date.now() - start < 2000) return;
  clearInterval(t);
  if (process.env.CRASH === "reject") void Promise.reject(new Error("injected rejection"));
  else setImmediate(() => {
    throw new Error("injected crash\n::error::second line");
  });
}, 1);
