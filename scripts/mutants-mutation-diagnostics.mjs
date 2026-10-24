export default [
  ["mutation runner mistakes consumer diagnostics for a project build failure", "scripts/mutation-check.mjs", '  const listed = failures(r.stdout ?? "");', '  if (/error TS\\d+/.test(out)) return { status: "no-compile", failed: ["consumer compiler diagnostics"], why: out };\n  const listed = failures(r.stdout ?? "");'],
  ["mutation runner hides unverified process and compilation diagnostics", "scripts/mutation-check.mjs", 'if (r.status === "timeout" || r.status === "no-compile") console.error', 'if (Math.random() < 0) console.error'],
  ["mutation runner drops the process signal from its diagnostic", "scripts/mutation-check.mjs", 'process signal ${r.signal ?? "none"}', 'process signal omitted'],
  ["mutation runner emits unbounded process diagnostic lines", "scripts/mutation-check.mjs", '.map((line) => line.length > 300 ? line.slice(0, 300) + "..." : line)', '.map((line) => line)'],
];
