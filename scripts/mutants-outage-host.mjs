// Mutants for what makes an outage a host's (src/net.ts OutageLedger): every answer from the registry, the Python
// index and OSV is recorded, a host that answered gets its claims back as fail-closed findings, a host that never
// answered is probed once with HEAD on its root (no redirect followed), a failure after a status line is never an
// outage, and OSV follows no redirect. scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how
// they run; a module holds at most 18 mutants.
//
/** [name, file, search, replace]: each keeps the code compiling and changes one decision. */
export default [
  ["outage host: the registry's answers are not recorded", "src/soak.ts", "if (!isTransientStatus(res.status)) opts.outages?.answered(host);", ""],
  ["outage host: the index's answers are not recorded", "src/python/index.ts", "if (!isTransientStatus(res.status)) opts.outages?.answered(new URL(url).host);", ""],
  ["outage host: OSV's answers are not recorded", "src/osv.ts", "      opts.outages?.answered(OSV_HOST);\n", ""],
  ["outage host: a host that answered still gets the warn findings", "src/net.ts", "      if (this.#answered.has(c.host)) {", "      if (Math.random() < 0) {"],
  ["outage host: a host that never answered is not probed", "src/net.ts", "if (this.#answered.has(c.host) || this.#probed.has(c.host)) continue;", "continue;"],
  ["outage host: a probe answered 404 counts as out", "src/net.ts", "if (!PROBE_DOWN.has(res.status)) this.answered(c.host);", "if (res.status < 400) this.answered(c.host);"],
  ["outage host: a probe answered 501 (no HEAD) counts as out", "src/net.ts", "if (!PROBE_DOWN.has(res.status)) this.answered(c.host);", "if (!isTransientStatus(res.status)) this.answered(c.host);"],
  ["outage host: a probe rejected for its certificate counts as out", "src/net.ts", "if (transportFailure(e) === undefined) this.answered(c.host);", ""],
  ["outage host: the probe follows a redirect", "src/net.ts", '{ method: "HEAD", redirect: "manual", signal', '{ method: "HEAD", signal'],
  ["outage host: the registry calls a failure after a status line an outage", "src/soak.ts", "const outage = status ? undefined : transportFailure(e);", "const outage = transportFailure(e);"],
  ["outage host: the index calls a failure after a status line an outage", "src/python/index.ts", "const outage = status ? undefined : transportFailure(e);", "const outage = transportFailure(e);"],
  ["outage host: OSV calls a failure after a status line an outage", "src/osv.ts", "outage = status ? undefined : transportFailure(e);", "outage = transportFailure(e);"],
  ["outage host: OSV follows a redirect", "src/osv.ts", '        redirect: "manual",\n', ""],
];
