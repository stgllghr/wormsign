import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { correlationAlerts, isMap, parseYamlDocuments, ruleMatches, type SigmaEvent, type Yaml, type YamlMap } from "./sigma-subset.js";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const DIR = join(ROOT, "detections");

/** ATT&CK Enterprise v19.2 techniques, each opened on attack.mitre.org on 2026-10-02. Check a new one there before adding it. */
const VERIFIED_ATTACK = new Map([
  ["T1036.005", "Masquerading: Match Legitimate Resource Name or Location"],
  ["T1098", "Account Manipulation"],
  ["T1102.002", "Web Service: Bidirectional Communication"],
  ["T1105", "Ingress Tool Transfer"],
  ["T1195.001", "Supply Chain Compromise: Compromise Software Dependencies and Development Tools"],
  ["T1528", "Steal Application Access Token"],
  ["T1546.016", "Event Triggered Execution: Installer Packages"],
  ["T1552.001", "Unsecured Credentials: Credentials In Files"],
  ["T1567.001", "Exfiltration Over Web Service: Exfiltration to Code Repository"],
  ["T1677", "Poisoned Pipeline Execution"],
]);

/**
 * Event names copied from GitHub's org and enterprise "Audit log events" pages (enterprise-cloud@latest, 2026-10-02;
 * rechecked 2026-10-14). workflows.prepared_workflow_job (with job_workflow_ref, runner_name and secrets_passed) and
 * enterprise.self_hosted_runner_online (with runner_name) were added from the same pages, retrieved 2026-10-15.
 */
const VERIFIED_AUDIT_EVENTS = new Set([
  "repo.access",
  "repo.create",
  "repo.register_self_hosted_runner",
  "org.register_self_hosted_runner",
  "enterprise.register_self_hosted_runner",
  "repo.self_hosted_runner_online",
  "org.self_hosted_runner_online",
  "enterprise.self_hosted_runner_online",
  "workflows.created_workflow_run",
  "workflows.delete_workflow_run",
  "workflows.prepared_workflow_job",
]);

const REQUIRED = ["id", "title", "severity", "description", "attack", "data_source", "logic", "false_positives", "sources", "examples"];
/** Fields of every Sigma rule that raises an alert. A base rule that a correlation counts carries none of the metadata. */
const SIGMA_REQUIRED = ["title", "id", "name", "status", "description", "references", "author", "date", "tags", "falsepositives", "level", "examples"];
const SIGMA_META = ["status", "references", "author", "date", "tags", "falsepositives", "level", "examples"];
/** The reference conversions committed next to each Sigma rule file: sigma-cli target and file extension. */
const BACKENDS = [
  ["splunk", "spl"],
  ["esql", "esql"],
] as const;

interface Field {
  inline: string;
  body: string[];
}

/**
 * Splits a CI detection file into its top-level keys. Not a YAML parser: the files keep to `key: value`,
 * `key: |` / `key: >-` blocks and `- item` lists, which is all this needs (and keeps the repo dependency-free).
 */
function topLevel(text: string): Map<string, Field> {
  const out = new Map<string, Field>();
  let cur: Field | undefined;
  for (const line of text.split("\n")) {
    if (line.startsWith("#") || line.trim() === "") continue;
    const m = /^([a-z_]+):(.*)$/.exec(line);
    if (m) out.set(m[1] as string, (cur = { inline: (m[2] as string).trim(), body: [] }));
    else cur?.body.push(line);
  }
  return out;
}

function unquote(v: string): string {
  if (v.startsWith('"')) return JSON.parse(v) as string;
  if (v.startsWith("'")) return v.slice(1, -1).replaceAll("''", "'");
  return v;
}

/** A field counts as missing when it has no value: absent, empty, or a bare `|` / `>-` block indicator with nothing under it. */
const isEmpty = (f: Field | undefined): boolean => !f || (f.body.length === 0 && (f.inline === "" || /^[|>][-+]?$/.test(f.inline)));

const items = (f: Field): string[] => f.body.filter((l) => l.startsWith("  - ")).map((l) => unquote(l.slice(4).trim()));

/** `- id: x` / `  url: y` entries of a list of maps. */
function entries(f: Field): Record<string, string>[] {
  const out: Record<string, string>[] = [];
  for (const l of f.body) {
    const m = /^ {2}(- | {2})([a-z_]+): (.*)$/.exec(l);
    if (!m) continue;
    if (m[1] === "- ") out.push({});
    const last = out.at(-1);
    if (last) last[m[2] as string] = unquote(m[3] as string);
  }
  return out;
}

/** The lines of a `positive: |`, `negative: |`, `known_miss: |` or `known_false_positive: |` block under `examples`. */
function example(f: Field, kind: "positive" | "negative" | "known_miss" | "known_false_positive"): string[] {
  const start = f.body.indexOf(`  ${kind}: |`);
  if (start < 0) return [];
  const out: string[] = [];
  for (const l of f.body.slice(start + 1)) {
    if (!l.startsWith("    ")) break;
    out.push(l.slice(4));
  }
  return out;
}

function stringsIn(v: unknown): string[] {
  if (typeof v === "string") return [v];
  if (Array.isArray(v)) return v.flatMap(stringsIn);
  if (v && typeof v === "object") return Object.values(v).flatMap(stringsIn);
  return [];
}

function checkAttack(id: string, name: string | undefined, url: string | undefined): string[] {
  if (!/^T\d{4}(\.\d{3})?$/.test(id)) return [`ATT&CK id ${id} has the wrong shape`];
  const known = VERIFIED_ATTACK.get(id);
  if (!known) return [`ATT&CK id ${id} is not in the verified list`];
  const out: string[] = [];
  if (name !== undefined && name !== known) out.push(`ATT&CK ${id} name should be "${known}"`);
  if (url !== undefined && url !== `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`) out.push(`ATT&CK ${id} url does not match the id`);
  return out;
}

/** A CI detection: wormsign's own format, with one regular expression applied line by line. */
function checkDetection(file: string, text: string): string[] {
  const doc = topLevel(text);
  const problems = REQUIRED.filter((k) => isEmpty(doc.get(k))).map((k) => `missing ${k}`);
  const get = (k: string): Field => doc.get(k) ?? { inline: "", body: [] };

  const id = get("id").inline;
  if (!/^WS-CI-\d{3}$/.test(id) || !basename(file).startsWith(id.toLowerCase())) problems.push(`id ${id} must be WS-CI-nnn and prefix the file name`);
  if (!["low", "medium", "high", "critical"].includes(get("severity").inline)) problems.push("severity must be low/medium/high/critical");

  const attack = entries(get("attack"));
  if (attack.length === 0) problems.push("attack needs at least one technique");
  for (const a of attack) {
    if (a["name"] === undefined || a["url"] === undefined) problems.push(`ATT&CK ${a["id"]} needs a name and a url`);
    problems.push(...checkAttack(a["id"] ?? "", a["name"], a["url"]));
  }

  const sources = items(get("sources"));
  if (sources.length === 0) problems.push("sources needs at least one link");
  for (const s of sources) if (!/^https:\/\/\S+$/.test(s)) problems.push(`source ${s} is not an https URL`);
  if (items(get("false_positives")).length === 0) problems.push("false_positives needs at least one entry");

  const pos = example(get("examples"), "positive");
  const neg = example(get("examples"), "negative");
  if (pos.length === 0 || neg.length === 0) problems.push("examples needs positive and negative lines");

  const re = new RegExp(unquote(get("pattern").inline));
  for (const l of pos) if (!re.test(l)) problems.push(`pattern misses positive example: ${l}`);
  for (const l of neg) if (re.test(l)) problems.push(`pattern matches negative example: ${l}`);
  // Documented misses are pinned so the docs that describe them cannot go stale.
  for (const l of example(get("examples"), "known_miss")) if (re.test(l)) problems.push(`pattern now matches known miss, update the docs: ${l}`);
  // So are documented false positives: a pattern that no longer matches one must update its false_positives note.
  for (const l of example(get("examples"), "known_false_positive")) if (!re.test(l)) problems.push(`pattern no longer matches known false positive, update the docs: ${l}`);

  for (const l of get("iocs").body) {
    const m = /^ {2}- (data\/iocs\/[a-z]+\.json): (.+)$/.exec(l);
    if (!m) {
      problems.push(`malformed ioc reference: ${l}`);
      continue;
    }
    const values = stringsIn(JSON.parse(readFileSync(join(ROOT, m[1] as string), "utf8")));
    const want = unquote(m[2] as string);
    if (!values.includes(want)) problems.push(`ioc "${want}" is not in ${m[1]}`);
  }
  return problems;
}

// --- Sigma rules: detections/github-audit-log/ and detections/sigma/ ------------------------------------------------

const hasValue = (v: Yaml | undefined): boolean => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && v.length === 0);
const strings = (v: Yaml | undefined): string[] => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]).map(String);
const eventsOf = (block: Yaml | undefined): SigmaEvent[] =>
  typeof block === "string"
    ? block
        .split("\n")
        .filter((l) => l.trim() !== "")
        .map((l) => JSON.parse(l) as SigmaEvent)
    : [];
/** The names of the base rules the correlations in a file count. */
const referencedNames = (docs: YamlMap[]): Set<string> => new Set(docs.flatMap((d) => (isMap(d["correlation"]) ? strings(d["correlation"]["rules"]) : [])));

/** Every value a rule's detection compares the field `field` with. */
function detectionValues(doc: YamlMap, field: string): string[] {
  const detection = doc["detection"];
  if (!isMap(detection)) return [];
  return Object.values(detection).flatMap((sel) => (isMap(sel) ? Object.entries(sel).flatMap(([k, v]) => (k.split("|")[0] === field ? strings(v) : [])) : []));
}

/** Runs one alerting rule over its examples: every positive must alert and no negative may; for a correlation each is one stream. */
function exampleProblems(doc: YamlMap, byName: Map<string, YamlMap>): string[] {
  const name = String(doc["name"]);
  const ex = doc["examples"];
  const pos = eventsOf(isMap(ex) ? ex["positive"] : undefined);
  const neg = eventsOf(isMap(ex) ? ex["negative"] : undefined);
  if (pos.length === 0 || neg.length === 0) return [`${name}: examples needs positive and negative events`];
  const problems: string[] = [];
  if (doc["correlation"] !== undefined) {
    const hit = new Set(correlationAlerts(doc, byName, pos).flatMap((a) => [...a]));
    for (const [i, e] of pos.entries()) if (!hit.has(i)) problems.push(`${name}: misses positive example in its correlation: ${JSON.stringify(e)}`);
    const alerts = correlationAlerts(doc, byName, neg);
    const first = [...(alerts[0] ?? [])].map((i) => neg[i]);
    if (alerts.length > 0) problems.push(`${name}: negative examples raise ${alerts.length} correlation alert(s), the first over ${JSON.stringify(first)}`);
  } else {
    for (const e of pos) if (!ruleMatches(doc, e)) problems.push(`${name}: misses positive example: ${JSON.stringify(e)}`);
    for (const e of neg) if (ruleMatches(doc, e)) problems.push(`${name}: matches negative example: ${JSON.stringify(e)}`);
  }
  return problems;
}

/** Checks the documents of one Sigma rule file: metadata, ATT&CK tags, audit-log actions, and the examples. */
function checkSigmaDocs(file: string, docs: YamlMap[]): string[] {
  const prefix = /^(ws-(?:al|ep)-\d{3})-/.exec(basename(file))?.[1];
  if (!prefix) return [`${basename(file)} must start with ws-al-nnn- or ws-ep-nnn-`];
  const namePrefix = `${prefix.replaceAll("-", "_")}_`;
  const auditLog = basename(dirname(file)) === "github-audit-log";
  const byName = new Map(docs.map((d) => [String(d["name"]), d]));
  const referenced = referencedNames(docs);
  const problems: string[] = [];
  if (byName.size !== docs.length) problems.push("every document needs its own name");

  for (const doc of docs) {
    const name = String(doc["name"]);
    if (!name.startsWith(namePrefix)) problems.push(`name ${name} must start with ${namePrefix}`);
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(String(doc["id"]))) problems.push(`${name}: id must be a UUIDv4`);
    const base = referenced.has(name);
    if (base) {
      if (!hasValue(doc["title"])) problems.push(`missing title in ${name}`);
      for (const k of SIGMA_META) if (doc[k] !== undefined) problems.push(`${name}: a base rule of a correlation must not carry ${k}`);
    } else {
      for (const k of SIGMA_REQUIRED) if (!hasValue(doc[k])) problems.push(`missing ${k} in ${name}`);
      if (!["informational", "low", "medium", "high", "critical"].includes(String(doc["level"]))) problems.push(`${name}: level must be a Sigma level`);
      if (!["stable", "test", "experimental"].includes(String(doc["status"]))) problems.push(`${name}: status must be stable, test or experimental`);
      for (const r of strings(doc["references"])) if (!/^https:\/\/\S+$/.test(r)) problems.push(`${name}: reference ${r} is not an https URL`);
      const techniques = strings(doc["tags"]).filter((t) => /^attack\.t\d/.test(t));
      if (techniques.length === 0) problems.push(`${name}: tags needs at least one attack.tNNNN technique`);
      for (const t of techniques) problems.push(...checkAttack(t.slice("attack.".length).toUpperCase(), undefined, undefined).map((p) => `${name}: ${p}`));
    }

    if (doc["correlation"] !== undefined) {
      if (base) problems.push(`${name}: chained correlations are not used here`);
      if (doc["logsource"] !== undefined || doc["detection"] !== undefined) problems.push(`${name}: a correlation has no logsource or detection`);
      for (const r of isMap(doc["correlation"]) ? strings(doc["correlation"]["rules"]) : []) {
        const target = byName.get(r);
        if (!target || target["correlation"] !== undefined) problems.push(`${name}: correlation rule ${r} is not a base rule in this file`);
      }
    } else {
      const logsource = doc["logsource"];
      const detection = doc["detection"];
      const want: Record<string, string> = auditLog ? { product: "github", service: "audit" } : { category: "process_creation" };
      if (!isMap(logsource) || Object.entries(want).some(([k, v]) => logsource[k] !== v)) problems.push(`${name}: logsource must be ${JSON.stringify(want)}`);
      if (!isMap(detection) || typeof detection["condition"] !== "string") problems.push(`${name}: detection has no condition`);
      if (auditLog) {
        const actions = detectionValues(doc, "action");
        if (actions.length === 0) problems.push(`${name}: the detection must select an audit-log action`);
        for (const a of actions) if (!VERIFIED_AUDIT_EVENTS.has(a)) problems.push(`${name}: event ${a} is not a verified GitHub audit-log event`);
      }
    }

    if (!base && hasValue(doc["examples"])) {
      const ex = doc["examples"];
      for (const e of [...eventsOf(isMap(ex) ? ex["positive"] : undefined), ...eventsOf(isMap(ex) ? ex["negative"] : undefined)]) {
        if (auditLog && !VERIFIED_AUDIT_EVENTS.has(String(e["action"]))) problems.push(`${name}: example action ${String(e["action"])} is not a verified GitHub audit-log event`);
        if (!auditLog && typeof e["Image"] !== "string") problems.push(`${name}: example lacks Image`);
      }
      try {
        problems.push(...exampleProblems(doc, byName));
      } catch (e) {
        problems.push(`${name}: cannot evaluate: ${(e as Error).message}`);
      }
    }
  }
  return problems;
}

function checkSigma(file: string, text: string): string[] {
  let docs: YamlMap[];
  try {
    docs = parseYamlDocuments(text);
  } catch (e) {
    return [`does not parse: ${(e as Error).message}`];
  }
  return checkSigmaDocs(file, docs);
}

const sha256 = (text: string): string => createHash("sha256").update(text).digest("hex");

/** A committed reference conversion must come from the rule file as it is now, and hold a query for each alerting rule. */
function checkReference(ruleText: string, ref: string, backend: string): string[] {
  const problems: string[] = [];
  if (/^# Rule sha256: ([0-9a-f]{64})$/m.exec(ref)?.[1] !== sha256(ruleText)) problems.push(`stale ${backend} reference: regenerate it with detections/tools/convert_rules.py`);
  if (!new RegExp(`^# .*sigma convert -t ${backend} --without-pipeline `, "m").test(ref)) problems.push(`the ${backend} reference does not say how it was generated`);
  const docs = parseYamlDocuments(ruleText);
  const referenced = referencedNames(docs);
  for (const d of docs) {
    const name = String(d["name"]);
    if (!referenced.has(name) && !ref.includes(`\n# ${name}: `)) problems.push(`the ${backend} reference has no query for ${name}`);
  }
  return problems;
}

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)) : e.name.endsWith(".yml") ? [join(dir, e.name)] : []));
}

const all = files(DIR);
const ci = all.filter((f) => basename(dirname(f)) === "ci");
const sigma = all.filter((f) => ["github-audit-log", "sigma"].includes(basename(dirname(f))));
const check = (f: string, text: string): string[] => (sigma.includes(f) ? checkSigma(f, text) : checkDetection(f, text));
const sigmaFile = (prefix: string): string => sigma.find((f) => basename(f).startsWith(prefix)) as string;
const docNamed = (prefix: string, name: string): YamlMap => parseYamlDocuments(readFileSync(sigmaFile(prefix), "utf8")).find((d) => d["name"] === name) as YamlMap;

/** Drops a top-level key and everything indented under it. */
function removeKey(text: string, key: string): string {
  let skipping = false;
  return text
    .split("\n")
    .filter((l) => {
      if (/^[a-z_#]/.test(l)) skipping = l.startsWith(`${key}:`);
      return !skipping;
    })
    .join("\n");
}

test("detections/ covers the audit-log, CI and endpoint content the spec requires", () => {
  const audit = sigma.filter((f) => basename(dirname(f)) === "github-audit-log");
  const actions = new Set(audit.flatMap((f) => parseYamlDocuments(readFileSync(f, "utf8")).flatMap((d) => detectionValues(d, "action"))));
  for (const e of ["repo.access", "repo.create", "repo.register_self_hosted_runner", "workflows.created_workflow_run"]) assert.ok(actions.has(e), e);
  assert.equal(audit.length, 4);
  assert.ok(ci.length >= 4);
  assert.equal(sigma.length - audit.length, 2);
  assert.equal(all.length, ci.length + sigma.length, "every detection file is in a known directory");
});

test("every detection file passes its schema check, and every Sigma rule matches its positive examples and no negative one", () => {
  for (const f of all) assert.deepEqual(check(f, readFileSync(f, "utf8")), [], f);
});

test("detection ids, and Sigma rule ids and names, are unique", () => {
  const ids = ci.map((f) => topLevel(readFileSync(f, "utf8")).get("id")?.inline);
  assert.equal(new Set(ids).size, ids.length);
  const docs = sigma.flatMap((f) => parseYamlDocuments(readFileSync(f, "utf8")));
  assert.equal(new Set(docs.map((d) => d["id"])).size, docs.length);
  assert.equal(new Set(docs.map((d) => d["name"])).size, docs.length);
});

test("removing any required field is reported", () => {
  for (const f of ci) {
    const text = readFileSync(f, "utf8");
    for (const key of REQUIRED) assert.ok(check(f, removeKey(text, key)).includes(`missing ${key}`), `${basename(f)} without ${key}`);
  }
  for (const f of sigma) {
    const text = readFileSync(f, "utf8");
    const docs = parseYamlDocuments(text);
    const referenced = referencedNames(docs);
    for (const [i, doc] of docs.entries()) {
      const name = String(doc["name"]);
      const keys = referenced.has(name) ? ["title"] : SIGMA_REQUIRED.filter((k) => k !== "name");
      for (const key of keys) {
        const copy = parseYamlDocuments(text);
        delete (copy[i] as YamlMap)[key];
        assert.ok(checkSigmaDocs(f, copy).includes(`missing ${key} in ${name}`), `${basename(f)} ${name} without ${key}`);
      }
    }
  }
});

test("bad sources, ATT&CK ids, examples and IOC references are reported", () => {
  const runner = ci.find((f) => basename(f).startsWith("ws-ci-004")) as string;
  const text = readFileSync(runner, "utf8");
  const has = (t: string, needle: string) => check(runner, t).some((p) => p.includes(needle));
  assert.ok(has(text.replace("  - https://unit42", "  - http://unit42"), "not an https URL"));
  assert.ok(has(text.replace("- id: T1102.002", "- id: T1102.2"), "wrong shape"));
  assert.ok(has(text.replace("- id: T1102.002", "- id: T1102.001"), "not in the verified list"));
  assert.ok(has(text.replace("T1102/002/", "T1102/003/"), "url does not match"));
  assert.ok(has(text.replace("--name build-07", '--name "SHA1HULUD"'), "matches negative example"));
  assert.ok(has(text.replace("workflows.json: SHA1HULUD", "workflows.json: SHA1HULUD2"), "is not in data/iocs/workflows.json"));

  assert.ok(has(text.replace(/\n {4}url: https:\/\/attack\.mitre\.org\/techniques\/T1102\/002\//, ""), "needs a name and a url"));
  assert.ok(has(text.replace(/\n {4}name: .*/, ""), "needs a name and a url"));
  assert.ok(has(text.replace(/^logic: \|\n(?: .*\n)+/m, "logic: |\n"), "missing logic"));
  assert.ok(has(text.replace(/^description: >-\n(?: .*\n)+/m, "description: >-\n"), "missing description"));

  const secrets = ci.find((f) => basename(f).startsWith("ws-ci-005")) as string;
  const pinned = readFileSync(secrets, "utf8").replace(/(known_false_positive: \|\n {4}).*/, "$1  token: ***");
  assert.ok(check(secrets, pinned).some((p) => p.includes("no longer matches known false positive")));

  const loader = ci.find((f) => basename(f).startsWith("ws-ci-001")) as string;
  const widened = readFileSync(loader, "utf8").replace("node setup\\.mjs\\b'", "node setup\\.mjs\\b|^> node setup\\.mjs$'");
  assert.ok(check(loader, widened).some((p) => p.includes("now matches known miss")));
});

test("bad Sigma rules are reported: tags, actions, examples, base-rule metadata and constructs the evaluator lacks", () => {
  const al1 = sigmaFile("ws-al-001");
  const ep = sigmaFile("ws-ep-001");
  const has = (f: string, t: string, needle: string) => checkSigma(f, t).some((p) => p.includes(needle));
  const a = readFileSync(al1, "utf8");
  const e = readFileSync(ep, "utf8");
  assert.ok(has(ep, e.replace("attack.t1105", "attack.t9999"), "not in the verified list"));
  assert.ok(has(ep, e.replace(/^description: >-\n(?: .*\n)+/m, "description: >-\n"), "missing description"));
  assert.ok(has(ep, e.replace("  - https://socket.dev", "  - http://socket.dev"), "not an https URL"));
  assert.ok(has(ep, e.replace("id: f73e17d6-c16e-4616-8e66-6c754886cfa1", "id: WS-EP-001"), "UUIDv4"));
  assert.ok(has(ep, e.replace("(parent_shell and install_context and", "(parent_shell and"), "matches negative example"));
  assert.ok(has(ep, e.replace("CommandLine|startswith: 'node '", "CommandLine|re: '^node '"), "cannot evaluate: unsupported modifier |re"));
  assert.ok(has(ep, e.replace("or worm_cache", "or 1 of them"), "cannot evaluate"));
  assert.ok(has(ep, e.replace("level: high", "level: severe"), "level must be a Sigma level"));
  const base = "    action: repo.access\n    visibility: public\n    previous_visibility:\n      - private\n      - internal\n  condition: selection\n---";
  assert.ok(has(al1, a.replace(base, "    action: repo.change_visibility\n    visibility: public\n  condition: selection\n---"), "not a verified GitHub audit-log event"));
  assert.ok(has(al1, a.replace("    gte: 3", "    gte: 4"), "misses positive example in its correlation"));
  assert.ok(has(al1, a.replace("name: ws_al_001_repo_made_public\n", "name: ws_al_001_repo_made_public\nlevel: low\n"), "a base rule of a correlation must not carry level"));
  assert.ok(has(al1, a.replace("    - ws_al_001_repo_made_public\n", "    - ws_al_001_missing\n"), "is not a base rule in this file"));
  assert.ok(has(al1, a.replace("  type: value_count", "  type: value_sum"), "cannot evaluate: unsupported correlation type"));
  assert.ok(has(al1, a.replace("name: ws_al_001_repo_made_public_with_token", "name: wsal001_token"), "must start with ws_al_001_"));
  assert.ok(has(al1, a.replace("previous_visibility:\n      - private", "previous_visibility: [private,"), "does not parse"));
});

test("the Sigma evaluator follows Sigma's matching rules", () => {
  const rule = (detection: YamlMap): YamlMap => ({ name: "t", detection });
  const m = (detection: YamlMap, event: SigmaEvent) => ruleMatches(rule(detection), event);
  // Strings compare case-insensitively; * and ? are wildcards; a backslash escapes only *, ? and itself.
  assert.ok(m({ s: { runner_name: "SHA1HULUD" }, condition: "s" }, { runner_name: "sha1hulud" }));
  assert.ok(!m({ s: { runner_name: "SHA1HULUD" }, condition: "s" }, { runner_name: "SHA1HULUD-2" }));
  assert.ok(m({ s: { a: "x*z" }, condition: "s" }, { a: "xyyz" }));
  assert.ok(!m({ s: { a: "x\\*z" }, condition: "s" }, { a: "xyyz" }));
  assert.ok(m({ s: { a: "x\\*z" }, condition: "s" }, { a: "x*z" }));
  assert.ok(m({ s: { "Image|endswith": "\\bun.exe" }, condition: "s" }, { Image: "C:\\Users\\dev\\.bun\\bin\\bun.exe" }));
  // Lists are OR unless |all; numbers and booleans compare as text; |exists tests presence.
  assert.ok(m({ s: { a: [1, 2] }, condition: "s" }, { a: 2 }));
  assert.ok(!m({ s: { "a|contains|all": ["x", "y"] }, condition: "s" }, { a: "x alone" }));
  assert.ok(m({ s: { b: true }, condition: "s" }, { b: true }));
  assert.ok(!m({ s: { b: true }, condition: "s" }, { b: false }));
  assert.ok(m({ s: { "p|exists": true }, condition: "s" }, { p: "token" }));
  assert.ok(!m({ s: { "p|exists": true }, condition: "s" }, { q: "token" }));
  assert.ok(!m({ s: { a: "x" }, condition: "s" }, {}));
  // "All values are treated as case-insensitive strings" (Sigma rules specification 2.1.0, "General").
  assert.ok(m({ s: { b: true }, condition: "s" }, { b: "TRUE" }));
  assert.ok(m({ s: { n: 1 }, condition: "s" }, { n: "1" }));
  // A list or map in the event fails closed: only |exists may test it.
  assert.throws(() => m({ s: { a: "x" }, condition: "s" }, { a: ["x", "y"] }), /holds a list/);
  assert.throws(() => m({ s: { a: "x" }, condition: "s" }, { a: { b: "x" } }), /holds a map/);
  assert.ok(m({ s: { "a|exists": true }, condition: "s" }, { a: ["x"] }));
  // not binds tighter than and, which binds tighter than or.
  const d = { a: { a: 1 }, b: { b: 1 }, c: { c: 1 } };
  assert.ok(m({ ...d, condition: "a or b and c" }, { a: 1 }));
  assert.ok(!m({ ...d, condition: "(a or b) and c" }, { a: 1 }));
  assert.ok(m({ ...d, condition: "not a and b" }, { b: 1 }));
  assert.ok(m({ ...d, condition: "1 of a*" }, { a: 1 }) && !m({ ...d, condition: "all of a*" }, { b: 1 }));

  // Windows slide rather than fall into clock-hour bins, and value_count counts distinct values case-insensitively.
  const names = new Map([["t", rule({ s: { action: "x" }, condition: "s" })]]);
  const corr = (type: string, condition?: YamlMap): YamlMap => ({ correlation: { type, rules: ["t"], "group-by": ["actor"], timespan: "1h", ...(condition ? { condition } : {}) } });
  const at = (min: number, repo: string, actor = "u"): SigmaEvent => ({ action: "x", actor, repo, "@timestamp": min * 60_000 });
  assert.equal(correlationAlerts(corr("value_count", { field: "repo", gte: 3 }), names, [at(50, "a"), at(70, "b"), at(100, "c")]).length, 1);
  assert.equal(correlationAlerts(corr("value_count", { field: "repo", gte: 3 }), names, [at(0, "a"), at(30, "b"), at(61, "c")]).length, 0);
  assert.equal(correlationAlerts(corr("value_count", { field: "repo", gte: 2 }), names, [at(0, "a"), at(1, "A")]).length, 0);
  assert.equal(correlationAlerts(corr("event_count", { gte: 2 }), names, [at(0, "a"), at(1, "A")]).length, 1);
  assert.equal(correlationAlerts(corr("event_count", { gte: 2 }), names, [at(0, "a"), at(1, "b", "v")]).length, 0);
  // Group-by values are case-insensitive text, as in the SQLite cross-check: 9001 and "9001" are one group.
  const num = (min: number, actor: unknown): SigmaEvent => ({ action: "x", actor, repo: "r", "@timestamp": min * 60_000 });
  assert.equal(correlationAlerts(corr("event_count", { gte: 2 }), names, [num(0, 9001), num(1, "9001")]).length, 1);
  assert.equal(correlationAlerts(corr("event_count", { gte: 2 }), names, [num(0, "Dev"), num(1, "dev")]).length, 1);
  assert.throws(() => correlationAlerts(corr("event_count", { gte: 2 }), names, [num(0, ["dev"])]), /group-by field holds a list/);
  assert.throws(() => correlationAlerts(corr("temporal_ordered"), names, [at(0, "a")]), /unsupported correlation type/);
});

test("the audit-log rules cover every IOC in data/iocs/", () => {
  const iocs = (f: string) => JSON.parse(readFileSync(join(ROOT, "data", "iocs", f), "utf8")) as Record<string, Record<string, string>[]>;
  const online = docNamed("ws-al-002", "ws_al_002_worm_runner_online");
  const runnerNames = iocs("workflows.json")["runnerNames"] ?? [];
  assert.ok(runnerNames.length > 0);
  for (const { name } of runnerNames) {
    for (const action of ["repo.self_hosted_runner_online", "org.self_hosted_runner_online", "enterprise.self_hosted_runner_online", "workflows.prepared_workflow_job"]) {
      assert.ok(ruleMatches(online, { action, runner_name: String(name).toLowerCase() }), `WS-AL-002 misses ${action} for runner ${name}`);
    }
  }
  const repos = iocs("repos.json");
  const created = docNamed("ws-al-003", "ws_al_003_ioc_repo_created");
  assert.ok((repos["patterns"] ?? []).length > 0 && (repos["branches"] ?? []).length > 0);
  for (const p of repos["patterns"] ?? []) {
    const event: SigmaEvent = { action: "repo.create", visibility: "public", repo: "example-org/q7k2m9x4v1b8n3c6z5" };
    if (p["match"] === "nameExact") event["repo"] = `example-org/${p["name"]}`;
    else if (p["match"] === "descriptionExact") event["enriched_description"] = p["description"];
    else if (p["match"] === "descriptionContains") event["enriched_description"] = `Mirror: ${p["description"]} (copy)`;
    else assert.fail(`repos.json pattern ${p["id"]} has match kind ${p["match"]}: add it to WS-AL-003 and to this test`);
    assert.ok(ruleMatches(created, event), `WS-AL-003 misses repos.json pattern ${p["id"]}`);
  }
  const branch = docNamed("ws-al-004", "ws_al_004_worm_branch_run");
  const job = docNamed("ws-al-004", "ws_al_004_worm_branch_job");
  for (const b of repos["branches"] ?? []) {
    const head = String(b["name"]).replace(/\*$/, "1764000000000");
    assert.ok(ruleMatches(branch, { action: "workflows.created_workflow_run", head_branch: head }), `WS-AL-004 misses repos.json branch ${b["name"]}`);
    // job_workflow_ref's form is undocumented: the full ref of the Actions OIDC claim, and the bare branch.
    for (const ref of [`refs/heads/${head}`, head]) {
      const value = `example-org/web/.github/workflows/x.yml@${ref}`;
      assert.ok(ruleMatches(job, { action: "workflows.prepared_workflow_job", job_workflow_ref: value }), `WS-AL-004's job rule misses repos.json branch ${b["name"]} as ${ref}`);
    }
  }
});

test("the README's hunt fetches every action it selects, and its schedules look back a timespan plus an interval", () => {
  const readme = readFileSync(join(DIR, "README.md"), "utf8");
  const hunt = /For a one-off hunt[\s\S]*?```sh\n([\s\S]*?)```/.exec(readme)?.[1] ?? "";
  // The select keeps what WS-AL-002's critical rule matches...
  const selected = [...hunt.matchAll(/\.action == "([\w.]+)"/g)].map((m) => m[1] as string);
  assert.deepEqual([...selected].sort(), detectionValues(docNamed("ws-al-002", "ws_al_002_worm_runner_online"), "action").sort());
  // ...and each action is fetched where GitHub keeps it: enterprise events only in the enterprise audit log.
  const fromOrg = /for a in ([^;]+); do\n\s*gh api --method GET --paginate "\/orgs\/\$ORG\/audit-log" -f phrase="action:\$a /.exec(hunt)?.[1]?.trim().split(/\s+/) ?? [];
  const fromEnterprise = [...hunt.matchAll(/"\/enterprises\/\$ENT\/audit-log" \\\n\s*-f phrase="action:([\w.]+) /g)].map((m) => m[1] as string);
  for (const a of selected) {
    const enterprise = a.startsWith("enterprise.");
    assert.ok((enterprise ? fromEnterprise : fromOrg).includes(a), `the hunt selects ${a} but never fetches it from the ${enterprise ? "enterprise" : "organization"} audit log`);
  }
  assert.ok(fromOrg.every((a) => !a.startsWith("enterprise.")), "the organization audit log holds no enterprise events");

  // A correlation run every interval must look back its timespan plus that interval, and throttle on its group-by
  // fields for as long, or runs count in fixed buckets again (WS-AL-001: 1h, by actor).
  const flip = docNamed("ws-al-001", "ws_al_001_mass_visibility_flip");
  const c = flip["correlation"] as YamlMap;
  const span = /^(\d+)h$/.exec(String(c["timespan"]));
  assert.ok(span, "the README's example assumes a timespan in hours");
  const minutes = Number(span[1]) * 60;
  const num = (re: RegExp): number => Number(re.exec(readme)?.[1] ?? Number.NaN);
  const schedules = {
    splunk: { every: num(/`cron_schedule = \*\/(\d+) \* \* \* \*`/), back: num(/`dispatch\.earliest_time = -(\d+)m`/), suppress: num(/`alert\.suppress\.period = (\d+)m`/) },
    esql: { every: num(/"interval": "(\d+)m"/), back: num(/"from": "now-(\d+)m"/), suppress: num(/suppresses alerts by `\w+` for (\d+) minutes/) },
  };
  for (const [backend, s] of Object.entries(schedules)) {
    assert.ok(s.every > 0 && s.back >= minutes + s.every, `${backend}: a run every ${s.every} minutes must look back at least ${minutes + s.every}, not ${s.back}`);
    assert.ok(s.suppress >= s.back, `${backend}: throttle for the look-back`);
  }
  assert.equal(/`alert\.suppress\.fields = ([\w,]+)`/.exec(readme)?.[1], strings(c["group-by"]).join(","));
  assert.equal(/suppresses alerts by `(\w+)`/.exec(readme)?.[1], strings(c["group-by"]).join(","));
});

test("every Sigma rule file has current Splunk and ES|QL reference conversions", () => {
  for (const f of sigma) {
    const text = readFileSync(f, "utf8");
    for (const [backend, ext] of BACKENDS) {
      const ref = f.replace(/\.yml$/, `.${ext}`);
      assert.ok(existsSync(ref), `${basename(ref)} is missing: run detections/tools/convert_rules.py`);
      assert.deepEqual(checkReference(text, readFileSync(ref, "utf8"), backend), [], ref);
    }
  }
  // The check notices a rule edited after its conversion, and a reference without one of the rule's queries.
  const f = sigmaFile("ws-al-002");
  const text = readFileSync(f, "utf8");
  const ref = readFileSync(f.replace(/\.yml$/, ".spl"), "utf8");
  assert.ok(checkReference(text.replace("runner_name: SHA1HULUD", "runner_name: SHA1HULUD2"), ref, "splunk").some((p) => p.startsWith("stale")));
  assert.ok(checkReference(text, ref.replace("\n# ws_al_002_worm_runner_online: ", "\n# "), "splunk").some((p) => p.includes("no query for ws_al_002_worm_runner_online")));
});
