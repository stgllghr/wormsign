// Mutants for the Action's private-registry inputs (action.yml, scripts/ci-action.mjs): registry-host reaches scan and
// diff as one --registry-host per comma-separated host and never soak, registry reaches soak as --registry, and a
// value with a line break, an empty entry or a space inside an entry is an error, not a value passed on.
// scripts/mutation-check.mjs loads every scripts/mutants-<module>.mjs and says how they run; a module holds at most
// 18 mutants.
//
/** [name, file, search, replace]: each keeps the script running and changes one decision. */
export default [
  ["action registry: registry-host does not reach scan", "scripts/ci-action.mjs", 'if (command === "scan" || command === "diff") for (const host of registryHosts)', 'if (command === "diff") for (const host of registryHosts)'],
  ["action registry: registry-host does not reach diff", "scripts/ci-action.mjs", 'if (command === "scan" || command === "diff") for (const host of registryHosts)', 'if (command === "scan") for (const host of registryHosts)'],
  ["action registry: registry-host reaches soak too", "scripts/ci-action.mjs", 'if (command === "scan" || command === "diff") for (const host of registryHosts)', "for (const host of registryHosts)"],
  ["action registry: registry does not reach soak", "scripts/ci-action.mjs", '    if (registry) args.push("--registry", registry);\n', ""],
  ["action registry: registry-host is not split on commas", "scripts/ci-action.mjs", 'return v.split(",").map((entry) => {', "return [v].map((entry) => {"],
  ["action registry: a line break in an input is accepted", "scripts/ci-action.mjs", "if (/[\\r\\n\\u2028\\u2029]/.test(v)) throw", "if (Math.random() < 0) throw"],
  ["action registry: an empty registry-host entry is passed on", "scripts/ci-action.mjs", 'if (e === "" || /\\s/.test(e)) throw', "if (/\\s/.test(e)) throw"],
  ["action registry: a registry-host entry with a space is passed on", "scripts/ci-action.mjs", 'if (e === "" || /\\s/.test(e)) throw', 'if (e === "") throw'],
  ["action.yml: registry-host does not reach the script", "action.yml", "        WS_REGISTRY_HOST: ${{ inputs.registry-host }}\n", ""],
  ["action.yml: registry does not reach the script", "action.yml", "        WS_REGISTRY: ${{ inputs.registry }}\n", ""],
];
