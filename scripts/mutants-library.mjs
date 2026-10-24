// Public API behavior and consumer packaging. Each reversion runs the complete suite.
export default [
  ["library scan drops observed findings", "src/index.ts", "return { ...result, notes: [...iocs.notes, ...result.notes] };", "return { ...result, findings: [], notes: [...iocs.notes, ...result.notes] };"],
  ["library scan uses ambient IOC selection", "src/index.ts", "const iocs = loadIocs({ dir: options.iocsDirectory ?? bundledIocDir });", "const iocs = loadIocs();"],
  ["library scan ignores explicit context options", "src/index.ts", "makeContext(iocs, options)", "makeContext(iocs)"],
  ["library scan ignores installed-package requests", "src/index.ts", "{ nodeModules: options.nodeModules ?? false }", "{ nodeModules: false }"],
  ["library scan accepts invalid JavaScript options", "src/index.ts", "  validate(root, options);\n", ""],
  ["library gate accepts an invalid severity", "src/index.ts", '  if (failOn !== "never") parseSeverity(failOn);\n', ""],
  ["library gate ignores findings", "src/index.ts", "return reportGateExitCode(findings, failOn);", "return reportGateExitCode([], failOn);"],
  ["library package omits generated declarations", "tsconfig.json", '"declaration": true', '"declaration": false'],
  ["library public import invokes the CLI", "package.json", '"import": "./dist/src/index.js"', '"import": "./dist/src/cli.js"'],
  ["library package exposes internal deep imports", "package.json", '"exports": {', '"x-internal-exports": {'],
  ["library example emits unsafe repository text", "examples/scan.mjs", "const encode = report => renderReport({ command: \"scan\", toolVersion: \"0.1.0\", ...report }, \"json\");", "const encode = report => JSON.stringify({ tool: \"wormsign\", version: \"0.1.0\", command: \"scan\", ...report }, null, 2) + \"\\n\";"],
];
