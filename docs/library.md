# TypeScript and JavaScript library

The package exposes a small, synchronous ESM API on Node.js 22 or later. It uses the same offline scanner and
finding format as the CLI. The API is beta; automatic shared-agent sandbox enforcement is future work and is not included.
The package has no npm runtime dependencies.

## Install from the local release candidate

No version is published yet. Build and pack a trusted checkout using the [development setup](../CONTRIBUTING.md#development-setup):

```sh
npm run build
npm run check-files
npm pack --ignore-scripts
```

In the consuming project:

```sh
npm install --ignore-scripts /absolute/path/to/wormsign-0.1.0.tgz
node node_modules/wormsign/examples/scan.mjs /path/to/project
```

The tarball includes [JavaScript](../examples/scan.mjs) and [TypeScript](../examples/scan.mts) examples. TypeScript
consumers need their usual TypeScript compiler and Node type declarations (`@types/node`); these are development
tools, not runtime dependencies of wormsign.

## Scan a project

```ts
import { scan, gateExitCode } from "wormsign";
import type { ScanResult } from "wormsign";

const result: ScanResult = scan("/path/to/project");
process.exitCode = gateExitCode(result.findings); // default threshold: high
```

`scan(root, options?)` reads a directory and returns:

| Field | Meaning |
|---|---|
| `findings` | `Finding[]`: rule ID, severity, message, fingerprint, key and optional file/line/source |
| `filesScanned` | Number of files visited |
| `filesIgnored` | Zero for this API; repository ignore/baseline rules are not applied |
| `notes` | IOC source and scanner coverage limits; retain these alongside findings |

| Option | Default | Meaning |
|---|---|---|
| `nodeModules` | `false` | Also inspect installed package manifests |
| `hashAll` | `false` | Hash all files within the scanner's existing byte limits |
| `registryHosts` | `[]` | Additional trusted registry hostnames, without schemes or paths; standard npm/Yarn hosts remain allowed |
| `iocsDirectory` | Bundled data | Explicit trusted IOC directory in the [existing format](iocs.md) |

The default uses only the IOC data bundled with the installed release. It does not read the user's update cache.
An explicit IOC directory replaces the bundled selection, as `--iocs` does for the CLI; its contents are trusted
input and should be controlled by the integration owner. No IOC or advisory refresh runs implicitly.

The library does not use a project's `.wormsign-baseline.json` as suppression policy or accept `baseline`/`ignorePrefixes` options.
Repository content cannot suppress its own findings through this API. The CLI's explicit baseline workflow
remains available for reviewed exceptions.

## Errors and reports

Bad options, a missing root or invalid IOC data throw `UsageError`. An unreadable or unparseable project input
the scanner should check produces a finding, usually WS-SC-900, following the existing [fail-closed rules](adr/0001-fail-closed.md).
Other unexpected exceptions should be treated as failed checks by the caller.

`gateExitCode(findings, failOn?)` returns `0` below the threshold and `1` at or above it. The threshold is
`info | low | medium | high | critical | never`; invalid JavaScript values throw `UsageError`.

`renderReport(report, format)` formats the same `Report` as the CLI, using `human | json | sarif`:

```ts
import { scan, renderReport } from "wormsign";

const result = scan("/path/to/project");
const sarif = renderReport({
  command: "scan",
  findings: result.findings,
  notes: result.notes,
  toolVersion: "0.1.0",
}, "sarif");
```

Named runtime exports are `scan`, `gateExitCode`, `renderReport` and `UsageError`. Type exports are `ScanOptions`,
`ScanResult`, `Finding`, `Severity`, `Report` and `Format`. Deep package imports are unsupported; the export map
keeps implementation internals out of the public module interface. It is not a filesystem access control.

## Agent integration boundary

An agent adapter can call this API and consume findings directly, without parsing terminal output or spawning a
CLI. Scanning does not run package scripts, write project files, start subprocesses or use the network. It is
synchronous and can block the calling event loop while it reads a large tree; a worker is appropriate for a
long-lived service.

An empty finding list or exit zero is **not permission to install or execute code**. This API does not check
release age or live malware advisories, verify every package artifact, isolate workloads or intercept installers.
Bundled IOC data can become outdated. Use the CLI's [soak gate](soak.md) for the checks it supports; automatic
shared-sandbox enforcement is a separate milestone in the [roadmap](../ROADMAP.md).

The package smoke test installs the actual tarball offline, runs the shipped examples on clean and inert positive
controls, and type-checks an external consumer. See [release readiness](release-readiness.md) for the remaining gates.
