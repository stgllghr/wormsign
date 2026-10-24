// After installing a locally built tarball: node node_modules/wormsign/examples/scan.mjs /path/to/project
import { scan, gateExitCode, renderReport, UsageError } from "wormsign";

const encode = report => renderReport({ command: "scan", toolVersion: "0.1.0", ...report }, "json");

try {
  const root = process.argv[2];
  if (!root) throw new UsageError("usage: scan.mjs <project-directory>");
  const result = scan(root);
  process.stdout.write(encode({
    findings: result.findings, notes: result.notes,
    extra: { filesScanned: result.filesScanned, filesIgnored: result.filesIgnored },
  }));
  process.exitCode = gateExitCode(result.findings);
} catch (error) {
  process.stderr.write(encode({ findings: [], notes: [], extra: { error: error instanceof Error ? error.message : String(error) } }));
  process.exitCode = 2;
}
