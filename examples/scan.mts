// Type-check with TypeScript and @types/node installed in the consuming project.
import { scan, gateExitCode, renderReport, UsageError } from "wormsign";
import type { ScanOptions, ScanResult, Report } from "wormsign";

const encode = (report: Omit<Report, "command" | "toolVersion">) => renderReport({ command: "scan", toolVersion: "0.1.0", ...report }, "json");

try {
  const root = process.argv[2];
  if (!root) throw new UsageError("usage: scan.mts <project-directory>");
  const options: ScanOptions = { nodeModules: false, hashAll: false };
  const result: ScanResult = scan(root, options);
  process.stdout.write(encode({
    findings: result.findings, notes: result.notes,
    extra: { filesScanned: result.filesScanned, filesIgnored: result.filesIgnored },
  }));
  process.exitCode = gateExitCode(result.findings);
} catch (error) {
  process.stderr.write(encode({ findings: [], notes: [], extra: { error: error instanceof Error ? error.message : String(error) } }));
  process.exitCode = 2;
}
