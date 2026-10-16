/**
 * Name and version in an npm-registry tarball URL: `<registry>/<name>/-/<unscoped name>-<version>.tgz`.
 * The lockfile's own name and version need not match it. With a cold cache npm 10, yarn 1.22 and pnpm 10.18
 * install the tarball at the URL whatever the lockfile says (pnpm 11.16 refuses the mismatch); npm installs
 * by integrity when that content is already in its cache. Either may be the installed package.
 */
export function registryTarball(url: string): { name: string; version: string } | undefined {
  let path: string;
  try {
    path = decodeURIComponent(new URL(url).pathname); // old lockfiles encode the scope's slash as %2f
  } catch {
    return undefined;
  }
  const m = /\/((?:@[^/]+\/)?([^/@]+))\/-\/\2-(\d[^/]*)\.tgz$/.exec(path);
  return m ? { name: m[1] as string, version: m[3] as string } : undefined;
}
