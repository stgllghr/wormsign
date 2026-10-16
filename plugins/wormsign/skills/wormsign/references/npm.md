# npm, pnpm, Yarn and bun

## Install from the lockfile
- npm: `npm ci --ignore-scripts`
- pnpm: `pnpm install --frozen-lockfile --ignore-scripts` (pnpm before 10 runs dependency scripts by default, and
  10.0 to 10.25 run a git dependency's `prepare`, fixed in 10.26.0)
- Yarn 2+: `YARN_ENABLE_SCRIPTS=false yarn install --immutable` (`enableScripts` set from the environment, no file)
- Yarn Classic: `yarn install --frozen-lockfile --ignore-scripts`
- bun: `bun install --frozen-lockfile --ignore-scripts` (without it, bun runs the scripts of its built-in list of
  trusted packages; `ignoreScripts = true` under `[install]` in `bunfig.toml` makes that the project's default)
Check the lockfile first when wormsign is installed: `wormsign soak && npm ci --ignore-scripts`. If the install
fails because the lockfile is out of date, tell the user; never fall back to `npm install`, which resolves versions.

## Release-age cooldown (7 days)
Set it in the project, where the package manager reads it, so every developer and CI install gets it:
- npm: `min-release-age=7` in `.npmrc` (days; enforced from npm 11.10, older npm ignores it)
- pnpm: `minimumReleaseAge: 10080` in `pnpm-workspace.yaml` (minutes)
- Yarn: `npmMinimalAgeGate: 10080` in `.yarnrc.yml` (minutes, Yarn 4.10 or newer; write bare minutes: Yarn 4.10
  reads `3d` as 3 minutes). Yarn Classic has none: `wormsign soak` in CI is its only gate.
- bun: `minimumReleaseAge = 604800` under `[install]` in `bunfig.toml` (seconds)
`wormsign soak --config-only` checks these settings offline. An exemption (`minimumReleaseAgeExclude`,
`npmPreapprovedPackages`, `minimumReleaseAgeExcludes`, npm's `min-release-age-exclude`) is a hole in the gate:
never add one without asking. Most package managers do not apply the cooldown to a version already in the
lockfile: that is what `wormsign soak` checks.

## Adding a package
1. `npm view <name> time --json` shows when each version was published (`created` is the first);
   `npm view <name>@<version> repository deprecated` shows its source repository and whether it is deprecated.
2. Write it into the lockfile, pinned, without installing it (a plain add of a name installs it before any check):
   - npm: `npm install --package-lock-only --save-exact --ignore-scripts <name>@<version>`
   - Yarn 2+: `yarn add --exact --mode=update-lockfile <name>@<version>`
   - bun: `bun add --exact --lockfile-only --ignore-scripts <name>@<version>`, if `bun add --help` lists
     `--lockfile-only`; if it does not, ask the user before adding a package with bun; it installs as it adds.
   - pnpm: its docs give its add command no lock-only option, and it installs as it adds. Write the exact version
     into `package.json` yourself, then run `pnpm install --lockfile-only --ignore-scripts`, which writes only
     `pnpm-lock.yaml` and `package.json`.
   - Yarn Classic: ask the user before adding a package with Yarn Classic; it installs as it adds.
3. Run `wormsign soak` on the changed lockfile (on a branch, `wormsign soak --base <base>` too).
4. Only after the soak passes, install from the lockfile: `npm ci --ignore-scripts`, or the pnpm, Yarn or bun
   command under "Install from the lockfile".

## Packages that need install scripts
Some packages (esbuild, sharp, prisma, puppeteer) need their install script to work. Scripts stay off for the rest;
approve one package at a time, never all at once:
1. Check the package as SKILL.md rule 3 says, and read its install script: `npm view <name>@<version> scripts`
   names it, and after the lockfile install the file it runs is under `node_modules/<name>/`.
2. Ask the user, naming the package, its version and what the script does. Approve it only on a yes.
3. Approve that one package:
   - npm: after `npm ci --ignore-scripts`, run `npm rebuild <name> --ignore-scripts=false`, which runs that
     package's scripts only (a plain `npm rebuild <name>` runs nothing while `ignore-scripts=true` is set). npm 12
     blocks unapproved scripts itself: run `npm install-scripts approve <name>` first.
   - pnpm 11, and pnpm 10 from 10.26: `<name>: true` under `allowBuilds:` in `pnpm-workspace.yaml`; older pnpm 10:
     `- <name>` under `onlyBuiltDependencies:` there (pnpm 11 removed that key). Then `pnpm rebuild <name>`.
   - Yarn 2+: with scripts off (`YARN_ENABLE_SCRIPTS=false` or `enableScripts: false`), add
     `"dependenciesMeta": { "<name>": { "built": true } }` to `package.json`: Yarn builds only the ones so marked.
   - bun: `bun pm trust <name>` runs its scripts and adds it to `trustedDependencies`, replacing bun's default list.
   - Yarn Classic has none of its own: with npm 11 or older, the npm command above, on its `node_modules`.
Never approve every package (`dangerouslyAllowAllBuilds`, `--dangerously-allow-all-scripts`, `bun pm trust --all`).

## Running a package
A dependency's bin needs no permission after this session's `npm ci --ignore-scripts`, as `./node_modules/.bin/<bin>`
or `npm run <script>` once you have read it and its `pre`/`post` scripts (npm runs those too, and searches the
project's `node_modules/.bin`, then its parents'). Never `npx` or `npm exec`, even with `--no`: before npm reads it,
it installs the project into its cache when the project's own `bin` has that name (dependencies resolved fresh), and
runs a same-named bin from a parent folder's `node_modules/.bin`, the global folder or its cache. Ask before anything
that downloads and runs a package, or installs from git, a URL or a tarball: `wormsign soak` cannot age-check those.
