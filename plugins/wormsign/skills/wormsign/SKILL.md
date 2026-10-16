---
name: wormsign
description: Precautions for installing, adding, updating or removing npm, pnpm, Yarn, bun, pip or uv packages, changing a lockfile, setting up a JavaScript or Python development environment, installing a command-line tool from npm or PyPI (npm install -g, pipx install, uv tool install), running a package with npx, pnpm dlx, bunx, uvx or pipx, or running an install script piped from curl or wget into a shell (curl | sh, wget | bash), and how to check them with wormsign (soak, diff, scan). Use before any such install, dependency change, install script, or npx, dlx, bunx, uvx or pipx run, including of a project's own tool.
license: MIT
---

# Installing packages safely

Supply-chain worms spread through packages that run code at install or import time, usually within hours or days
of being published. These rules keep installs to versions that are old enough, locked and checked. The exact
commands are in the reference files listed under "References" at the end: open the one that fits before you act.

## Rules

1. Install from the lockfile. Never let an install choose new versions:
   - npm: `npm ci --ignore-scripts`; pnpm: `pnpm install --frozen-lockfile --ignore-scripts`; Yarn 2+:
     `YARN_ENABLE_SCRIPTS=false yarn install --immutable`; bun: `bun install --frozen-lockfile --ignore-scripts`
   - uv: `uv sync --locked`; pip: `pip install --require-hashes --no-deps -r <hash-locked file>`
   - a Python project itself: in its virtual environment (create one with `python3 -m venv .venv`), install its
     lock first, then `pip install --no-deps -e .` (`pip install --no-deps .` to build or install a copy instead). A
     plain `pip install .` or `pip install -e .` chooses its own versions for the project's dependencies, outside
     what wormsign checks.
2. Keep install scripts off and the release-age cooldown (7 days) on. Never turn either off to make an install work.
   A package that needs its install script (esbuild, sharp, prisma, puppeteer) is approved on its own, and only
   with the user's OK: references/npm.md, "Packages that need install scripts".
3. Before adding or upgrading a package, prefer a dependency the project already has. Then check the new one: it
   passes when all of these hold, and you ask the user only when one fails or cannot be checked:
   - the exact name is the one the user asked for, or a well-known package's (a judgement call): typosquats differ
     by one letter, a hyphen or a scope;
   - the version was published at least 7 days ago;
   - the package links a source repository;
   - it is not deprecated;
   - it was first published at least 30 days ago, or the user named it (30 days is a judgement call, not one of
     wormsign's settings).
   Then pin the exact version and write it into the lockfile without installing or building it (commands in the
   references); with a tool that cannot do that (Yarn Classic, a bun without `--lockfile-only`, a Python package
   published only as source), ask the user first.
4. After a lockfile changes and before installing from it, run `wormsign soak` if wormsign is installed. For a
   branch, also run `wormsign soak --base <base>` and `wormsign diff <base> HEAD`. On a high or critical finding,
   stop: report it and do not install.
5. A dependency's bin runs without asking only after the lockfile install (rule 1; if you have not run it in this
   session, run it first), as `./node_modules/.bin/<bin>`, or through `npm run <script>` after reading that script
   and its pre and post scripts (if one runs npx, npm exec, a dlx, an install or a download, rules 5 and 6 apply to
   it); a Python tool from the lock, as `.venv/bin/<tool>`. Never through `npx` or `npm exec`, even with `--no`: npm
   can still install the project itself, or run a same-named bin from a parent folder, the global folder or its cache
   (references/npm.md). Ask the user before anything that downloads and runs
   a package (npx, npm exec, pnpm dlx, bunx, uvx, pipx run) other than as rule 6 says, and before you install from a
   URL, git or a tarball, pipe curl or wget into a shell, or use sudo for an install.
6. Installing a command-line tool outside a project (`npm install -g`, `npx <name>@<version>`, `pipx install`,
   `uv tool install`, or `pip install <name>` into a throwaway virtual environment): check it as rule 3 checks a
   new dependency, and ask the user first unless they named the tool and every check passes. Either way, say which
   exact version you install and when it was published. Use an exact version published at least 7 days ago, with
   install scripts and source builds off, and a 7-day cooldown for its dependencies, which no lock pins:
   - npm: `npm install -g --ignore-scripts --min-release-age=7 <name>@<version>`, or
     `npx --ignore-scripts --min-release-age=7 <name>@<version>`. npm reads `--min-release-age` from 11.10; below
     that, use `--before=<the date 7 days ago, YYYY-MM-DD>` instead, or say that its dependencies are not aged
   - pipx: `pipx install --pip-args="--only-binary :all:" <name>==<version>`, adding `--cooldown 7` if
     `pipx install --help` lists `--cooldown`
   - uv 0.9.17 or newer: `uv tool install --no-build --exclude-newer "7 days" <name>==<version>`
   - pip 26.1 or newer, with the virtual environment's own pip:
     `pip install --only-binary :all: --uploaded-prior-to P7D <name>==<version>`
   If the tool fails without its install script, or has no wheel to install, ask the user; do not turn scripts or
   builds back on.
7. Read-only checks need no permission: `wormsign soak`, `diff` and `scan`; `harden-dev.sh` without `--apply`;
   looking up a package's metadata. Ask before anything that changes protection: adding an entry to
   `.wormsign-baseline.json`, running `harden-dev.sh --apply`, editing `~/.npmrc`, `pip.conf`, `uv.toml` or other
   user-level installer settings, turning install scripts back on, shortening a cooldown, or installing despite a
   finding.
8. If wormsign is not installed, follow these rules by hand. Tell the user once per session, not each time this
   skill is used, that wormsign can check them (https://github.com/stgllghr/wormsign/blob/main/docs/installation.md).
   Do not install wormsign yourself.

## When something fails

- A cooldown refuses a version: wait, or choose an older version. Do not shorten the cooldown without asking.
- A lockfile install fails because the lock is out of date: tell the user. Do not fall back to a resolving install.
- A wormsign finding: what to do depends on its rule ID (references/wormsign.md). A malware record (WS-OS-001) is
  a compromise: stop and tell the user at once. A check wormsign could not make is never a pass.
- A finding looks wrong: report it with its rule ID and ask. Only the user approves a baseline entry.

## References

- references/npm.md: npm, pnpm, Yarn and bun. Installing from the lockfile, adding a package without installing
  it, approving one package's install script, cooldown settings, running a project's bin, running a package with
  npx, dlx or bunx.
- references/python.md: pip and uv. Installing from a lock, installing the project itself in its virtual
  environment, adding a package, Poetry, PDM and Pipfile locks, builds from source, cooldowns.
- references/wormsign.md: running soak, diff and scan, reading their output and exit codes, what to do for each
  kind of finding, the baseline, `--no-baseline`, IOC updates.
- references/ci.md: the pull-request gate in GitHub Actions, the jobs that wait for it, the scheduled re-check,
  pinning, checking a committed copy of this skill.
- references/environment.md: `harden-dev.sh`, user-level cooldown settings, the npm and Node versions that
  enforce them, tokens.
