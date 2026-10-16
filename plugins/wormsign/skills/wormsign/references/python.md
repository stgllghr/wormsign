# pip and uv

## Install from the lock
- uv: `uv sync --locked` installs exactly what `uv.lock` lists, the project included, and fails when `uv.lock` is
  out of date (`--frozen` installs the lock without checking it).
- pip: `pip install --require-hashes --no-deps -r requirements.txt`, from a file with a `--require-hashes` line and
  every requirement `name==<version>` with `--hash=sha256:` hashes; `--no-deps` resolves nothing outside it.
- pip 26.1 or newer: `pip install -r pylock.toml` (experimental in pip) installs a PEP 751 lock. pip resolves it in
  hash-checking mode, so a dependency the lock leaves out fails the install.
- uv 0.12.0 or newer: `uv pip sync requirements.txt`. Older uv ignores `--require-hashes` inside the file: use pip.
Check the lock first when wormsign is installed: `wormsign soak && uv sync --locked`.

## Installing the project itself
`wormsign soak` checks a lock in the project's directory (or in a `requirements/` directory beside it), but a plain
`pip install .` or `pip install -e .` chooses its own versions for the project's dependencies. In the project's
virtual environment (activate it, or create it), install the lock, then the project without its dependencies:
```sh
python3 -m venv .venv && . .venv/bin/activate
pip install --require-hashes --no-deps -r requirements.txt
pip install --no-deps -e .
```
`pip install --no-deps .` (no `-e`) builds and installs a copy instead. With uv and a `uv.lock`, `uv sync --locked`
installs both. Either way, building the project installs its build requirements fresh ("Builds" below).

## Adding a package
1. Check its PyPI page for the upload date of the exact version and for the project's source repository.
2. Add it pinned, without installing or building it: `uv add --no-sync --no-build <name>==<version>` (without
   them, uv installs into the environment and runs the `setup.py` of a package published only as source, before any
   check), or add the pinned, hashed line to the requirements lock. If uv refuses because the package has no wheel,
   ask the user: do not drop `--no-build` or add the `--frozen` its error suggests.
3. Run `wormsign soak` on the changed lock.
4. Only after the soak passes, install from the lock: `uv sync --locked`, or
   `pip install --require-hashes --no-deps -r requirements.txt`.
Write a requirements lock with `pip-compile --generate-hashes --no-emit-options --pip-args "--only-binary :all:"` or
`uv pip compile --no-build --generate-hashes`, then add a `--require-hashes` line. Both refuse a package published
only as source instead of building it: then ask the user. `--no-emit-options` should keep out the `--only-binary`
line `wormsign soak` refuses (pip-compile's help; no recorded run): check. Keep its name `requirements.txt` (or
another `*requirements*.txt`) so `wormsign soak` reads it. If the project's own metadata is `dynamic`, the uv add and
pip-compile commands above still build the project itself to read it, installing its build requirements fresh: the
build limitation under "Builds" below. So for such a project, ask the user before running either: each builds it.

## Poetry, PDM and pipenv
`wormsign soak` does not read `poetry.lock`, `pdm.lock` or `Pipfile.lock` yet (each is WS-SK-002). Export a
hash-locked requirements file or a `pylock.toml` from it, then install and soak that; if unsure how, ask the user.

## Builds (WS-SK-005)
Installing an sdist, or the project itself, builds it, and a build first installs its build requirements, which no
lock pins: the installer resolves them fresh, protected only by its own cooldown and `==`-pinned build constraints.
`wormsign soak` reports the builds it can see as WS-SK-005, none for a project that no `uv.lock` or `pylock.toml`
lists; there `wormsign diff` reports an edit to a build file (`[build-system]`, `setup.py`, `setup.cfg`, a hook; not
what they read or import) as WS-DF-005. Avoid a build where you can: `uv sync --locked --no-install-project`, or
`[tool.uv] package = false`. Report either finding to the user; do not baseline it yourself.

## Release-age cooldown (7 days)
- pip 26.1 or newer: `uploaded-prior-to = P7D` under `[global]` in pip's user config, or `--uploaded-prior-to P7D`.
- uv 0.9.17 or newer: `exclude-newer = "7 days"` at the top of `uv.toml`.
On locked installs they apply to `pip install --require-hashes -r` and `uv pip sync` of a requirements file (a pin
younger than the cutoff fails, unless that version is already installed); `uv sync --locked` fails when the cutoff
differs from the one `uv.lock` records, but does not re-check a lock that records the same one; pip 26.2 checks a
`pylock.toml`'s own `upload-time` fields, which whoever wrote the lock wrote; they have no effect on
`uv sync --frozen`, `uv run --frozen` or `pip install -r pylock.toml` with pip 26.1. `wormsign soak` checks every
locked version either way.

## Running a tool
`uvx`, `uv tool run` and `pipx run` use their own environment, never the lock: ask first. A locked tool runs as
`.venv/bin/<tool>` without asking, failing if the lock lacks it. Ask before installing from git, a URL or an archive.
