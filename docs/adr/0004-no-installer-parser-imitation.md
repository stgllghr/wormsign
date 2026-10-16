# ADR 0004: Never imitate an installer's parser to decide coverage

- **Status:** Accepted (0.1.0). Replaces the declared-dependency matching tried before 0.1.0.
- **Date:** 2026-10-14

## Context

Some questions only the installer can answer exactly: which versions `pip install .` resolves, whether `uv.lock` is
stale for its `pyproject.toml`, which script `npm run` reaches. A model of the answer is a second implementation,
and it drifts from the real one. Where the model is wrong, wormsign passes what the installer installs. In a
fail-closed tool that is worse than not checking, because the result looks verified.

**The Python example.** `soak` must decide whether a manifest that declares dependencies (`pyproject.toml`,
`setup.py`, `setup.cfg`, `Pipfile`) is covered by a lock. The first rule went by directory: a lock beside the
manifest covers it. The gap is real. A lock beside a `pyproject.toml` covers it whatever it pins, and
`pip install .` resolves the project's dependencies fresh.

Before 0.1.0, `soak` instead matched declarations against pins. A requirements file or `pylock.toml` covered a
manifest only if, together, they pinned every dependency it declared, by PEP 503 name. That meant reading
`[project]` dependencies, Poetry tables, `setup.cfg`, `Pipfile` and setuptools' dynamic metadata, then markers,
extras, and dependencies computed by `setup.py` and build hooks. Fourteen review rounds each found another case
where wormsign read a manifest, or the build code behind it, differently from pip, uv or a build backend. Each fix
made the model larger.

## Decision

Never close a gap by imitating pip, uv or npm more closely. A heuristic may shape a finding; it never hides one
([AGENTS.md](../../AGENTS.md)).

- Python coverage went back to the directory rule. The revert deleted the declared-dependency reader, the marker
  evaluator and a PEP 440 specifier matcher: 4,755 lines removed and 409 added, tests included.
- Also covering a manifest: a `uv.lock` that lists its directory (a workspace member or path package), and a
  requirements file in a `requirements/` directory beside it. Nothing else: a `pyproject.toml` that names only the
  root project, such as an example beside a library, is uncovered unless the root's lock lists it. A uv source
  pointing at the root binds the root's code, not its dependencies' versions, and pip ignores `[tool.uv.sources]`.
- The gap became a stated boundary. The gate covers installs of the lock as written: install the lock, then the
  project with `pip install --no-deps .` ([soak.md](../soak.md#installing-the-project-itself)).
- `diff` reports any change to a Python manifest, compared whole, at medium or higher.

The same rule applies elsewhere:

- `soak` does not decide whether `uv.lock` is out of date. `uv sync --locked` does that.
- Python install settings are collected, not resolved. Any non-default index fails closed.
- Every editor or agent auto-run entry is high, whatever its command. Telling a harmless command from a harmful one
  would mean modelling `npm run`, shell quoting and config redirects
  ([architecture.md](../architecture.md#every-editor-or-agent-auto-run-entry-is-high-instead-of-interpreting-commands)).

## Consequences

- Known gaps are written down, not hidden: Python limitations 1 and 12 in
  [soak.md](../soak.md#python-limitations).
- Users must install with the forms the docs name. A resolving install is outside the gate.
- Less code to audit, and no drift as pip and uv change.

## Alternatives considered

- **Keep the declared-dependency matching and keep fixing it.** Rejected. Every round found a new divergence, and
  each one not yet found is a silent pass.
- **Ask the installer**, for example a dry-run resolve of the project. Rejected. Preparing a local project's
  metadata runs its build backend and `setup.py`, so the gate would run the change's code
  ([ADR 0002](0002-pr-gate-built-from-base.md)).
