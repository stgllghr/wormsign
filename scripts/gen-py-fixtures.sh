#!/usr/bin/env bash
# Regenerates the Python reader fixtures with pinned real tools, and records what those tools read in the corpora the
# tests compare against offline. Maintainer script: network (pypi.org, files.pythonhosted.org), not run in CI.
#
# Writes (replacing them):
#   test/fixtures/python/locks/        uv.lock, PEP 723 script locks and pylock.toml files written by uv 0.10.9 and
#                                      0.12.21 and by pip 26.2.1, plus forged/ variants derived from them;
#                                      forged/uv-script-reads.json records how both uvs read each script in forged/scripts/
#   test/fixtures/python/requirements/ a requirements corpus (corpus/), what pip 26.2.1's parser reads in each file
#                                      (pip-26.2.1.json) and what `uv pip sync --dry-run` of both uvs would install
#                                      (uv-pip-sync.json)
#   test/fixtures/python/simple/       PEP 691 Simple JSON responses for the projects the locks use, from pypi.org
#
# Tools are installed into a temporary directory from PyPI with pip --require-hashes (hashes below, from the PyPI
# Simple API), and every tool runs with HOME, XDG_*, the pip and uv caches and pip's config pointed into that
# directory, so nothing reads or writes the user's own configuration. Locks resolve with --exclude-newer
# 2026-10-01T00:00:00Z, so the same versions come back on a later run. Only benign, long-published projects are
# locked: six, idna, packaging, certifi and markupsafe. Tool versions follow wormsign's own 7-day soak: each was
# published at least 7 days before 2026-10-08 (uv 0.12.21 on 2026-09-29; 0.12.22 and 0.12.23, published on 2026-10-02
# and 2026-10-03, were too new). The design named uv 0.12.23 and pip 26.1.2 as well: no real-tool lock of revision 4
# or 5 is here until a uv that writes one clears the soak (0.12.23 wrote revision 5 and clears it at
# 2026-10-10T17:31Z), and pip 26.1.2's reading is not recorded.
#
# Usage: scripts/gen-py-fixtures.sh   (from the repository root; macOS arm64/x86_64 or Linux x86_64/aarch64)
set -euo pipefail

repo="$(pwd)"
if [ ! -f "$repo/package.json" ] || [ ! -d "$repo/test/fixtures" ]; then
  echo "run from the repository root" >&2
  exit 2
fi
command -v python3 > /dev/null || { echo "python3 is required" >&2; exit 2; }

EXCLUDE_NEWER="2026-10-01T00:00:00Z"
PIP_VERSION="26.2.1"
PIP_SHA256="71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e"
UV_VERSIONS=("0.10.9" "0.12.21")

# sha256 of the uv wheel for this platform, per version (PyPI Simple API, 2026-10-08).
uv_wheel_sha256() {
  case "$1/$(uname -s)/$(uname -m)" in
    0.10.9/Darwin/arm64) echo a7a784254380552398a6baf4149faf5b31a4003275f685c28421cf8197178a08 ;;
    0.10.9/Darwin/x86_64) echo 880dd4cffe4bd184e8871ddf4c7d3c3b042e1f16d2682310644aa8d61eaea3e6 ;;
    0.10.9/Linux/x86_64) echo 7c9d6deb30edbc22123be75479f99fb476613eaf38a8034c0e98bba24a344179 ;;
    0.10.9/Linux/aarch64) echo 5ea0e8598fa012cfa4480ecad4d112bc70f514157c3cc1555a7611c7b6b1ab0a ;;
    0.12.21/Darwin/arm64) echo eb4f75e8ed770e1f142e03a134b9507e7f4710c4b2cec385d4bf8c5810a91094 ;;
    0.12.21/Darwin/x86_64) echo 9c6fab087f35c8f8c0c79ad4c8a94f6804b983369c2887250fb753a70d8080fd ;;
    0.12.21/Linux/x86_64) echo 0083454d25479f1cd03547c8c98c235b4af92bd07f0e61c3eae5d1cbb0c1834c ;;
    0.12.21/Linux/aarch64) echo b7db8b4913e6cd34e6aabbe08ff82fbac7c1edae57747ea23118ca460f060d44 ;;
    *) echo "no pinned uv $1 wheel for $(uname -s)/$(uname -m)" >&2; return 1 ;;
  esac
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/home" "$work/xdg/config" "$work/xdg/cache" "$work/xdg/data" "$work/tools" "$work/out"
export HOME="$work/home" XDG_CONFIG_HOME="$work/xdg/config" XDG_CACHE_HOME="$work/xdg/cache" XDG_DATA_HOME="$work/xdg/data"
export PIP_CONFIG_FILE=/dev/null PIP_CACHE_DIR="$work/xdg/cache/pip" PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1
export UV_CACHE_DIR="$work/xdg/cache/uv" UV_PYTHON_DOWNLOADS=never UV_NO_PROGRESS=1
unset VIRTUAL_ENV PYTHONPATH PYTHONHOME PIP_INDEX_URL PIP_EXTRA_INDEX_URL UV_INDEX_URL UV_EXTRA_INDEX_URL UV_INDEX UV_DEFAULT_INDEX UV_EXCLUDE_NEWER UV_CONFIG_FILE
if [ -e /etc/uv/uv.toml ]; then echo "/etc/uv/uv.toml exists and would apply to uv; remove it or run elsewhere" >&2; exit 2; fi

# ---- tools ----
python3 -m venv "$work/tools/py"
py="$work/tools/py/bin/python"
printf '%s\n' "--require-hashes" "--only-binary :all:" "pip==$PIP_VERSION --hash=sha256:$PIP_SHA256" > "$work/tools/pip.txt"
"$py" -m pip install -q --no-deps -r "$work/tools/pip.txt"
[ "$("$py" -m pip --version | cut -d' ' -f2)" = "$PIP_VERSION" ] || { echo "pip is not $PIP_VERSION" >&2; exit 1; }
export UV_PYTHON="$py"
for v in "${UV_VERSIONS[@]}"; do
  printf '%s\n' "--require-hashes" "--only-binary :all:" "uv==$v --hash=sha256:$(uv_wheel_sha256 "$v")" > "$work/tools/uv-$v.txt"
  "$py" -m pip install -q --no-deps --target "$work/tools/uv-$v" -r "$work/tools/uv-$v.txt"
  got="$("$work/tools/uv-$v/bin/uv" --version | cut -d' ' -f2)"
  [ "$got" = "$v" ] || { echo "uv is $got, not $v" >&2; exit 1; }
done
"$work/tools/uv-0.12.21/bin/uv" venv -q --python "$py" "$work/tools/target"

out="$work/out"
mkdir -p "$out/locks" "$out/requirements/corpus/included" "$out/simple"

# ---- uv projects, locked and exported by each uv ----
project() { # project <dir>: writes the pyproject files of one fixture project into <dir>
  local d="$1"
  case "$(basename "$d")" in
    simple)
      printf '%s\n' '[project]' 'name = "demo-simple"' 'version = "0.1.0"' 'requires-python = ">=3.9"' 'dependencies = ["six==1.17.0", "idna>=3.7"]' > "$d/pyproject.toml" ;;
    fork)
      # Different markupsafe requirements per Python version make uv fork: two [[package]] entries for one name.
      printf '%s\n' '[project]' 'name = "demo-fork"' 'version = "0.1.0"' 'requires-python = ">=3.8"' 'dependencies = [' \
        "    \"markupsafe>=2.1,<3 ; python_version < '3.10'\"," "    \"markupsafe>=3.0.3 ; python_version >= '3.10'\"," '    "six==1.17.0",' ']' > "$d/pyproject.toml" ;;
    editable)
      mkdir -p "$d/packages/member"
      printf '%s\n' '[project]' 'name = "demo-editable"' 'version = "0.1.0"' 'requires-python = ">=3.9"' 'dependencies = ["packaging==25.0", "member"]' '' \
        '[build-system]' 'requires = ["hatchling"]' 'build-backend = "hatchling.build"' '' '[tool.uv.workspace]' 'members = ["packages/member"]' '' \
        '[tool.uv.sources]' 'member = { workspace = true }' > "$d/pyproject.toml"
      printf '%s\n' '[project]' 'name = "member"' 'version = "0.2.0"' 'requires-python = ">=3.9"' 'dependencies = ["certifi"]' '' \
        '[build-system]' 'requires = ["hatchling"]' 'build-backend = "hatchling.build"' > "$d/packages/member/pyproject.toml" ;;
    path)
      mkdir -p "$d/vendor" "$d/libs/localdir"
      printf '%s\n' "six==1.17.0 --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274" > "$work/six.txt"
      "$py" -m pip download -q --no-deps --only-binary :all: --require-hashes -r "$work/six.txt" -d "$d/vendor"
      printf '%s\n' '[project]' 'name = "demo-path"' 'version = "0.1.0"' 'requires-python = ">=3.9"' 'dependencies = ["six", "localdir"]' '' \
        '[tool.uv]' 'package = false' '' '[tool.uv.sources]' 'six = { path = "vendor/six-1.17.0-py2.py3-none-any.whl" }' \
        'localdir = { path = "libs/localdir", editable = false }' > "$d/pyproject.toml"
      printf '%s\n' '[project]' 'name = "localdir"' 'version = "1.0.0"' 'requires-python = ">=3.9"' 'dependencies = ["idna==3.10"]' '' \
        '[build-system]' 'requires = ["hatchling"]' 'build-backend = "hatchling.build"' > "$d/libs/localdir/pyproject.toml" ;;
  esac
}

for v in "${UV_VERSIONS[@]}"; do
  uv="$work/tools/uv-$v/bin/uv"
  for name in simple fork editable path; do
    d="$out/locks/uv-$v/$name"
    mkdir -p "$d"
    project "$d"
    # --no-build: these projects have static metadata, so no build backend ever runs.
    (cd "$d" && "$uv" lock -q --no-build --exclude-newer "$EXCLUDE_NEWER")
  done
  (cd "$out/locks/uv-$v/simple" && "$uv" export -q --frozen --format pylock.toml -o pylock.toml && "$uv" export -q --frozen --format requirements-txt -o requirements.txt)
  d="$out/locks/uv-$v/script"
  mkdir -p "$d"
  # CRLF line endings, a uv shebang and the cutoff inside the block: the lock records it.
  printf '%s\r\n' '#!/usr/bin/env -S uv run --script' '# /// script' '# requires-python = ">=3.9"' '# dependencies = [' '#     "six==1.17.0",' \
    '#     "certifi",' '# ]' '# [tool.uv]' "# exclude-newer = \"$EXCLUDE_NEWER\"" '# ///' 'import six' 'print(six.PY3)' > "$d/example.py"
  (cd "$d" && "$uv" lock -q --no-build --script example.py)
done

# pip lock (marked experimental by pip): no index, no upload-time, this platform's wheels only.
d="$out/locks/pip-$PIP_VERSION/lock"
mkdir -p "$d"
printf '%s\n' 'six==1.17.0' 'idna==3.10' 'certifi' > "$d/requirements.in"
(cd "$d" && "$py" -m pip lock -q --only-binary :all: --uploaded-prior-to "$EXCLUDE_NEWER" -r requirements.in -o pylock.toml)

# ---- forged variants for reader problems, derived from the uv 0.12.21 and pip outputs ----
"$py" - "$out/locks" <<'PY'
import hashlib, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
forged = root / "forged"
forged.mkdir()
simple = (root / "uv-0.12.21/simple/uv.lock").read_text()
pylock = (root / "uv-0.12.21/simple/pylock.toml").read_text()
piplock = (root / f"pip-26.2.1/lock/pylock.toml").read_text()
SIX_WHL = "sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274"
SIX_SDIST = "sha256:ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81"
assert SIX_WHL in simple and SIX_SDIST in simple

def sub(text, old, new, count=1):
    assert text.count(old) >= 1, old
    return text.replace(old, new, count)

def six_block(text):
    start = text.index('[[package]]\nname = "six"')
    return start, text.index("\n\n", start) if "\n\n" in text[start:] else len(text)

uv = {
    "uv-sha512-only-wheel.lock": sub(simple, SIX_WHL, "sha512:" + hashlib.sha512(b"six wheel").hexdigest()),
    "uv-unhashed-wheel.lock": sub(simple, f', hash = "{SIX_WHL}"', ""),
    "uv-uppercase-hash.lock": sub(simple, SIX_WHL, SIX_WHL.upper().replace("SHA256", "sha256")),
    "uv-unknown-file-key.lock": sub(simple, f'hash = "{SIX_WHL}"', f'hash = "{SIX_WHL}", signature = "x"'),
    "uv-unknown-package-key.lock": sub(simple, 'name = "six"\nversion = "1.17.0"\n', 'name = "six"\nversion = "1.17.0"\ninstall-hook = "x"\n'),
    "uv-unknown-source.lock": sub(simple, 'name = "six"\nversion = "1.17.0"\nsource = { registry = "https://pypi.org/simple" }', 'name = "six"\nversion = "1.17.0"\nsource = { svn = "https://example.invalid/six" }'),
    "uv-registry-and-path-source.lock": sub(simple, 'name = "six"\nversion = "1.17.0"\nsource = { registry = "https://pypi.org/simple" }', 'name = "six"\nversion = "1.17.0"\nsource = { registry = "https://pypi.org/simple", path = "vendor/six.whl" }'),
    "uv-unknown-top-key.lock": sub(simple, "requires-python", 'install-from = "elsewhere"\nrequires-python'),
    "uv-distribution-tables.lock": simple.replace("[[package]]", "[[distribution]]"),
    "uv-version-2.lock": sub(simple, "version = 1\n", "version = 2\n"),
    "uv-revision-99.lock": sub(simple, "revision = 3\n", "revision = 99\n"),
    "uv-revision-5.lock": sub(simple, "revision = 3\n", "revision = 5\n"),
    "uv-no-revision.lock": sub(simple, "revision = 3\n", ""),
    "uv-missing-version.lock": sub(simple, 'name = "six"\nversion = "1.17.0"\n', 'name = "six"\n'),
    "uv-oversized-size.lock": sub(simple, "size = 11050", "size = 9007199254740993"),
    "uv-duplicate-key.lock": sub(simple, 'name = "six"\nversion = "1.17.0"\n', 'name = "six"\nversion = "1.17.0"\nversion = "1.16.0"\n'),
    "uv-bom.lock": "\ufeff" + simple,
    # uv reads the first of url, path and filename (WheelWire, SourceDist); the reader refuses more than one.
    "uv-wheel-url-and-filename.lock": sub(simple, f'hash = "{SIX_WHL}"', f'filename = "six-1.16.0-py2.py3-none-any.whl", hash = "{SIX_WHL}"'),
    "uv-sdist-url-and-path.lock": sub(simple, f'hash = "{SIX_SDIST}"', f'path = "vendor/six-1.16.0.tar.gz", hash = "{SIX_SDIST}"'),
}
start, end = six_block(simple)
block = simple[start:end]
nofiles = "\n".join(l for l in block.split("\n") if not l.startswith(("sdist =", "wheels =", "    {", "]")))
uv["uv-no-files.lock"] = simple[:start] + nofiles + simple[end:]
git = nofiles.replace('source = { registry = "https://pypi.org/simple" }', 'source = { git = "https://github.com/benjaminp/six?tag=1.17.0#2b9bd1ba1ee9e3f1a6c7a1d1b6b6a7c3f7f2a1c0" }')
uv["uv-git-source.lock"] = simple[:start] + git + simple[end:]
for name, text in uv.items():
    (forged / name).write_text(text, encoding="utf-8", newline="")

PL_WHL = 'hashes = { sha256 = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274" }'
assert PL_WHL in pylock
pl = {
    "pylock-sha512-only.toml": sub(pylock, PL_WHL, 'hashes = { sha512 = "' + hashlib.sha512(b"six wheel").hexdigest() + '" }'),
    "pylock-empty-hashes.toml": sub(pylock, PL_WHL, "hashes = {}"),
    "pylock-uppercase-algorithm.toml": sub(pylock, PL_WHL, PL_WHL.replace("sha256", "SHA256")),
    "pylock-no-version.toml": sub(pylock, 'name = "six"\nversion = "1.17.0"\n', 'name = "six"\n'),
    "pylock-unknown-package-key.toml": sub(pylock, 'name = "six"\nversion = "1.17.0"\n', 'name = "six"\nversion = "1.17.0"\nbuild-script = "x"\n'),
    "pylock-unknown-file-key.toml": sub(pylock, PL_WHL, PL_WHL + ', signature = "x"'),
    "pylock-lock-version-2.toml": sub(pylock, 'lock-version = "1.0"', 'lock-version = "2.0"'),
    "pylock-lock-version-1-1.toml": sub(pylock, 'lock-version = "1.0"', 'lock-version = "1.1"'),
    "pylock-sdist-and-archive.toml": sub(pylock, 'name = "six"\nversion = "1.17.0"\n', 'name = "six"\nversion = "1.17.0"\narchive = { path = "vendor/six-1.17.0-py2.py3-none-any.whl", hashes = { sha256 = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274" } }\n'),
    "pylock-bom.toml": "\ufeff" + pylock,
    # pip and uv install from the path when a file has both; the reader refuses both.
    "pylock-url-and-path.toml": sub(pylock, PL_WHL, 'path = "vendor/six-1.16.0-py2.py3-none-any.whl", ' + PL_WHL),
}
start = pylock.index('[[packages]]\nname = "six"')
pl["pylock-no-files.toml"] = pylock[:start] + '[[packages]]\nname = "six"\nversion = "1.17.0"\nindex = "https://pypi.org/simple"\n'
pl["pylock-local-sources.toml"] = pylock[:start] + "\n".join([
    '[[packages]]', 'name = "six"', 'version = "1.17.0"',
    'archive = { path = "vendor/six-1.17.0-py2.py3-none-any.whl", hashes = { sha256 = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274" } }', '',
    '[[packages]]', 'name = "localdir"', 'directory = { path = "libs/localdir", editable = false }', '',
    '[[packages]]', 'name = "six-git"', 'vcs = { type = "git", url = "https://github.com/benjaminp/six", commit-id = "2b9bd1ba1ee9e3f1a6c7a1d1b6b6a7c3f7f2a1c0" }', ''])
pl["pylock-wheel-name-override.toml"] = piplock.replace('name = "six-1.17.0-py2.py3-none-any.whl"', 'name = "six-1.16.0-py2.py3-none-any.whl"')
for name, text in pl.items():
    (forged / name).write_text(text, encoding="utf-8", newline="")

# PEP 723 scripts: what uv does with each is recorded below.
DEPS = "# /// script\n# dependencies = [\"six==1.17.0\"]\n# ///\n"
scripts = {
    "script-lf.py": "import os\n" + DEPS + "print(1)\n",
    "script-crlf.py": (DEPS + "print(1)\n").replace("\n", "\r\n"),
    "script-bare-cr.py": (DEPS + "print(1)\n").replace("\n", "\r"),
    "script-bom.py": "\ufeff" + DEPS + "print(1)\n",
    "script-indented.py": "  " + DEPS + "print(1)\n",
    "script-trailing-space.py": DEPS.replace("# /// script\n", "# /// script \n") + "print(1)\n",
    "script-unclosed.py": "# /// script\n# dependencies = [\"six==1.17.0\"]\nprint(1)\n",
    "script-bad-toml.py": "# /// script\n# dependencies = [\"six==1.17.0\"\n# ///\nprint(1)\n",
    "script-two-blocks.py": DEPS + "print(1)\n" + DEPS.replace("six==1.17.0", "idna==3.10") + "print(2)\n",
    "script-tag-in-string.py": "x = '# /// script'\n" + DEPS + "print(1)\n",
    "script-none.py": "print('no block')\n",
    "script-closing-twice.py": "# /// script\n# dependencies = [\"six==1.17.0\"]\n# ///\n#\n# ///\nprint(1)\n",
}
(forged / "scripts").mkdir()
for name, text in scripts.items():
    (forged / "scripts" / name).write_text(text, encoding="utf-8", newline="")
PY

# How each uv reads each script: the requirements `uv lock --script` locks, or its first error line.
"$py" - "$out/locks/forged/scripts" "$work" "$EXCLUDE_NEWER" "${UV_VERSIONS[@]}" <<'PY'
import json, pathlib, shutil, subprocess, sys, tomllib
scripts, work, cutoff, versions = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3], sys.argv[4:]
result = {}
for script in sorted(scripts.glob("*.py")):
    entry = {}
    for v in versions:
        tmp = work / "script-read"
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir()
        shutil.copy(script, tmp / script.name)
        r = subprocess.run([str(work / f"tools/uv-{v}/bin/uv"), "lock", "-q", "--no-build", "--exclude-newer", cutoff, "--script", script.name], cwd=tmp, capture_output=True, text=True)
        lock = tmp / (script.name + ".lock")
        if r.returncode == 0 and lock.exists():
            manifest = tomllib.loads(lock.read_text()).get("manifest", {})
            entry[f"uv-{v}"] = {"exit": 0, "requirements": sorted(req["name"] for req in manifest.get("requirements", []))}
        else:
            entry[f"uv-{v}"] = {"exit": r.returncode, "error": (r.stderr.strip().splitlines() or [""])[0]}
    result[script.name] = entry
(scripts.parent / "uv-script-reads.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
PY

# ---- requirements corpus ----
c="$out/requirements/corpus"
printf '%s\n' 'six==1.17.0' 'idna==3.10' 'packaging==25.0' > "$work/requirements.in"
(cd "$work" && "$work/tools/uv-0.12.21/bin/uv" pip compile -q --generate-hashes --no-header --exclude-newer "$EXCLUDE_NEWER" requirements.in -o compiled.txt)
{ echo "--require-hashes"; cat "$work/compiled.txt"; } > "$c/lock-uv-pip-compile.txt"
{ echo "--require-hashes"; cat "$out/locks/uv-0.12.21/simple/requirements.txt"; } > "$c/lock-uv-export.txt"
"$py" - "$c" "$work/compiled.txt" <<'PY'
import pathlib, re, sys
c = pathlib.Path(sys.argv[1])
compiled = pathlib.Path(sys.argv[2]).read_text()
# One line per requirement, with its hashes on the same line: "name==version --hash=... --hash=..."
reqs = {}
for block in re.split(r"\n(?=\S)", compiled.strip()):
    lines = [l.strip().rstrip("\\").strip() for l in block.splitlines() if not l.strip().startswith("#")]
    if lines and "==" in lines[0]:
        reqs[lines[0].split("==")[0]] = " ".join(lines)
six, idna, packaging = reqs["six"], reqs["idna"], reqs["packaging"]
six_name, six_hashes = six.split(" ", 1)
H = six_hashes.split()[0]  # one --hash=sha256:... of six
NL = "\n"
files = {
    "lock-one-line.txt": f"--require-hashes{NL}{six}{NL}{idna}{NL}{packaging}{NL}",
    "lock-crlf.txt": f"--require-hashes\r\n{six}\r\n{idna}\r\n",
    "lock-utf8-bom.txt": f"\ufeff--require-hashes{NL}{six}{NL}",
    "lock-coding-utf8.txt": f"# -*- coding: utf-8 -*-{NL}--require-hashes{NL}{six}{NL}",
    "lock-continuation.txt": f"--require-hashes{NL}{six_name} \\{NL}    " + f" \\{NL}    ".join(six_hashes.split()) + NL,
    "lock-extras-marker.txt": f"--require-hashes{NL}six[test]==1.17.0 ; python_version >= \"3.8\" {six_hashes}{NL}",
    "lock-spaces-around-eq.txt": f"--require-hashes{NL}six == 1.17.0 {six_hashes}{NL}",
    "lock-hash-space-value.txt": f"--require-hashes{NL}six==1.17.0 --hash {H.split('=', 1)[1]}{NL}",
    "lock-include.txt": f"--require-hashes{NL}-r included/base.txt{NL}{idna}{NL}",
    "include-attached.txt": f"--require-hashes{NL}-rincluded/base.txt{NL}",
    "include-equals.txt": f"--require-hashes{NL}-r included/equals.txt{NL}",
    "include-hash-in-path.txt": f"--require-hashes{NL}-r included/hash#x.txt{NL}",
    "requirements-in-constraint.txt": f"--require-hashes{NL}{six}{NL}-c included/constraint-with-r.txt{NL}",
    "require-hashes-in-constraint.txt": f"six==1.17.0{NL}-c included/require-hashes-only.txt{NL}",
    "require-hashes-in-include-unhashed.txt": f"six==1.17.0{NL}-r included/require-hashes-only.txt{NL}",
    "mixed-hashes.txt": f"--require-hashes{NL}{six} --hash=sha512:{'ab' * 64}{NL}",
    "lock-constraint.txt": f"--require-hashes{NL}{six}{NL}-c included/constraints.txt{NL}",
    "lock-require-hashes-in-include.txt": f"-r included/with-require-hashes.txt{NL}{six}{NL}",
    "lock-only-require-hashes.txt": f"--require-hashes{NL}",
    "lock-comments.txt": f"# a comment{NL}--require-hashes  # trailing comment{NL}{six}    # via demo{NL}#{NL}",
    "lock-trailing-backslash-eof.txt": f"--require-hashes{NL}{six} \\",
    "empty-comments.txt": f"# only comments{NL}{NL}   # and blank lines{NL}",
    "empty-file.txt": "",
    "no-require-hashes.txt": f"{six}{NL}{idna}{NL}",
    "unhashed-line.txt": f"--require-hashes{NL}{six}{NL}idna==3.10{NL}",
    "unpinned.txt": f"--require-hashes{NL}six>=1.16 {six_hashes}{NL}",
    "wildcard.txt": f"--require-hashes{NL}six==1.17.* {six_hashes}{NL}",
    "triple-equals.txt": f"--require-hashes{NL}six===1.17.0 {six_hashes}{NL}",
    "local-version.txt": f"--require-hashes{NL}six==1.17.0+local {six_hashes}{NL}",
    "md5-hash.txt": f"--require-hashes{NL}six==1.17.0 --hash=md5:0123456789abcdef0123456789abcdef{NL}",
    "sha512-only.txt": f"--require-hashes{NL}six==1.17.0 --hash=sha512:{'ab' * 64}{NL}",
    "uppercase-hash.txt": f"--require-hashes{NL}six==1.17.0 {H.upper().replace('--HASH=SHA256', '--hash=sha256')}{NL}",
    "index-url.txt": f"-i https://example.invalid/simple{NL}--require-hashes{NL}{six}{NL}",
    "extra-index-url.txt": f"--extra-index-url https://example.invalid/simple{NL}--require-hashes{NL}{six}{NL}",
    "find-links.txt": f"--find-links ./wheels{NL}--require-hashes{NL}{six}{NL}",
    "no-index.txt": f"--no-index{NL}--require-hashes{NL}{six}{NL}",
    "trusted-host.txt": f"--trusted-host example.invalid{NL}--require-hashes{NL}{six}{NL}",
    "no-binary.txt": f"--no-binary :all:{NL}--require-hashes{NL}{six}{NL}",
    "only-binary.txt": f"--only-binary :all:{NL}--require-hashes{NL}{six}{NL}",
    "prefer-binary.txt": f"--prefer-binary{NL}--require-hashes{NL}{six}{NL}",
    "config-settings.txt": f"--require-hashes{NL}{six} --config-settings key=value{NL}",
    "editable.txt": f"--require-hashes{NL}-e .{NL}{six}{NL}",
    "url-line.txt": f"--require-hashes{NL}six @ https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl {six_hashes}{NL}",
    "vcs-line.txt": f"--require-hashes{NL}git+https://github.com/benjaminp/six@1.17.0#egg=six{NL}",
    "path-line.txt": f"--require-hashes{NL}./vendor/six-1.17.0-py2.py3-none-any.whl {six_hashes}{NL}",
    "env-var.txt": f"--require-hashes{NL}six==${{SIX_VERSION}} {six_hashes}{NL}",
    "env-var-in-comment.txt": f"--require-hashes{NL}{six}  # ${{NOT_EXPANDED}}{NL}",
    "include-outside.txt": f"--require-hashes{NL}-r ../outside.txt{NL}",
    "include-missing.txt": f"--require-hashes{NL}-r included/missing.txt{NL}",
    "include-url.txt": f"--require-hashes{NL}-r file:///nonexistent/requirements.txt{NL}",
    "include-cycle.txt": f"--require-hashes{NL}-r included/cycle-a.txt{NL}",
    "include-and-require-hashes.txt": f"--require-hashes -r included/base.txt{NL}",
    "include-twice-on-a-line.txt": f"--require-hashes{NL}-r included/base.txt -r included/constraints.txt{NL}",
    "require-hashes-on-requirement-line.txt": f"{six} --require-hashes{NL}",
    "include-on-requirement-line.txt": f"--require-hashes{NL}{six} -r included/base.txt{NL}",
    "hash-before-requirement.txt": f"--require-hashes{NL}{H} six==1.17.0{NL}",
    "hash-on-own-line.txt": f"--require-hashes{NL}six==1.17.0{NL}{H}{NL}",
    "continuation-broken-by-comment.txt": f"--require-hashes{NL}six==1.17.0 \\{NL}# a comment{NL}{H}{NL}",
    "comment-ends-with-backslash.txt": f"--require-hashes{NL}# a comment \\{NL}{six}{NL}",
    "double-backslash.txt": f"--require-hashes{NL}{six} \\\\{NL}",
    "quoted-hash.txt": f"--require-hashes{NL}six==1.17.0 --hash=\"{H.split('=', 1)[1]}\"{NL}",
    "abbreviated-hash.txt": f"--require-hashes{NL}six==1.17.0 --has={H.split('=', 1)[1]}{NL}",
    "abbreviated-require-hashes.txt": f"--require-hash{NL}{six}{NL}",
    "leftover-text.txt": f"--require-hashes{NL}{six} junk{NL}",
    "double-dash.txt": f"--require-hashes{NL}six==1.17.0 -- {H}{NL}",
    "tab-before-hash.txt": f"--require-hashes{NL}six==1.17.0\t{H}{NL}",
    "nbsp-before-comment.txt": f"--require-hashes{NL}{six}\u00a0# comment{NL}",
    "sep-bare-cr.txt": f"--require-hashes\r{six}{NL}",
    "sep-form-feed.txt": f"--require-hashes{NL}{six}\x0c{idna}{NL}",
    "sep-vertical-tab.txt": f"--require-hashes{NL}{six}\x0b{idna}{NL}",
    "sep-next-line.txt": f"--require-hashes{NL}{six}\x85{idna}{NL}",
    "sep-line-separator.txt": f"--require-hashes{NL}{six}\u2028{idna}{NL}",
    "sep-file-separator.txt": f"--require-hashes{NL}{six}\x1c{idna}{NL}",
    "sep-escape-control.txt": f"--require-hashes{NL}{six}\x1b{NL}",
    # Characters Python reads as whitespace (str.strip, re's \s) and JavaScript does not, or the other way round:
    # pip strips a leading U+001F, and a "#" after one starts a comment line it never joins to the next.
    "ws-unit-separator.txt": f"--require-hashes{NL}{six}{NL}\x1f{idna}{NL}",
    "ws-unit-separator-comment.txt": f"--require-hashes{NL}\x1f# a comment \\{NL}{six}{NL}",
    "ws-bom-middle.txt": f"--require-hashes{NL}{six}{NL}\ufeff{idna}{NL}",
    "ws-bom-comment.txt": f"--require-hashes{NL}{six}{NL}\ufeff# a comment \\{NL}{idna}{NL}",
    "ws-nbsp-start.txt": f"--require-hashes{NL}\u00a0{six}{NL}",
    "ws-em-space-start.txt": f"--require-hashes{NL}\u2003{six}{NL}",
    "ctl-start-of-heading.txt": f"--require-hashes{NL}{six}{NL}\x01{NL}",
    "ctl-delete.txt": f"--require-hashes{NL}{six}\x7f{NL}",
    "included/base.txt": f"{six}{NL}",
    "included/constraints.txt": f"{packaging}{NL}",
    "included/with-require-hashes.txt": f"--require-hashes{NL}{idna}{NL}",
    "included/cycle-a.txt": f"-r cycle-b.txt{NL}{six}{NL}",
    "included/cycle-b.txt": f"-r cycle-a.txt{NL}",
    # pip reads "-r=eq.txt" as the file "=eq.txt" and "-r hash#x.txt" as "hash#x.txt"; uv reads "eq.txt" and "hash".
    "included/equals.txt": f"-r=eq.txt{NL}",
    "included/=eq.txt": f"{six}{NL}",
    "included/eq.txt": f"{idna}{NL}",
    "included/hash#x.txt": f"{six}{NL}",
    "included/hash": f"{idna}{NL}",
    "included/constraint-with-r.txt": f"-r reqs-in-constraint.txt{NL}",
    "included/reqs-in-constraint.txt": f"{idna}{NL}",
    "included/require-hashes-only.txt": f"--require-hashes{NL}",
}
for name, text in files.items():
    (c / name).write_text(text, encoding="utf-8", newline="")
(c / "utf16.txt").write_bytes(f"--require-hashes{NL}{six}{NL}".encode("utf-16"))
(c / "nul-byte.txt").write_bytes(f"--require-hashes{NL}{six}{NL}\x00{NL}".encode())
(c / "coding-latin1.txt").write_bytes(f"# -*- coding: latin-1 -*-{NL}--require-hashes{NL}{six}{NL}# caf\xe9{NL}".encode("latin-1"))
(c / "invalid-utf8.txt").write_bytes(f"--require-hashes{NL}{six}{NL}# \xff{NL}".encode("latin-1"))
PY

# What pip 26.2.1's own parser reads in every corpus file (requirement files are parsed, never installed).
"$py" - "$c" > "$out/requirements/pip-$PIP_VERSION.json" <<'PY'
import json, logging, os, sys
from pip._internal.network.session import PipSession
from pip._internal.req.req_file import RequirementsFileParser, build_parser, get_line_parser
logging.disable(logging.CRITICAL)
root = os.path.abspath(sys.argv[1])
os.chdir(root)
defaults = vars(build_parser().get_default_values())
def plain(v):
    return v if isinstance(v, (str, int, float, bool, type(None))) else [plain(x) for x in v] if isinstance(v, (list, tuple)) else {k: plain(x) for k, x in v.items()} if isinstance(v, dict) else repr(v)
result = {}
for dirpath, _, names in sorted(os.walk(".")):
    for name in sorted(names):
        rel = os.path.relpath(os.path.join(dirpath, name), ".").replace(os.sep, "/")
        try:
            lines = []
            for pl in RequirementsFileParser(PipSession(), get_line_parser(None)).parse(rel, constraint=False):
                opts = {k: plain(v) for k, v in vars(pl.opts).items() if k in defaults and v != defaults[k] and k != "index_url"}
                if pl.opts.index_url is not None:
                    opts["index_url"] = pl.opts.index_url
                lines.append({"file": os.path.relpath(pl.filename, ".").replace(os.sep, "/"), "line": pl.lineno, "args": pl.args, "requirement": pl.requirement, "constraint": pl.constraint, "opts": opts})
            require_hashes = any(l["requirement"] is None and l["opts"].get("require_hashes") for l in lines)
            result[rel] = {"lines": lines, "require_hashes": require_hashes}
        except Exception as e:  # pip's refusal is the recorded answer
            message = str(e).splitlines()[0] if str(e) else ""
            parent = os.path.dirname(root)
            for path, name in ((os.path.realpath(root), "<corpus>"), (root, "<corpus>"), (os.path.realpath(parent), "<corpus>/.."), (parent, "<corpus>/..")):
                message = message.replace(path, name)
            result[rel] = {"error": f"{type(e).__name__}: {message}"}
json.dump({"pip": "26.2.1", "parser": "pip._internal.req.req_file.RequirementsFileParser with get_line_parser(None)", "files": result}, sys.stdout, indent=2, sort_keys=True, ensure_ascii=True)
print()
PY

# What each uv would install from every corpus file (--dry-run: nothing is installed; hashes are not checked).
"$py" - "$c" "$work" "$EXCLUDE_NEWER" "${UV_VERSIONS[@]}" > "$out/requirements/uv-pip-sync.json" <<'PY'
import json, os, re, subprocess, sys
root, work, cutoff, versions = os.path.abspath(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4:]
os.chdir(root)
result = {}
for dirpath, _, names in sorted(os.walk(".")):
    for name in sorted(names):
        rel = os.path.relpath(os.path.join(dirpath, name), ".").replace(os.sep, "/")
        entry = {}
        for v in versions:
            r = subprocess.run([f"{work}/tools/uv-{v}/bin/uv", "pip", "sync", "--dry-run", "--python", f"{work}/tools/target/bin/python", "--exclude-newer", cutoff, rel], capture_output=True, text=True, timeout=120)
            out = r.stdout + r.stderr
            for path, name in ((os.path.realpath(root), "<corpus>"), (root, "<corpus>"), (os.path.realpath(work), "<work>"), (work, "<work>")):
                out = out.replace(path, name)
            out = re.sub(r"after (\d+) retries in [0-9.]+s", r"after \1 retries", out)
            entry[f"uv-{v}"] = {
                "exit": r.returncode,
                "install": sorted(m.group(1) for m in re.finditer(r"^ \+ (\S+)$", out, re.M)),
                "warnings": [l for l in out.splitlines() if l.startswith("warning:")],
                "error": next((l for l in out.splitlines() if l.startswith("error:")), None),
            }
        result[rel] = entry
json.dump({"uv": versions, "command": "uv pip sync --dry-run --python <venv> --exclude-newer " + cutoff + " <file>", "files": result}, sys.stdout, indent=2, sort_keys=True, ensure_ascii=True)
print()
PY

# ---- Simple JSON (PEP 691) snapshots ----
for p in six idna packaging certifi markupsafe; do
  curl -sSf --max-time 60 -H 'Accept: application/vnd.pypi.simple.v1+json' -H 'User-Agent: wormsign-fixtures (+https://github.com/stgllghr/wormsign)' \
    -D "$work/headers-$p.txt" -o "$out/simple/$p.json" "https://pypi.org/simple/$p/"
  grep -qi '^content-type: application/vnd.pypi.simple.v1+json' "$work/headers-$p.txt" || { echo "pypi.org did not answer $p with Simple JSON" >&2; exit 1; }
done
"$py" - "$out/simple" <<'PY'
import datetime, hashlib, json, pathlib, sys
d = pathlib.Path(sys.argv[1])
index = {"captured": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "from": "https://pypi.org/simple/<project>/",
         "accept": "application/vnd.pypi.simple.v1+json", "projects": {}}
for f in sorted(d.glob("*.json")):
    if f.name == "index.json":
        continue
    doc = json.loads(f.read_bytes())
    index["projects"][doc["name"]] = {"file": f.name, "sha256": hashlib.sha256(f.read_bytes()).hexdigest(), "api-version": doc["meta"]["api-version"], "files": len(doc["files"])}
(d / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
PY

# ---- tool versions, then replace the committed fixtures ----
{
  echo "pip $("$py" -m pip --version | cut -d' ' -f2)"
  for v in "${UV_VERSIONS[@]}"; do "$work/tools/uv-$v/bin/uv" --version; done
  echo "python $("$py" -c 'import platform; print(platform.python_version())')"
  echo "exclude-newer $EXCLUDE_NEWER"
} > "$out/locks/TOOLS.txt"
for d in locks requirements simple; do
  rm -rf "${repo:?}/test/fixtures/python/${d:?}"
  mkdir -p "$repo/test/fixtures/python"
  cp -R "$out/$d" "$repo/test/fixtures/python/$d"
done
echo "gen-py-fixtures: wrote test/fixtures/python/{locks,requirements,simple}"
