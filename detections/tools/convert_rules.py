"""Write the reference conversions committed next to each Sigma rule file. Dev-only; needs sigma-cli with the
splunk and elasticsearch backends.

For every rule file in detections/github-audit-log/ and detections/sigma/, converts it without a processing pipeline,
as `sigma convert -t <target> --without-pipeline <file>` does, then applies the post-processing below and writes
<file>.spl (Splunk) and <file>.esql (ES|QL). Each query is labelled with the name, title and level of the rule it comes
from, and the header records the command, the edits, the tool versions and the sha256 of the rule file, which
test/detections.test.ts compares so that a reference cannot go stale silently. The script also runs that sigma-cli
command and fails unless sigma-cli prints the same queries as the backend did before the post-processing.

Post-processing, so that the committed queries mean what the Sigma rule means (the Sigma correlation specification
2.1.0, "Compatibility", warns that fixed time boundaries cause false negatives):

- Splunk: a correlation's `| bin _time span=<t>` and `| stats ... by _time <fields>` become `| sort 0 _time` and
  `| streamstats time_window=<t> ... by <fields>`, a window that slides instead of fixed clock buckets, and a final
  `| dedup <fields>` keeps one result per group, the first event that completes its burst, instead of one for each.
- ES|QL, which has no sliding window: a correlation counts each event in two sets of clock-aligned buckets of the
  timespan, the second offset by half of it, through a two-valued `timebucket`.
- ES|QL: every string comparison (==, in, like, starts_with, ends_with) is made on to_lower(field) with a lower-case
  value, because those operators are case-sensitive and Sigma's values are not.
- ES|QL: every `not` wraps its operand in coalesce(..., false). A comparison with a missing field is null, and
  `not null` drops the event, where Sigma's `not filter` passes an event that lacks the filter's field.
- ES|QL: a like pattern doubles each literal backslash, since like reads a backslash as its escape character.

The ES|QL edits follow the ES|QL reference as the author knows it; no Elasticsearch has run them. Each edit fails
closed: a query shape it does not recognise stops the script.

Usage: python convert_rules.py <path to the sigma executable>
"""
import hashlib
import re
import subprocess
import sys
import tempfile
from importlib.metadata import version
from pathlib import Path

from sigma.backends.elasticsearch import ESQLBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

ROOT = Path(__file__).resolve().parents[2]

SPLUNK_EDITS = [
    "# Post-processed by convert_rules.py: a correlation's `bin _time span=<t>` and `stats ... by _time` are replaced by",
    "# `sort 0 _time` and `streamstats time_window=<t> ... by`, so its window slides as the Sigma rule's does. Fixed",
    "# clock buckets would miss a burst across a bucket boundary. A final `dedup` of the group-by fields keeps one result",
    "# per group, the first event that completes its burst, instead of one per event that completes it.",
]
ESQL_EDITS = [
    "# Post-processed by convert_rules.py (not run in Elasticsearch; checked against the ES|QL reference only):",
    "# - string comparisons are on to_lower(field) with a lower-case value: ==, in, like, starts_with and ends_with are",
    "#   case-sensitive in ES|QL and Sigma's values are not;",
    "# - each `not` wraps its operand in coalesce(..., false), so an event without the field passes a not filter as in",
    "#   Sigma, instead of being dropped as null;",
    "# - like patterns double each literal backslash, which like reads as its escape character;",
    "# - ES|QL has no sliding window: a correlation counts in clock-aligned buckets of its timespan and in a second set",
    "#   offset by half of it. Each alert is one the Sigma rule raises. A burst within half the timespan is always",
    "#   caught; a longer one only when one bucket holds it whole.",
]


def span_seconds(timespan: str) -> int:
    m = re.fullmatch(r"(\d+)([smhd])", timespan)
    if not m:
        sys.exit(f"FAIL: unsupported timespan {timespan}")
    return int(m[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m[2]]


def esql_duration(seconds: int) -> str:
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60), ("second", 1)):
        if seconds % size == 0:
            n = seconds // size
            return f"{n} {unit}{'' if n == 1 else 's'}"
    raise AssertionError(seconds)


# --- Splunk -------------------------------------------------------------------------------------------------------

def splunk_post(query: str, correlation) -> str:
    pattern = re.compile(r"\n\| bin _time span=(?P<span>\S+)\n\| stats (?P<agg>.+?) by _time (?P<by>[^\n]+)\n")
    found = pattern.findall(query)
    if correlation is None:
        if found or "bin _time" in query:
            sys.exit(f"FAIL: unexpected time bucketing in a single-event Splunk query: {query}")
        return query
    if len(found) != 1:
        sys.exit(f"FAIL: the Splunk correlation query does not have one bin/stats pair: {query}")
    span = found[0][0]
    if span_seconds(span) != correlation.timespan.seconds:
        sys.exit(f"FAIL: Splunk span {span} differs from the rule's timespan")
    if found[0][2].split(" ") != list(correlation.group_by or []):
        sys.exit(f"FAIL: Splunk groups by {found[0][2]}, not the rule's group-by {correlation.group_by}")
    out = pattern.sub(lambda m: f"\n| sort 0 _time\n| streamstats time_window={m['span']} {m['agg']} by {m['by']}\n", query)
    if not re.search(r"\n\| search \w+ >= \d+$", out):
        sys.exit(f"FAIL: the Splunk correlation query does not end in its threshold search: {query}")
    return f"{out}\n| dedup {found[0][2]}"


# --- ES|QL --------------------------------------------------------------------------------------------------------

TOKEN = re.compile(r'\s*(?:(?P<str>"(?:[^"\\]|\\.)*")|(?P<num>-?\d+)\b|(?P<op>==|[(),])|(?P<word>[A-Za-z_@][\w@.]*))')


def tokenize(text: str):
    out, i = [], 0
    while i < len(text):
        if text[i:].strip() == "":
            break
        m = TOKEN.match(text, i)
        if not m or m.end() == i:
            sys.exit(f"FAIL: cannot read ES|QL at {text[i:i + 40]!r}")
        kind = m.lastgroup
        out.append((kind, m[kind]))
        i = m.end()
    return out


def decode(literal: str) -> str:
    """An ES|QL double-quoted literal as its string value. Only \\\\ and \\" are expected from the backend."""
    body, out, i = literal[1:-1], [], 0
    while i < len(body):
        c = body[i]
        if c == "\\":
            n = body[i + 1]
            if n not in '\\"':
                sys.exit(f"FAIL: unexpected escape \\{n} in ES|QL literal {literal}")
            out.append(n)
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def encode(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Parser:
    """The boolean expressions pySigma's ES|QL backend writes: comparisons joined by and, or, not and parentheses."""

    def __init__(self, text: str):
        self.tokens, self.i = tokenize(text), 0

    def peek(self, k=0):
        return self.tokens[self.i + k] if self.i + k < len(self.tokens) else (None, None)

    def take(self, kind=None, value=None):
        tok = self.peek()
        if tok[0] is None or (kind and tok[0] != kind) or (value and tok[1] != value):
            sys.exit(f"FAIL: expected {value or kind} in ES|QL, found {tok[1]!r}")
        self.i += 1
        return tok[1]

    def word(self, w):
        return self.peek() == ("word", w)

    def expr(self):
        return self.binary("or", lambda: self.binary("and", self.unary))

    def binary(self, op, sub):
        parts = [sub()]
        while self.word(op):
            self.take()
            parts.append(sub())
        flat = []
        for p in parts:
            flat.extend(p[1] if p[0] == op else [p])
        return flat[0] if len(flat) == 1 else (op, flat)

    def unary(self):
        if self.word("not"):
            self.take()
            return ("not", self.unary())
        return self.primary()

    def literal(self):
        kind, value = self.peek()
        if kind == "str":
            self.take()
            return ("str", decode(value))
        if kind == "num" or (kind == "word" and value in ("true", "false")):
            self.take()
            return ("raw", value)
        sys.exit(f"FAIL: expected a literal in ES|QL, found {value!r}")

    def primary(self):
        if self.peek() == ("op", "("):
            self.take()
            e = self.expr()
            self.take("op", ")")
            return e
        name = self.take("word")
        if name in ("starts_with", "ends_with"):
            self.take("op", "(")
            field = self.take("word")
            self.take("op", ",")
            value = self.literal()
            self.take("op", ")")
            return ("fn", name, field, value)
        if self.peek() == ("op", "=="):
            self.take()
            return ("eq", name, self.literal())
        if self.word("in"):
            self.take()
            self.take("op", "(")
            values = [self.literal()]
            while self.peek() == ("op", ","):
                self.take()
                values.append(self.literal())
            self.take("op", ")")
            return ("in", name, values)
        if self.word("like"):
            self.take()
            return ("like", name, self.literal())
        if self.word("is"):
            self.take()
            negated = self.word("not")
            if negated:
                self.take()
            self.take("word", "null")
            return ("null", name, negated)
        sys.exit(f"FAIL: unsupported ES|QL comparison after {name}")


def lower(value) -> str:
    kind, text = value
    if kind != "str":
        sys.exit(f"FAIL: a string comparison with the non-string {text}")
    if not text.isascii():
        sys.exit(f"FAIL: non-ASCII value {text!r}: check that to_lower and Python agree before allowing it")
    return text.lower()


def render(node, parent=None) -> str:
    kind = node[0]
    if kind in ("and", "or"):
        text = f" {kind} ".join(render(child, kind) for child in node[1])
        return f"({text})" if parent in ("and", "or") else text
    if kind == "not":
        return f"not coalesce({render(node[1])}, false)"
    if kind == "eq":
        _, field, value = node
        return f"{field} == {value[1]}" if value[0] == "raw" else f"to_lower({field}) == {encode(lower(value))}"
    if kind == "in":
        _, field, values = node
        return f"to_lower({field}) in ({', '.join(encode(lower(v)) for v in values)})"
    if kind == "fn":
        _, name, field, value = node
        return f"{name}(to_lower({field}), {encode(lower(value))})"
    if kind == "like":
        _, field, value = node
        return f"to_lower({field}) like {encode(lower(value).replace(chr(92), chr(92) * 2))}"
    if kind == "null":
        _, field, negated = node
        return f"{field} is {'not ' if negated else ''}null"
    raise AssertionError(node)


def esql_expr(text: str) -> str:
    p = Parser(text)
    node = p.expr()
    if p.peek()[0] is not None:
        sys.exit(f"FAIL: unread ES|QL after the expression: {p.peek()[1]!r}")
    return render(node)


def esql_post(query: str, correlation) -> str:
    out = []
    for line in query.split("\n"):
        head = "from * metadata _id, _index, _version | where "
        if line.startswith(head):
            out.append(head + esql_expr(line[len(head):]))
        elif line.startswith("| eval event_type=case(") and line.endswith(")"):
            p = Parser(line[len("| eval event_type=case("):-1])
            arms = []
            while True:
                cond = render(p.expr())
                p.take("op", ",")
                arms.append(f"{cond}, {encode(p.literal()[1])}")
                if p.peek()[0] is None:
                    break
                p.take("op", ",")
            out.append(f"| eval event_type=case({', '.join(arms)})")
        elif line.startswith("| eval timebucket=date_trunc("):
            if correlation is None:
                sys.exit("FAIL: time bucketing in a single-event ES|QL query")
            m = re.fullmatch(r"\| eval timebucket=date_trunc\((\d+)(\w+), @timestamp\) (\| stats .+ by timebucket, .+)", line)
            if not m:
                sys.exit(f"FAIL: unexpected ES|QL bucketing: {line}")
            width = correlation.timespan.seconds
            unit = {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400}.get(m[2])
            if unit is None or int(m[1]) * unit != width or width % 2:
                sys.exit(f"FAIL: ES|QL bucket {m[1]}{m[2]} does not match the rule's timespan")
            w, half = esql_duration(width), esql_duration(width // 2)
            out.append(f"| eval timebucket=mv_append(date_trunc({w}, @timestamp), date_trunc({w}, @timestamp + {half}) - {half}) {m[3]}")
        elif line.startswith("| where ") or line == "":
            out.append(line)
        else:
            sys.exit(f"FAIL: unexpected ES|QL line: {line}")
    if correlation is not None and not any("timebucket=mv_append(" in l for l in out):
        sys.exit("FAIL: an ES|QL correlation without its bucketing")
    return "\n".join(out)


TARGETS = (
    ("splunk", "spl", "Splunk SPL", SplunkBackend, "pySigma-backend-splunk", splunk_post, SPLUNK_EDITS),
    ("esql", "esql", "Elasticsearch ES|QL", ESQLBackend, "pySigma-backend-elasticsearch", esql_post, ESQL_EDITS),
)

sigma = sys.argv[1]
rules = sorted([*ROOT.glob("detections/github-audit-log/*.yml"), *ROOT.glob("detections/sigma/*.yml")])
for path in rules:
    raw = path.read_bytes()
    rel = path.relative_to(ROOT).as_posix()
    for target, ext, label, backend_class, dist, post, edits in TARGETS:
        collection = SigmaCollection.from_yaml(raw.decode("utf-8"))
        collection.resolve_rule_references()
        backend = backend_class()
        queries, blocks = [], []
        for rule in collection.rules:  # the order backend.convert() uses
            converted = backend.convert_rule(rule) if isinstance(rule, SigmaRule) else backend.convert_correlation_rule(rule)
            if not converted:  # a base rule of a correlation, which produces no query of its own
                continue
            queries += converted
            correlation = rule if isinstance(rule, SigmaCorrelationRule) else None
            level = rule.level.name.lower() if rule.level else "no level"
            blocks.append(f"# {rule.name}: {rule.title} ({level})\n" + "\n\n".join(post(q, correlation) for q in converted))

        command = ["convert", "-t", target, "--without-pipeline", rel]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.txt"
            subprocess.run([sigma, *command[:-1], "-o", str(out), rel], cwd=ROOT, check=True, capture_output=True)
            if out.read_text(encoding="utf-8") != "\n\n".join(queries) + "\n":
                sys.exit(f"FAIL: sigma {' '.join(command)} does not print the queries the backend wrote for {rel}")

        header = [
            f"# Reference conversion of {path.name} to {label}. Generated; do not edit.",
            f"# Generated by detections/tools/convert_rules.py: sigma {' '.join(command)}, then the edits below.",
            *edits,
            f"# sigma-cli {version('sigma-cli')}, pySigma {version('pySigma')}, {dist} {version(dist)}.",
            "# No processing pipeline: the fields are the rule's own, and no index, source type or table is set.",
            "# Each query follows a line naming the Sigma rule it comes from; base rules of a correlation have none.",
            f"# Rule sha256: {hashlib.sha256(raw).hexdigest()}",
        ]
        path.with_suffix(f".{ext}").write_text("\n".join(header) + "\n\n" + "\n\n".join(blocks) + "\n", encoding="utf-8")
        print(f"{rel} -> {path.with_suffix(f'.{ext}').name}: {len(queries)} queries")
