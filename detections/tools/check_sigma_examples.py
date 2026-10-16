"""Run each Sigma rule over its own `examples` with the official pySigma SQLite backend. Dev-only; needs sigma-cli
with the sqlite backend (pySigma-backend-sqlite).

test/detections.test.ts runs the same examples through its own small evaluator; this is the independent check. Each
alerting rule in a file is converted with the SQLite backend and run over in-memory tables built from its examples:
a rule must return every positive event and no negative one. A correlation runs over the positive events as one
stream, where its alerts must cover every event, and over the negative events as another, where it must raise none.
The columns are COLLATE NOCASE, as Zircolite builds them, so that = compares case-insensitively as Sigma specifies,
and @timestamp is read as epoch milliseconds.

Usage: python check_sigma_examples.py <rule.yml>...
"""
import json
import sqlite3
import sys

import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule


def fields(docs, events):
    """Every field the rules or the events name, so that a query never refers to a missing column."""
    out = {"@timestamp"}
    for doc in docs:
        for selection in (doc.get("detection") or {}).values():
            if isinstance(selection, dict):
                out.update(key.split("|")[0] for key in selection)
        correlation = doc.get("correlation") or {}
        out.update(correlation.get("group-by") or [])
        if isinstance((correlation.get("condition") or {}).get("field"), str):
            out.add(correlation["condition"]["field"])
    for event in events:
        out.update(event)
    return sorted(out)


def run(query, columns, events, correlation):
    """The rowids of the events the query returns or, for a correlation, the rowids in each alert's evidence."""
    db = sqlite3.connect(":memory:")
    quoted = [f'"{c}"' for c in columns]
    db.execute(f"CREATE TABLE logs ({', '.join(f'{q} INTEGER' if c == '@timestamp' else f'{q} TEXT COLLATE NOCASE' for q, c in zip(quoted, columns))})")
    for e in events:
        # A list or map is stored as its JSON text: the rules only test such a field with |exists.
        values = [("true" if e[c] else "false") if isinstance(e.get(c), bool) else json.dumps(e[c]) if isinstance(e.get(c), (list, dict)) else e.get(c) for c in columns]
        db.execute(f"INSERT INTO logs ({', '.join(quoted)}) VALUES ({', '.join('?' * len(columns))})", values)
    if not correlation:
        return [{row[0] for row in db.execute(query.replace("SELECT *", "SELECT rowid", 1))}]
    cursor = db.execute(query)
    names = [d[0] for d in cursor.description]
    return [{int(eid.split(":")[-1]) for eid in json.loads(row[names.index("event_ids")])} for row in cursor]


failed = False
for path in sys.argv[1:]:
    text = open(path, encoding="utf-8").read()
    docs = list(yaml.safe_load_all(text))
    collection = SigmaCollection.from_yaml(text)
    collection.resolve_rule_references()
    backend = sqliteBackend(timestamp_field="@timestamp", timestamp_format="unix_ms")
    # In the order backend.convert() uses: a correlation needs its base rules converted first.
    queries = {r.name: (backend.convert_rule(r) if isinstance(r, SigmaRule) else backend.convert_correlation_rule(r), not isinstance(r, SigmaRule)) for r in collection.rules}
    referenced = {n for d in docs for n in (d.get("correlation") or {}).get("rules", [])}
    for doc in docs:
        if doc["name"] in referenced:
            continue
        pos = [json.loads(l) for l in doc["examples"]["positive"].strip().splitlines()]
        neg = [json.loads(l) for l in doc["examples"]["negative"].strip().splitlines()]
        (query,), is_corr = queries[doc["name"]]
        columns = fields(docs, pos + neg)
        hits_pos = set().union(*run(query, columns, pos, is_corr))
        alerts_neg = [a for a in run(query, columns, neg, is_corr) if a]
        problems = []
        if hits_pos != set(range(1, len(pos) + 1)):
            problems.append(f"positive events returned: {sorted(hits_pos)} of 1..{len(pos)}")
        if alerts_neg:
            problems.append(f"negative events returned: {sorted(set().union(*alerts_neg))}")
        kind = "correlation" if is_corr else "rule"
        print(f"{'FAIL' if problems else 'OK  '} {doc['name']} ({kind}): {len(pos)} positive, {len(neg)} negative{': ' + '; '.join(problems) if problems else ''}")
        failed |= bool(problems)
sys.exit(1 if failed else 0)
