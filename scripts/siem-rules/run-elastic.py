#!/usr/bin/env python3
"""Run the TrueSignal Elastic detection rules against the Hub's real output.

Replays Docs/siem/testdata/detection-samples.ndjson (generated from the Hub's
own event pipeline and ECS formatter by TestSIEMDetectionSamples) into a
throwaway Elasticsearch, installs the index template from
Docs/siem-integration.md, imports every rule in Docs/siem/elastic/ through the
Kibana detection engine, waits for one execution of each and compares the
alerts with expected-elastic.json.

Only use a disposable stack: the script deletes the logs-truesignal-default
data stream, the truesignal-* rules and their alerts.

    scripts/siem-rules/run-elastic.sh            # starts ES + Kibana in Docker
    python3 scripts/siem-rules/run-elastic.py --es URL --kibana URL --user U --password P

Standard library only.
"""
import argparse
import base64
import datetime as dt
import glob
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SAMPLES = os.path.join(ROOT, "Docs/siem/testdata/detection-samples.ndjson")
RULES = os.path.join(ROOT, "Docs/siem/elastic")
INTEGRATION_DOC = os.path.join(ROOT, "Docs/siem-integration.md")
EXPECTED = os.path.join(os.path.dirname(__file__), "expected-elastic.json")
DATA_STREAM = "logs-truesignal-default"
ALERTS = ".alerts-security.alerts-default"
SKIP = {"truesignal-honeytoken-authentication"}  # matches other products' logs


class Client:
    def __init__(self, base, user, password, kibana=False):
        self.base = base.rstrip("/")
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.kibana = kibana

    def req(self, method, path, body=None, ndjson=False, ok=(200, 201)):
        data = None
        headers = {"Authorization": self.auth}
        if self.kibana:
            headers["kbn-xsrf"] = "true"
            headers["elastic-api-version"] = "2023-10-31"
        if body is not None:
            data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            headers["Content-Type"] = "application/x-ndjson" if ndjson else "application/json"
        r = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(r, timeout=60) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raw = e.read()
            if e.code in ok:
                return e.code, json.loads(raw) if raw else {}
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, {"error": raw.decode(errors="replace")}


def index_template():
    """The index template exactly as Docs/siem-integration.md publishes it."""
    text = open(INTEGRATION_DOC).read()
    m = re.search(r"PUT _index_template/logs-truesignal\n(\{.*?\n\})\n```", text, re.S)
    if not m:
        sys.exit("index template not found in Docs/siem-integration.md")
    return json.loads(m.group(1))


def load_samples(now):
    docs = []
    for line in open(SAMPLES):
        s = json.loads(line)
        doc = s["doc"]
        ts = now - dt.timedelta(seconds=s["offset_sec"])
        doc["@timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        docs.append((s["case"], doc))
    return docs


def get_path(doc, dotted):
    cur = doc
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, dict) and dotted in cur:
            return cur[dotted]
        else:
            return None
    return cur


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--es", default="http://localhost:9200")
    ap.add_argument("--kibana", default="http://localhost:5601")
    ap.add_argument("--user", default="elastic")
    ap.add_argument("--password", default=os.environ.get("ES_PASSWORD", "changeme-test"))
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()
    es = Client(args.es, args.user, args.password)
    kb = Client(args.kibana, args.user, args.password, kibana=True)

    # 1. Index template and data.
    es.req("DELETE", f"/_data_stream/{DATA_STREAM}", ok=(200, 404))
    st, r = es.req("PUT", "/_index_template/logs-truesignal", index_template())
    if st != 200:
        sys.exit(f"index template: {st} {r}")
    now = dt.datetime.now(dt.timezone.utc)
    docs = load_samples(now)
    bulk = "".join(json.dumps({"create": {"_id": case}}) + "\n" + json.dumps(doc) + "\n" for case, doc in docs)
    st, r = es.req("POST", f"/{DATA_STREAM}/_bulk?refresh=true", bulk, ndjson=True)
    if st != 200 or r.get("errors"):
        bad = [i for i in r.get("items", []) if i.get("create", {}).get("error")]
        sys.exit(f"bulk ingest failed: {st} {json.dumps(bad[:3])}")
    print(f"ingested {len(docs)} documents into {DATA_STREAM} (mapping errors: none)")

    # 2. Rules.
    kb.req("POST", "/api/detection_engine/index", ok=(200, 201, 400, 409))
    rules = {}
    for f in sorted(glob.glob(os.path.join(RULES, "truesignal-*.json"))):
        rule = json.load(open(f))
        if rule["rule_id"] in SKIP:
            continue
        rule["enabled"] = True  # also exercise rules that ship disabled
        rules[rule["rule_id"]] = rule
    expected = {k: v for k, v in json.load(open(EXPECTED)).items() if not k.startswith("_")}
    missing = sorted(set(rules) ^ set(expected))
    if missing:
        sys.exit(f"rules and expected-elastic.json disagree: {missing}")

    es.req("POST", f"/{ALERTS}/_delete_by_query?refresh=true&ignore_unavailable=true",
           {"query": {"prefix": {"kibana.alert.rule.rule_id": "truesignal-"}}}, ok=(200, 404))
    created_at = {}
    for rid, rule in rules.items():
        kb.req("DELETE", f"/api/detection_engine/rules?rule_id={rid}", ok=(200, 404))
        st, r = kb.req("POST", "/api/detection_engine/rules", rule)
        if st != 200:
            sys.exit(f"{rid}: Kibana rejected the rule: {st} {json.dumps(r)[:500]}")
        created_at[rid] = time.time()
    print(f"imported {len(rules)} rules into Kibana")

    # 3. Wait for one execution of every rule.
    pending, failures = set(rules), {}
    deadline = time.time() + args.timeout
    while pending and time.time() < deadline:
        time.sleep(5)
        for rid in sorted(pending):
            st, r = kb.req("GET", f"/api/detection_engine/rules?rule_id={rid}")
            last = (r.get("execution_summary") or {}).get("last_execution") or {}
            status = last.get("status")
            if status in ("succeeded", "failed", "partial failure"):
                pending.discard(rid)
                if status != "succeeded":
                    failures[rid] = f"{status}: {last.get('message')}"
    if pending:
        sys.exit(f"rules did not run within {args.timeout}s: {sorted(pending)}")
    time.sleep(3)
    es.req("POST", f"/{ALERTS}/_refresh", ok=(200, 404))

    # 4. Compare.
    ok = True
    for rid, exp in expected.items():
        st, r = es.req("POST", f"/{ALERTS}/_search", {
            "size": 1000, "query": {"term": {"kibana.alert.rule.rule_id": rid}}})
        hits = [h["_source"] for h in r.get("hits", {}).get("hits", [])]
        problems = []
        if rid in failures:
            problems.append(f"execution {failures[rid]}")
        if "cases" in exp:
            got, sev = set(), {}
            for a in hits:
                for anc in a.get("kibana.alert.ancestors", []):
                    if anc.get("index", "").find(DATA_STREAM) >= 0:
                        got.add(anc["id"])
                        if a.get("kibana.alert.building_block_type") is None:
                            sev[anc["id"]] = a.get("kibana.alert.severity")
            want = set(exp["cases"])
            if got != want:
                problems.append(f"missing {sorted(want - got)} unexpected {sorted(got - want)}")
            for case, s in exp.get("severity", {}).items():
                if sev.get(case) != s:
                    problems.append(f"{case}: severity {sev.get(case)}, want {s}")
        if "groups" in exp:
            got = []
            for a in hits:
                g = {}
                th = a.get("kibana.alert.threshold_result")
                if th:
                    for t in th.get("terms", []):
                        g[t["field"]] = t["value"]
                    g["count"] = th.get("count")
                else:
                    for k in ("host.id", "truesignal.sensor_id", "source.ip"):
                        v = get_path(a, k)
                        if v is not None:
                            g[k] = v
                got.append(g)
            for want in exp["groups"]:
                if not any(all(g.get(k) == v for k, v in want.items()) for g in got):
                    problems.append(f"no alert for {want}; got {got}")
            if len(got) != len(exp["groups"]):
                problems.append(f"{len(got)} alerts, want {len(exp['groups'])}: {got}")
        print(("FAIL " if problems else "ok   ") + rid + ("" if not problems else ": " + "; ".join(problems)))
        ok &= not problems
    print("PASS" if ok else "FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
