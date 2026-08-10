#!/usr/bin/env python3
"""Detect likely DNS tunneling / exfiltration from query logs.

Groups DNS queries by their registered domain (last two labels), then scores
each domain on subdomain entropy, length, and uniqueness - the fingerprints of
data smuggled through DNS. Flags domains that look like tunnels. Standard
library only.
"""
import argparse
import csv
import json
import math
import sys
from collections import defaultdict

DEFAULTS = {
    "entropy_threshold": 3.5,
    "avg_len_threshold": 20.0,
    "min_unique": 20,
    "long_label_threshold": 40,
}
QUERY_COLUMN_HINTS = ("query", "qname", "domain", "name", "question")


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def split_query(qname):
    """Return (registered_domain, subdomain_string) using a last-two-labels heuristic."""
    labels = qname.strip().strip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels), ""
    registered = ".".join(labels[-2:])
    subdomain = ".".join(labels[:-2])
    return registered, subdomain


def analyze(queries):
    grouped = defaultdict(list)
    for q in queries:
        registered, sub = split_query(q)
        if registered:
            grouped[registered].append(sub)

    stats = {}
    for domain, subs in grouped.items():
        non_empty = [s for s in subs if s]
        unique = set(non_empty)
        entropies = [shannon_entropy(s.replace(".", "")) for s in non_empty]
        lengths = [len(s) for s in non_empty]
        max_label = max((len(lbl) for s in non_empty for lbl in s.split(".")), default=0)
        stats[domain] = {
            "queries": len(subs),
            "unique_subdomains": len(unique),
            "avg_entropy": round(sum(entropies) / len(entropies), 2) if entropies else 0.0,
            "avg_subdomain_length": round(sum(lengths) / len(lengths), 1) if lengths else 0.0,
            "max_label_length": max_label,
        }
    return stats


def detect(stats, opts=None):
    opts = {**DEFAULTS, **(opts or {})}
    findings = []
    for domain, s in stats.items():
        reasons = []
        tunneling = (s["avg_entropy"] >= opts["entropy_threshold"]
                     and s["avg_subdomain_length"] >= opts["avg_len_threshold"]
                     and s["unique_subdomains"] >= opts["min_unique"])
        if tunneling:
            reasons.append("high-entropy unique subdomains (H=%.2f, avg_len=%.1f, unique=%d)"
                           % (s["avg_entropy"], s["avg_subdomain_length"], s["unique_subdomains"]))
        if s["max_label_length"] >= opts["long_label_threshold"]:
            reasons.append("very long label (%d chars)" % s["max_label_length"])
        if reasons:
            severity = "high" if s["avg_entropy"] >= opts["entropy_threshold"] + 0.5 or tunneling else "medium"
            findings.append({"domain": domain, "severity": severity,
                             "detail": "; ".join(reasons), **s})
    findings.sort(key=lambda f: (f["avg_entropy"], f["queries"]), reverse=True)
    return findings


def load_queries(path):
    fh = sys.stdin if path == "-" else open(path, encoding="utf-8", errors="replace")
    try:
        first = fh.readline()
        rest = fh.read()
    finally:
        if fh is not sys.stdin:
            fh.close()
    header = first.strip().lower()
    if "," in header and any(h in header for h in QUERY_COLUMN_HINTS):
        import io
        reader = csv.DictReader(io.StringIO(first + rest))
        col = next((c for c in reader.fieldnames if c.strip().lower() in QUERY_COLUMN_HINTS), None)
        return [row[col] for row in reader if row.get(col)]
    lines = [first] + rest.splitlines()
    out = []
    for line in lines:
        line = line.strip()
        if line:
            out.append(line.split()[-1])  # last token handles "ts src qname" style lines
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description="Detect likely DNS tunneling/exfiltration from query logs.")
    parser.add_argument("logfile", help="DNS query log ('-' for stdin)")
    parser.add_argument("--json", dest="json_out", help="write findings to this JSON file")
    parser.add_argument("--entropy-threshold", type=float, default=DEFAULTS["entropy_threshold"])
    parser.add_argument("--min-unique", type=int, default=DEFAULTS["min_unique"])
    args = parser.parse_args(argv)

    queries = load_queries(args.logfile)
    stats = analyze(queries)
    findings = detect(stats, {"entropy_threshold": args.entropy_threshold, "min_unique": args.min_unique})

    if not findings:
        sys.stdout.write("no DNS tunneling indicators found across %d domain(s)\n" % len(stats))
    for f in findings:
        sys.stdout.write("[%-8s] %-30s %s\n" % (f["severity"].upper(), f["domain"], f["detail"]))
    sys.stderr.write("\n%d queries, %d domains, %d flagged\n" % (len(queries), len(stats), len(findings)))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as out:
            json.dump(findings, out, indent=2)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
