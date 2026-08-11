# dns-exfil-detector

[![CI](https://github.com/1B05H1N/dns-exfil-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/1B05H1N/dns-exfil-detector/actions/workflows/ci.yml)

Detect likely DNS tunneling / exfiltration from query logs. Groups queries by
registered domain and scores each on subdomain entropy, length, and uniqueness -
the fingerprints of data smuggled through DNS. Pure Python standard library, no
dependencies.

> **Goal:** surface the one domain in millions of DNS queries that is actually a
> covert channel, using statistics rather than a signature.

## What it does

- Parses DNS query logs (plain list, `ts src qname` lines, or CSV with a `query`/`qname` column)
- Groups by registered domain (last-two-labels heuristic)
- Computes per-domain: query count, unique subdomains, average subdomain entropy and length, longest label
- Flags domains with high-entropy, long, highly-unique subdomains, or abnormally long labels
- Severity-ranked output, optional JSON

## Files

- `dns_exfil.py` - CLI and detection engine
- `sample-dns.log` - synthetic log (benign traffic + one tunnel; generated)
- `test_dns_exfil.py` - unit tests

## Usage

```bash
python3 dns_exfil.py sample-dns.log
python3 dns_exfil.py queries.csv --entropy-threshold 3.8 --json findings.json
cat resolver.log | python3 dns_exfil.py -
```

## Test

```bash
python3 -m unittest -v
```

## Disclaimer

This repository reflects personal study and practice; the sample log is
synthetic. The registered-domain grouping is a heuristic (no Public Suffix
List), and entropy scoring produces false positives on legitimately random
subdomains (some CDNs, telemetry). Tune thresholds and review results. Provided
as-is.

## License

MIT. See [LICENSE](LICENSE).
