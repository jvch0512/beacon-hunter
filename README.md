# beacon-hunter

Find command-and-control beaconing in connection logs. Malware that phones home on a timer leaves a statistical fingerprint: regular intervals, near-constant request sizes, long persistence. beacon-hunter measures that fingerprint, tolerates attacker jitter, and explains every score.

**Live demo:** https://jvch0512.github.io/beacon-hunter/ (a report generated from synthetic data)

Rust, zero dependencies, one static binary, offline.

## Use

```bash
cargo build --release
./target/release/beacon-hunter examples/conn.csv                 # text report
./target/release/beacon-hunter conn.csv --html > report.html     # shareable report
./target/release/beacon-hunter conn.csv --json                   # for pipelines
./target/release/beacon-hunter conn.csv --allow updates.vendor.example --min-score 70
./target/release/beacon-hunter conn.csv --fail-on-find           # exit 1 in CI or scheduled hunts
```

Input is a CSV with `ts,src,dst,dport,bytes_out,bytes_in` (epoch seconds). Zeek `conn.log`, firewall or proxy exports convert with one `awk` or `jq` line. See [examples/conn.csv](examples/conn.csv) and [docs/sample-output.txt](docs/sample-output.txt).

## How the score works

Connections are grouped by source, destination and port. For each group with enough connections:

| Signal | Weight | Why |
|---|---|---|
| Interval regularity (median absolute deviation over the median) | 45 | Robust to jitter and outliers: a beacon with 20% jitter still reads as regular |
| Request size consistency | 20 | Check-ins send similar small messages |
| Skew of the interval distribution (Bowley) | 10 | Fixed interval plus symmetric jitter is symmetric, human traffic is not |
| Persistence (count and span) | 15 | Beacons run for hours or days |
| Small payloads | 10 | Tasking and check-ins are small |

Large regular transfers are scored down (updates and backups), and sub-5-second intervals too (legitimate polling). The method follows the same ideas used by open tools such as RITA.

## Limits

- Timing statistics produce candidates, not verdicts. Updaters, monitoring agents and NTP are regular too: allowlist them and triage the rest (owner of the destination, process, reputation).
- Attackers can add heavy jitter or random sleeps. Raise `--min-conns`, lower `--min-score`, and combine with DNS and TLS-fingerprint hunting.
- Encrypted traffic is fine: only metadata is used.

## Where it fits

Threat hunting, MDR and SOC engagements, purple-team debriefs and incident response. A natural paid add-on for a managed detection service: schedule it over daily proxy or firewall exports and ship the HTML report.

## Tests

```bash
cargo test --release   # 11 tests: exact and jittered beacons, human traffic, allowlist, parser errors, HTML escaping, sample data
```

MIT.
