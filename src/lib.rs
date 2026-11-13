//! beacon-hunter: statistical detection of command-and-control beaconing in connection logs.
use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone)]
pub struct Conn { pub ts: f64, pub src: String, pub dst: String, pub dport: u16, pub bytes_out: u64, pub bytes_in: u64 }

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub src: String, pub dst: String, pub dport: u16, pub count: usize,
    pub median_interval: f64, pub interval_cv: f64, pub jitter_pct: f64, pub size_cv: f64, pub skew: f64,
    pub span_hours: f64, pub score: u32, pub reasons: Vec<String>,
}

#[derive(Debug)]
pub struct ParseError(pub String);
impl std::fmt::Display for ParseError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) } }

pub struct Options { pub min_conns: usize, pub min_score: u32, pub allow: Vec<String> }
impl Default for Options { fn default() -> Self { Options { min_conns: 8, min_score: 60, allow: vec![] } } }

/// CSV with header: ts,src,dst,dport,bytes_out,bytes_in (ts in epoch seconds).
pub fn parse_csv(text: &str) -> Result<Vec<Conn>, ParseError> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let head = lines.next().ok_or_else(|| ParseError("empty input".into()))?;
    let cols: Vec<&str> = head.split(',').map(|c| c.trim()).collect();
    let idx = |n: &str| cols.iter().position(|c| *c == n).ok_or_else(|| ParseError(format!("missing column \"{}\" (need ts,src,dst,dport,bytes_out,bytes_in)", n)));
    let (t, s, d, p, bo, bi) = (idx("ts")?, idx("src")?, idx("dst")?, idx("dport")?, idx("bytes_out")?, idx("bytes_in")?);
    let mut out = Vec::new();
    for (n, l) in lines.enumerate() {
        let f: Vec<&str> = l.split(',').map(|c| c.trim()).collect();
        let g = |i: usize| f.get(i).copied().ok_or_else(|| ParseError(format!("line {}: too few fields", n + 2)));
        let num = |i: usize, w: &str| g(i)?.parse::<f64>().map_err(|_| ParseError(format!("line {}: bad {}", n + 2, w)));
        out.push(Conn { ts: num(t, "ts")?, src: g(s)?.to_string(), dst: g(d)?.to_string(), dport: num(p, "dport")? as u16, bytes_out: num(bo, "bytes_out")? as u64, bytes_in: num(bi, "bytes_in")? as u64 });
    }
    Ok(out)
}

fn median(v: &mut Vec<f64>) -> f64 { v.sort_by(|a, b| a.partial_cmp(b).unwrap()); let n = v.len(); if n == 0 { 0.0 } else if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 } }
fn quantile(sorted: &[f64], q: f64) -> f64 { if sorted.is_empty() { return 0.0; } let pos = q * (sorted.len() - 1) as f64; let lo = pos.floor() as usize; let hi = pos.ceil() as usize; sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo as f64) }
fn mean_std(v: &[f64]) -> (f64, f64) { let n = v.len() as f64; let m = v.iter().sum::<f64>() / n; (m, (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / n).sqrt()) }

pub fn analyze(conns: &[Conn], o: &Options) -> Vec<Finding> {
    let mut groups: BTreeMap<(String, String, u16), Vec<&Conn>> = BTreeMap::new();
    for c in conns { if o.allow.iter().any(|a| a == &c.dst) { continue; } groups.entry((c.src.clone(), c.dst.clone(), c.dport)).or_default().push(c); }
    let mut out = Vec::new();
    for ((src, dst, dport), mut g) in groups {
        if g.len() < o.min_conns { continue; }
        g.sort_by(|a, b| a.ts.partial_cmp(&b.ts).unwrap());
        let mut iv: Vec<f64> = g.windows(2).map(|w| w[1].ts - w[0].ts).filter(|d| *d > 0.0).collect();
        if iv.len() < o.min_conns - 1 { continue; }
        let mut s = iv.clone(); s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let med = median(&mut iv);
        if med <= 0.0 { continue; }
        // jitter-tolerant: median absolute deviation relative to the median
        let mut dev: Vec<f64> = s.iter().map(|x| (x - med).abs()).collect();
        let mad = median(&mut dev);
        let jitter = mad / med;
        let (m, sd) = mean_std(&s);
        let cv = if m > 0.0 { sd / m } else { 9.9 };
        // Bowley skewness: near 0 means symmetric around the median, as a fixed interval with jitter is
        let (q1, q2, q3) = (quantile(&s, 0.25), quantile(&s, 0.5), quantile(&s, 0.75));
        let skew = if q3 - q1 > 0.0 { (q3 + q1 - 2.0 * q2) / (q3 - q1) } else { 0.0 };
        let sizes: Vec<f64> = g.iter().map(|c| c.bytes_out as f64).collect();
        let (sm, ssd) = mean_std(&sizes);
        let size_cv = if sm > 0.0 { ssd / sm } else { 0.0 };
        let span = (g.last().unwrap().ts - g[0].ts) / 3600.0;
        let mut reasons = Vec::new();
        let mut score = 0.0;
        let reg = (1.0 - (jitter / 0.35)).clamp(0.0, 1.0); score += 45.0 * reg;
        if jitter < 0.05 { reasons.push(format!("very regular interval: median {:.0}s, deviation {:.1}%", med, jitter * 100.0)); }
        else if jitter < 0.25 { reasons.push(format!("regular interval with jitter: median {:.0}s, deviation {:.0}%", med, jitter * 100.0)); }
        let sz = (1.0 - (size_cv / 0.5)).clamp(0.0, 1.0); score += 20.0 * sz;
        if size_cv < 0.15 { reasons.push(format!("near-constant request size (cv {:.2})", size_cv)); }
        let sk = (1.0 - skew.abs()).clamp(0.0, 1.0); score += 10.0 * sk * reg;
        let persist = ((g.len() as f64) / 40.0).min(1.0) * 0.5 + (span / 12.0).min(1.0) * 0.5; score += 15.0 * persist;
        if span >= 12.0 { reasons.push(format!("persisted {:.0} hours", span)); }
        let small = if sm < 2048.0 { 1.0 } else if sm < 20000.0 { 0.4 } else { 0.0 }; score += 10.0 * small;
        if sm < 2048.0 { reasons.push(format!("small payloads (mean {:.0} bytes out)", sm)); }
        if dport == 80 || dport == 443 || dport == 53 { reasons.push(format!("blends into port {}", dport)); }
        if sm > 1_000_000.0 { reasons.push("large transfers: looks more like updates or backups than command traffic".into()); score *= 0.7; }
        if med < 5.0 { reasons.push("sub-5s interval: also common for legitimate polling".into()); score *= 0.8; }
        let score = score.round() as u32;
        if score >= o.min_score {
            out.push(Finding { src, dst, dport, count: g.len(), median_interval: med, interval_cv: cv, jitter_pct: jitter * 100.0, size_cv, skew, span_hours: span, score, reasons });
        }
    }
    out.sort_by(|a, b| b.score.cmp(&a.score).then(a.dst.cmp(&b.dst)));
    out
}

pub fn render_text(fs: &[Finding]) -> String {
    let mut s = String::new();
    if fs.is_empty() { return "No beaconing above the threshold.\n".into(); }
    let _ = writeln!(s, "{:<5} {:<16} {:<22} {:>5} {:>6} {:>9} {:>7}", "score", "src", "dst:port", "conns", "every", "jitter", "span");
    for f in fs { let _ = writeln!(s, "{:<5} {:<16} {:<22} {:>5} {:>5.0}s {:>8.1}% {:>6.1}h", f.score, f.src, format!("{}:{}", f.dst, f.dport), f.count, f.median_interval, f.jitter_pct, f.span_hours); for r in &f.reasons { let _ = writeln!(s, "        - {}", r); } }
    s
}

fn esc(t: &str) -> String { t.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;") }

pub fn render_html(fs: &[Finding], total_conns: usize) -> String {
    let mut rows = String::new();
    for f in fs {
        let cls = if f.score >= 85 { "bad" } else if f.score >= 70 { "warn" } else { "ok" };
        let _ = write!(rows, "<tr><td class=\"{}\">{}</td><td>{}</td><td>{}:{}</td><td>{}</td><td>every {:.0}s</td><td>{:.1}%</td><td>{:.1}h</td><td>{}</td></tr>", cls, f.score, esc(&f.src), esc(&f.dst), f.dport, f.count, f.median_interval, f.jitter_pct, f.span_hours, esc(&f.reasons.join("; ")));
    }
    format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>beacon-hunter report</title><style>{}</style></head><body><h1>beacon-hunter</h1><p class=\"sub\">Statistical beaconing detection over {} connections. Rust, zero dependencies. This page is generated by <code>beacon-hunter examples/conn.csv --html</code> on synthetic data.</p><p><b>{}</b> candidate(s) above the threshold.</p><table><tr><th>Score</th><th>Source</th><th>Destination</th><th>Conns</th><th>Interval</th><th>Jitter</th><th>Span</th><th>Why</th></tr>{}</table><p class=\"sub\">A high score means the timing looks machine-driven, not that the host is malicious. Triage: who owns the destination, is it allowlisted software (updaters, monitoring), what process opens it.</p></body></html>\n", CSS, total_conns, fs.len(), rows)
}

const CSS: &str = ":root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}.sub{color:#8b98a8}table{border-collapse:collapse;width:100%;margin-top:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3441;vertical-align:top}th{color:#8b98a8;font-weight:600}td.bad{color:#f85149;font-weight:700}td.warn{color:#e3b341;font-weight:700}td.ok{color:#3fb950;font-weight:700}code{background:#161d26;padding:1px 5px;border-radius:4px}";
