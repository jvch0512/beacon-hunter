use beacon_hunter::{analyze, parse_csv, render_html, render_text, Options};
use std::{env, fs, process::exit};

const USAGE: &str = "beacon-hunter <conn.csv> [--min-conns N] [--min-score N] [--allow dst]... [--html | --json] [--fail-on-find]\n\nCSV columns: ts,src,dst,dport,bytes_out,bytes_in (ts in epoch seconds). Offline.\nExit codes: 0 ok, 1 findings (with --fail-on-find), 2 bad input.";

fn main() {
    let a: Vec<String> = env::args().skip(1).collect();
    if a.is_empty() || a[0].starts_with("--") { eprintln!("{}", USAGE); exit(2); }
    let mut o = Options::default();
    let (mut html, mut json, mut fail) = (false, false, false);
    let mut i = 1;
    while i < a.len() {
        match a[i].as_str() {
            "--html" => html = true, "--json" => json = true, "--fail-on-find" => fail = true,
            "--min-conns" | "--min-score" | "--allow" => {
                let v = a.get(i + 1).unwrap_or_else(|| { eprintln!("error: {} needs a value", a[i]); exit(2) }).clone(); i += 1;
                match a[i - 1].as_str() { "--min-conns" => o.min_conns = v.parse().unwrap_or_else(|_| { eprintln!("error: bad number"); exit(2) }), "--min-score" => o.min_score = v.parse().unwrap_or_else(|_| { eprintln!("error: bad number"); exit(2) }), _ => o.allow.push(v) }
            }
            x => { eprintln!("error: unknown option {}\n{}", x, USAGE); exit(2) }
        }
        i += 1;
    }
    if o.min_conns < 4 { eprintln!("error: --min-conns must be at least 4"); exit(2); }
    let text = fs::read_to_string(&a[0]).unwrap_or_else(|e| { eprintln!("error: {}: {}", a[0], e); exit(2) });
    let conns = parse_csv(&text).unwrap_or_else(|e| { eprintln!("error: {}", e); exit(2) });
    let fs_ = analyze(&conns, &o);
    if html { print!("{}", render_html(&fs_, conns.len())); }
    else if json {
        println!("[{}]", fs_.iter().map(|f| format!("{{\"src\":\"{}\",\"dst\":\"{}\",\"dport\":{},\"count\":{},\"median_interval\":{:.1},\"jitter_pct\":{:.1},\"score\":{}}}", f.src, f.dst, f.dport, f.count, f.median_interval, f.jitter_pct, f.score)).collect::<Vec<_>>().join(","));
    } else { print!("{}", render_text(&fs_)); }
    if fail && !fs_.is_empty() { exit(1); }
}
