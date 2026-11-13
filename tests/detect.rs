use beacon_hunter::*;

fn lcg(seed: &mut u64) -> f64 { *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); ((*seed >> 33) as f64) / ((1u64 << 31) as f64) }

fn beacon(n: usize, every: f64, jitter: f64, size: u64) -> Vec<Conn> {
    let mut s = 42u64; let mut t = 1_000_000.0;
    (0..n).map(|_| { t += every * (1.0 + jitter * (lcg(&mut s) * 2.0 - 1.0)); Conn { ts: t, src: "10.0.0.5".into(), dst: "203.0.113.9".into(), dport: 443, bytes_out: size, bytes_in: 500 } }).collect()
}
fn human(n: usize) -> Vec<Conn> {
    let mut s = 7u64; let mut t = 1_000_000.0;
    (0..n).map(|_| { t += -(1.0 - lcg(&mut s)).max(1e-9).ln() * 120.0; Conn { ts: t, src: "10.0.0.6".into(), dst: "www.example.org".into(), dport: 443, bytes_out: 400 + (lcg(&mut s) * 60000.0) as u64, bytes_in: 5000 } }).collect()
}

#[test] fn detects_exact_beacon() { let f = analyze(&beacon(60, 60.0, 0.0, 300), &Options::default()); assert_eq!(f.len(), 1); assert!(f[0].score >= 85); assert!((f[0].median_interval - 60.0).abs() < 0.01); }
#[test] fn detects_beacon_with_20pct_jitter() { let f = analyze(&beacon(120, 60.0, 0.2, 300), &Options::default()); assert_eq!(f.len(), 1); assert!(f[0].jitter_pct < 15.0); }
#[test] fn ignores_human_browsing() { assert!(analyze(&human(400), &Options::default()).is_empty()); }
#[test] fn too_few_connections_are_ignored() { assert!(analyze(&beacon(6, 60.0, 0.0, 300), &Options::default()).is_empty()); }
#[test] fn allowlist_removes_destination() { let o = Options { allow: vec!["203.0.113.9".into()], ..Options::default() }; assert!(analyze(&beacon(60, 60.0, 0.0, 300), &o).is_empty()); }
#[test] fn large_regular_transfers_score_lower_than_small_beacons() {
    let small = analyze(&beacon(60, 3600.0, 0.0, 300), &Options::default())[0].score;
    let big = analyze(&beacon(60, 3600.0, 0.0, 3_000_000), &Options { min_score: 0, ..Options::default() })[0].score;
    assert!(big < small);
}
#[test] fn groups_are_separate_per_destination() { let mut v = beacon(40, 60.0, 0.0, 300); for c in beacon(40, 300.0, 0.0, 300).iter_mut() { c.dst = "198.51.100.1".into(); v.push(c.clone()); } assert_eq!(analyze(&v, &Options::default()).len(), 2); }
#[test] fn csv_parser_rejects_missing_columns() { assert!(parse_csv("ts,src\n1,a").is_err()); assert!(parse_csv("").is_err()); }
#[test] fn csv_parser_reports_bad_lines() { let e = parse_csv("ts,src,dst,dport,bytes_out,bytes_in\nx,a,b,1,2,3").unwrap_err(); assert!(e.0.contains("line 2")); }
#[test] fn html_escapes_hostile_values() { let f = Finding { src: "<script>".into(), dst: "a\"b".into(), dport: 1, count: 9, median_interval: 1.0, interval_cv: 0.0, jitter_pct: 0.0, size_cv: 0.0, skew: 0.0, span_hours: 1.0, score: 90, reasons: vec!["<b>".into()] }; let h = render_html(&[f], 9); assert!(!h.contains("<script>") && h.contains("&lt;script&gt;")); }
#[test] fn sample_file_finds_two_real_beacons_and_the_updater() {
    let c = parse_csv(&std::fs::read_to_string("examples/conn.csv").unwrap()).unwrap();
    let f = analyze(&c, &Options::default());
    assert!(f.iter().any(|x| x.dst == "203.0.113.50") && f.iter().any(|x| x.dst == "198.51.100.77"));
    assert!(!f.iter().any(|x| x.dst == "www.example.org"));
    let g = analyze(&c, &Options { allow: vec!["updates.vendor.example".into()], ..Options::default() });
    assert_eq!(g.len(), 2);
}
