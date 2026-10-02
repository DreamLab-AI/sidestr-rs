//! A loopback sidechain for the Hitch host: the reference producer
//! (`siding produce`, 2-second blocks) on a chain whose first 100 blocks are
//! minted here, so the genesis pegs are mature at once; an in-process relay
//! (`sidestr_round::relay::RelayStandIn`); and agents, each a separate
//! `sidestr-agent` process with its own keys and state directory.
//!
//! The producer is the JavaScript reference (`SIDESTR_SIDING`, `SCHEMA`,
//! `BLAKETESTNODE`), the engine the estate runs. Every run ends with
//! [`replays_in_rust`]: `sidestr-core` (which judges Hitch's leaves since
//! stream S1) replays the producer's block file to the producer's tip.
//! Without those checkouts every test here skips and says so.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bitcoin::secp256k1::SecretKey;
use serde_json::{json, Value};
use sidestr_core::block::{challenge_for, pubkey_of, HeaderFamily, SidestrBlock, Stock};
use sidestr_core::blockfile::{append_block, write_index, Index};
use sidestr_core::document::ChainDocument;
use sidestr_core::state::{NextBlock, StateOf};
use sidestr_header::Blake2bV2;

/// The block interval, seconds.
pub const BLOCK_SECS: u64 = 2;

/// The reference checkouts.
#[derive(Clone, Debug)]
pub struct Upstream {
    pub siding: PathBuf,
    pub schema: String,
    pub blaketestnode: String,
}

/// The checkouts from the environment, or `None` (the test skips).
pub fn upstream() -> Option<Upstream> {
    let siding = PathBuf::from(std::env::var("SIDESTR_SIDING").ok()?);
    let schema = std::env::var("SCHEMA").ok()?;
    let blaketestnode = std::env::var("BLAKETESTNODE").ok()?;
    if !siding.join("bin/siding.mjs").exists() {
        eprintln!("SIDESTR_SIDING={} has no bin/siding.mjs", siding.display());
        return None;
    }
    Some(Upstream {
        siding,
        schema,
        blaketestnode,
    })
}

pub fn skip_unless_upstream() -> Option<Upstream> {
    let u = upstream();
    if u.is_none() {
        eprintln!(
            "skipped: set SIDESTR_SIDING, SCHEMA and BLAKETESTNODE to run the loopback siding"
        );
    }
    u
}

pub fn random_secret() -> SecretKey {
    loop {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).unwrap();
        if let Ok(k) = SecretKey::from_slice(&b) {
            return k;
        }
    }
}

pub fn write_key(path: &Path, key: &SecretKey) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, format!("{}\n", hex::encode(key.secret_bytes()))).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn scratch(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("sidestr-hitch-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

pub fn http_get(url: &str) -> Option<String> {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(10)))
            .build(),
    );
    agent
        .get(url)
        .call()
        .ok()
        .and_then(|mut r| r.body_mut().read_to_string().ok())
}

/// Poll `f` every 250 ms until it is true or `secs` pass.
pub fn wait_until(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    f()
}

/// The reference producer on loopback.
pub struct Producer {
    u: Upstream,
    child: Option<Child>,
    pub dir: PathBuf,
    pub chain: PathBuf,
    key: PathBuf,
    pub port: u16,
    relay: String,
    log: PathBuf,
    starts: u32,
}

impl Producer {
    /// A chain whose genesis pegs `pegs` (script hex, sats), 100 blocks
    /// minted in Rust so they are spendable, then the reference producer
    /// running on it at 2-second blocks, following `relay` for kind 23500.
    ///
    /// `parent` is `tbtc4` (stock headers) or `txbt4` (BLAKE2b v2 headers,
    /// the family of `sidestr:dreamlab-txbt4`).
    pub fn seed(
        u: &Upstream,
        at: &Path,
        parent: &str,
        pegs: &[(String, u64)],
        relay: &str,
    ) -> Self {
        let dir = at.join("chain");
        std::fs::create_dir_all(&dir).unwrap();
        let signer = random_secret();
        let key = at.join("producer.key");
        write_key(&key, &signer);
        let pubkey = pubkey_of(&signer);
        let genesis_time = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3_600) as u32;
        let pegs: Vec<Value> = pegs
            .iter()
            .enumerate()
            .map(|(i, (script, amount))| {
                json!({"txid": "ab".repeat(32), "vout": i, "amount": amount, "script": script})
            })
            .collect();
        let doc = json!({
            "id": "sidestr:hitchloop", "name": "hitchloop", "parent": parent,
            "comment": "A loopback chain for the Hitch host tests. Coins with no value.",
            "challenge": challenge_for(&pubkey).to_hex_string(), "signer": pubkey.to_string(),
            "powLimit": "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "addressPrefix": "hl", "magic": "0badc0de", "pegConfirmations": 6, "refundBlocks": 10000,
            "pegoutBlocks": 144, "pegoutMin": 10000, "minFeeRate": 1,
            "genesisTime": genesis_time, "pegs": pegs,
        });
        let chain = at.join("chain.json");
        std::fs::write(&chain, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
        // the first 100 blocks, minted here: the genesis pegs mature at 100
        let parsed = ChainDocument::from_json(&serde_json::to_string(&doc).unwrap()).unwrap();
        let mut index = Index::new(&parsed.id);
        let dat = dir.join("blocks.dat");
        match parent {
            "txbt4" | "xbt" => mint(&Blake2bV2, &parsed, &signer, &dat, &mut index, genesis_time),
            _ => mint(&Stock, &parsed, &signer, &dat, &mut index, genesis_time),
        }
        write_index(dir.join("blocks.json"), &index).unwrap();
        let mut p = Self {
            u: u.clone(),
            child: None,
            dir,
            chain,
            key,
            port: free_port(),
            relay: relay.to_string(),
            log: at.join("producer.log"),
            starts: 0,
        };
        p.start();
        p
    }

    /// Start (or restart) the producer on its port and wait for `/tip`.
    pub fn start(&mut self) {
        self.starts += 1;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        let child = Command::new("node")
            .arg(self.u.siding.join("bin/siding.mjs"))
            .arg("produce")
            .args(["--chain", &self.chain.display().to_string()])
            .args(["--dir", &self.dir.display().to_string()])
            .args(["--key-file", &self.key.display().to_string()])
            .args(["--port", &self.port.to_string()])
            .args(["--interval", &BLOCK_SECS.to_string()])
            .args(["--tx-interval", &BLOCK_SECS.to_string()])
            .args(["--relay", &self.relay])
            .env("SCHEMA", &self.u.schema)
            .env("BLAKETESTNODE", &self.u.blaketestnode)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("node");
        self.child = Some(child);
        assert!(
            wait_until(60, || self.tip().is_some()),
            "the producer did not start:\n{}",
            self.log_tail(40)
        );
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn tip(&self) -> Option<(u32, String)> {
        let v: Value = serde_json::from_str(&http_get(&format!("{}/tip", self.url()))?).ok()?;
        Some((
            v["height"].as_u64()? as u32,
            v["hash"].as_str()?.to_string(),
        ))
    }

    /// The tip height as written to disk: readable while the producer is
    /// paused, when `/tip` cannot answer.
    pub fn disk_height(&self) -> u32 {
        let text = std::fs::read_to_string(self.dir.join("blocks.json")).unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        v["to"].as_u64().unwrap() as u32
    }

    pub fn height(&self) -> u32 {
        self.tip().map(|t| t.0).unwrap_or(0)
    }

    /// Coins on a script, as the producer lists them.
    pub fn coins(&self, script_hex: &str) -> Vec<Value> {
        http_get(&format!("{}/coins/{script_hex}", self.url()))
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn signal(&self, sig: &str) {
        if let Some(c) = &self.child {
            Command::new("kill")
                .args([sig, &c.id().to_string()])
                .status()
                .unwrap();
        }
    }

    /// Freeze block production.
    pub fn pause(&self) {
        self.signal("-STOP");
    }

    /// Resume after [`Producer::pause`].
    pub fn resume(&self) {
        self.signal("-CONT");
    }

    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            self.signal_child(&mut c);
        }
    }

    fn signal_child(&self, c: &mut Child) {
        let _ = Command::new("kill")
            .args(["-CONT", &c.id().to_string()])
            .status();
        let _ = c.kill();
        let _ = c.wait();
    }

    /// Copy the chain directory (with the producer paused, so the copy is
    /// consistent).
    pub fn snapshot(&self, to: &Path) {
        self.pause();
        copy_dir(&self.dir, to);
        self.resume();
    }

    /// Stop, put a snapshot back, start: the chain reorganises from the
    /// snapshot's tip.
    pub fn restart_from(&mut self, snapshot: &Path) {
        self.stop();
        std::fs::remove_dir_all(&self.dir).unwrap();
        copy_dir(snapshot, &self.dir);
        self.start();
    }

    pub fn log_tail(&self, n: usize) -> String {
        let l = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = l.lines().collect();
        lines[lines.len().saturating_sub(n)..].join("\n")
    }
}

impl Drop for Producer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The genesis and 100 empty blocks of family `F`, appended to the block file.
fn mint<F: HeaderFamily>(
    family: &F,
    doc: &ChainDocument,
    signer: &SecretKey,
    dat: &Path,
    index: &mut Index,
    genesis_time: u32,
) {
    let genesis = StateOf::<F>::genesis_block_for(doc, signer).unwrap();
    let hash = family.block_hash(genesis.header()).to_string();
    append_block(dat, index, 0, &hash, &genesis.encode()).unwrap();
    let mut state = StateOf::<F>::with_key(doc.clone(), signer).unwrap();
    for i in 1..=100u32 {
        let (_, b) = state
            .produce(
                signer,
                &NextBlock {
                    time: genesis_time + i,
                    claims: vec![],
                },
                None,
            )
            .unwrap();
        let hash = family.block_hash(b.header()).to_string();
        append_block(dat, index, i, &hash, &b.encode()).unwrap();
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

/// An agent: its own identity key, spend key, state directory and process.
pub struct Agent {
    pub name: String,
    pub state: PathBuf,
    pub identity_file: PathBuf,
    pub spend_file: Option<PathBuf>,
    pub url: String,
    pub relays: String,
    pub spend: String,
    pub did: String,
    watch: Option<Child>,
    log: PathBuf,
}

impl Agent {
    /// An agent whose spend key is minted here (so a genesis can peg to it
    /// before the chain exists); `bind` takes it with `--key-file`.
    pub fn with_spend_key(at: &Path, name: &str) -> Self {
        let dir = at.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let identity_file = dir.join("identity.key");
        write_key(&identity_file, &random_secret());
        let spend = random_secret();
        let spend_file = dir.join("spend-given.key");
        write_key(&spend_file, &spend);
        Self {
            name: name.into(),
            state: dir.join("state"),
            identity_file,
            spend_file: Some(spend_file),
            url: String::new(),
            relays: String::new(),
            spend: pubkey_of(&spend).to_string(),
            did: String::new(),
            watch: None,
            log: dir.join("watch.log"),
        }
    }

    /// An agent whose spend key `bind` mints into its state directory.
    pub fn minting(at: &Path, name: &str) -> Self {
        let mut a = Self::with_spend_key(at, name);
        a.spend_file = None;
        a.spend = String::new();
        a
    }

    /// The script the spend key's coins pay: `OP_1 <spend key>`.
    pub fn script(&self) -> String {
        format!("5120{}", self.spend)
    }

    fn base(&self) -> Vec<String> {
        let mut v = vec![
            "--url".into(),
            self.url.clone(),
            "--relays".into(),
            self.relays.clone(),
            "--state".into(),
            self.state.display().to_string(),
            "--poll-ms".into(),
            "500".into(),
        ];
        if let Some(k) = &self.spend_file {
            v.push("--key-file".into());
            v.push(k.display().to_string());
        }
        v
    }

    /// `hitch bind --identity-file … --publish`.
    pub fn bind(&mut self, url: &str, relays: &str) -> Value {
        self.url = url.into();
        self.relays = relays.into();
        let v = self
            .hitch(&[
                "bind",
                "--identity-file",
                &self.identity_file.display().to_string(),
                "--publish",
            ])
            .unwrap_or_else(|e| panic!("{} bind: {e}", self.name));
        self.spend = v["spend"].as_str().unwrap().to_string();
        self.did = v["did"].as_str().unwrap().to_string();
        assert_ne!(v["identity"], v["spend"], "k_spend is not k_id");
        v
    }

    /// Run `sidestr-agent hitch <args>`; its JSON, or its error text.
    pub fn hitch(&self, args: &[&str]) -> Result<Value, String> {
        let out = Command::new(env!("CARGO_BIN_EXE_sidestr-agent"))
            .arg("hitch")
            .args(args)
            .args(self.base())
            .env("SIDESTR_HITCH_DEVELOPER", "1")
            .output()
            .expect("sidestr-agent");
        if out.status.success() {
            serde_json::from_slice(&out.stdout)
                .map_err(|e| format!("{e}: {}", String::from_utf8_lossy(&out.stdout)))
        } else {
            Err(String::from_utf8_lossy(&out.stderr).to_string())
        }
    }

    /// Start `hitch watch` with `extra` flags and wait for its socket.
    pub fn watch(&mut self, extra: &[&str]) {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_sidestr-agent"))
            .args(["hitch", "watch"])
            .args(extra)
            .args(self.base())
            .env("SIDESTR_HITCH_DEVELOPER", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        self.watch = Some(child);
        let sock = self.state.join("control.sock");
        assert!(
            wait_until(30, || sock.exists()),
            "{} watch did not start:\n{}",
            self.name,
            self.log_tail(30)
        );
    }

    /// Kill the daemon (no clean stop: as a crash would).
    pub fn kill(&mut self) {
        if let Some(mut c) = self.watch.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    pub fn status(&self) -> Value {
        self.hitch(&["status"]).unwrap_or(Value::Null)
    }

    /// One channel as the running host last saw it (`status.json`).
    pub fn channel(&self, id: &str) -> Option<Value> {
        let s = self.status();
        s["host"]["channels"]
            .as_array()?
            .iter()
            .find(|c| c["channel"] == id)
            .cloned()
    }

    pub fn channel_status(&self, id: &str) -> String {
        self.channel(id)
            .and_then(|c| c["status"].as_str().map(str::to_string))
            .unwrap_or_default()
    }

    pub fn journal(&self) -> Vec<Value> {
        std::fs::read_to_string(self.state.join("journal.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    pub fn log_tail(&self, n: usize) -> String {
        let l = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = l.lines().collect();
        lines[lines.len().saturating_sub(n)..].join("\n")
    }

    /// The journal's lines of one kind.
    pub fn journal_of(&self, ev: &str) -> Vec<Value> {
        self.journal()
            .into_iter()
            .filter(|j| j["ev"] == ev)
            .collect()
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Stream S1's check, after a channel run: `sidestr-core` replays the
/// producer's block file (read while the producer is paused, cut at the
/// index's last record) and must reach the producer's tip hash. A Rust
/// validator, a forum wallet among them, then agrees with the producer
/// about every channel spend in it. Returns the height replayed.
pub fn replays_in_rust(p: &Producer) -> u32 {
    p.pause();
    let dat = std::fs::read(p.dir.join("blocks.dat")).unwrap();
    let index: Index =
        serde_json::from_str(&std::fs::read_to_string(p.dir.join("blocks.json")).unwrap()).unwrap();
    p.resume();
    let last = index.blocks.last().unwrap();
    let end = (last.offset + 8 + u64::from(last.size)) as usize;
    let doc = ChainDocument::from_json(&std::fs::read_to_string(&p.chain).unwrap()).unwrap();
    let (height, hash) = match doc.family().unwrap() {
        sidestr_core::parents::Family::Stock => {
            let s = StateOf::<Stock>::replay(doc, &dat[..end], None)
                .unwrap_or_else(|e| panic!("sidestr-core refuses the producer's chain: {e}"));
            (s.height(), s.hash_at(s.height()).unwrap().to_string())
        }
        sidestr_core::parents::Family::Blake2b => {
            let s = StateOf::<Blake2bV2>::replay(doc, &dat[..end], None)
                .unwrap_or_else(|e| panic!("sidestr-core refuses the producer's chain: {e}"));
            (s.height(), s.hash_at(s.height()).unwrap().to_string())
        }
    };
    assert_eq!(height, last.height);
    assert_eq!(
        hash, last.hash,
        "sidestr-core and the producer disagree at {height}"
    );
    eprintln!("sidestr-core replayed the producer's chain to {height} {hash}");
    height
}

/// Sum of the coins a script holds at the producer.
pub fn balance(p: &Producer, script: &str) -> u64 {
    p.coins(script)
        .iter()
        .filter_map(|c| c["value"].as_u64())
        .sum()
}

/// Print a receipt of a run: what the lead's records cite.
pub fn receipt(label: &str, agents: &[&Agent], channel: &str) {
    eprintln!("=== receipt: {label} (channel {channel})");
    for a in agents {
        eprintln!("--- {} spend {} {}", a.name, a.spend, a.did);
        for j in a.journal() {
            if matches!(
                j["ev"].as_str(),
                Some(
                    "sent"
                        | "broadcast"
                        | "funding-spent"
                        | "funded"
                        | "reorg"
                        | "spend-undone"
                        | "repaired"
                        | "binding-resolved"
                )
            ) {
                eprintln!("{j}");
            }
        }
    }
}

/// One `POST /tx` the proxy saw.
#[derive(Debug, Clone)]
pub struct Posted {
    /// The transaction.
    pub tx: bitcoin::Transaction,
    /// The producer's tip height when it arrived.
    pub tip: u32,
    /// Whether the proxy refused it.
    pub refused: bool,
}

/// A proxy in front of the producer that refuses the **first** `POST /tx`
/// of every txid with "rejected this session", as siding from `c3b9e7a`
/// does for bytes it refused or evicted, and forwards everything else. It
/// records every posted transaction with the producer's tip at that moment.
pub struct RefusingProxy {
    pub port: u16,
    pub posts: std::sync::Arc<std::sync::Mutex<Vec<Posted>>>,
}

impl RefusingProxy {
    pub fn start(upstream: u16) -> Self {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let posts: std::sync::Arc<std::sync::Mutex<Vec<Posted>>> = Default::default();
        let seen: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<bitcoin::Txid>>> =
            Default::default();
        let (p2, s2) = (posts.clone(), seen.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (posts, seen) = (p2.clone(), s2.clone());
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        return;
                    }
                    let mut parts = line.split_whitespace();
                    let (method, path) = (
                        parts.next().unwrap_or("").to_string(),
                        parts.next().unwrap_or("/").to_string(),
                    );
                    let (mut length, mut range) = (0usize, None);
                    loop {
                        let mut h = String::new();
                        if reader.read_line(&mut h).is_err() || h.trim().is_empty() {
                            break;
                        }
                        let lower = h.to_ascii_lowercase();
                        if let Some(v) = lower.strip_prefix("content-length:") {
                            length = v.trim().parse().unwrap_or(0);
                        }
                        if lower.starts_with("range:") {
                            range = Some(h[6..].trim().to_string());
                        }
                    }
                    let mut body = vec![0u8; length];
                    let _ = reader.read_exact(&mut body);
                    let base = format!("http://127.0.0.1:{upstream}");
                    let agent = ureq::Agent::new_with_config(
                        ureq::Agent::config_builder()
                            .http_status_as_error(false)
                            .timeout_global(Some(Duration::from_secs(20)))
                            .build(),
                    );
                    let (status, out) = if method == "POST" && path == "/tx" {
                        let hex = String::from_utf8_lossy(&body).trim().to_string();
                        let tx: Option<bitcoin::Transaction> =
                            bitcoin::consensus::encode::deserialize_hex(&hex).ok();
                        let tip = http_get(&format!("{base}/tip"))
                            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
                            .and_then(|v| v["height"].as_u64())
                            .unwrap_or(0) as u32;
                        let first = tx
                            .as_ref()
                            .is_some_and(|t| seen.lock().unwrap().insert(t.compute_txid()));
                        if let Some(tx) = tx {
                            posts.lock().unwrap().push(Posted {
                                tx,
                                tip,
                                refused: first,
                            });
                        }
                        if first {
                            (
                                400,
                                br#"{"error":"rejected this session (refusing proxy)"}"#.to_vec(),
                            )
                        } else {
                            match agent
                                .post(&format!("{base}/tx"))
                                .content_type("text/plain")
                                .send(&body[..])
                            {
                                Ok(mut r) => (
                                    r.status().as_u16(),
                                    r.body_mut().read_to_vec().unwrap_or_default(),
                                ),
                                Err(_) => (502, vec![]),
                            }
                        }
                    } else {
                        let mut req = agent.get(&format!("{base}{path}"));
                        if let Some(r) = &range {
                            req = req.header("range", r);
                        }
                        match req.call() {
                            Ok(mut r) => (
                                r.status().as_u16(),
                                r.body_mut()
                                    .with_config()
                                    .limit(256 * 1024 * 1024)
                                    .read_to_vec()
                                    .unwrap_or_default(),
                            ),
                            Err(_) => (502, vec![]),
                        }
                    };
                    let head = format!(
                        "HTTP/1.1 {status} X\r\ncontent-length: {}\r\ncontent-type: application/octet-stream\r\nconnection: close\r\n\r\n",
                        out.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(&out);
                });
            }
        });
        Self { port, posts }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

/// Every block's height for each transaction in the producer's chain.
pub fn heights(p: &Producer) -> std::collections::HashMap<bitcoin::Txid, u32> {
    let dat = std::fs::read(p.dir.join("blocks.dat")).unwrap();
    let doc = ChainDocument::from_json(&std::fs::read_to_string(&p.chain).unwrap()).unwrap();
    let header = match doc.family().unwrap() {
        sidestr_core::parents::Family::Stock => 80,
        sidestr_core::parents::Family::Blake2b => 164,
    };
    let mut out = std::collections::HashMap::new();
    for r in sidestr_core::mirror::records(&dat).unwrap_or_default() {
        if let Ok(txs) =
            bitcoin::consensus::deserialize::<Vec<bitcoin::Transaction>>(&r.bytes[header..])
        {
            for t in txs {
                out.insert(t.compute_txid(), r.height);
            }
        }
    }
    out
}
