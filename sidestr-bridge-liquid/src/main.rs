//! `usd-reserve`: the Liquid reserve wallet for the owner's private USD unit
//! (ADR-2117). Read-only apart from `init`, which writes a new key file; it
//! never signs, spends or broadcasts.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use sidestr_bridge_liquid::{
    attest, fetch_registry_entry, reserve_asset, validate_proxy_url, ReserveKey, ReserveWallet,
    Result, DEFAULT_ESPLORA_URL, ISSUER_SOURCE_URL, REGISTRY_URL,
};

const DISCLAIMER: &str = "Private USD unit of account of the owner's estate. No value, not \
redeemable, not offered to anyone. Not USD₮ or USDC and not issued, backed or endorsed by Tether \
or Circle. Not live: fund the reserve only on the owner's explicit go.";

/// The Liquid reserve wallet for the owner's private USD unit (ADR-2117).
#[derive(Parser)]
#[command(name = "usd-reserve", version, after_help = DISCLAIMER)]
struct Cli {
    /// Esplora API base URL of the Liquid mainnet server to sync from.
    #[arg(long, global = true, default_value = DEFAULT_ESPLORA_URL)]
    esplora_url: String,

    /// Route every request through this proxy, e.g. socks5h://127.0.0.1:9050
    /// for Tor. socks5:// is refused (it resolves names outside the proxy).
    #[arg(long, global = true)]
    proxy: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new 24-word reserve mnemonic into a new file, mode 0400.
    /// Refuses if the file exists. Prints nothing secret.
    Init {
        /// Where to write the mnemonic (the directory must exist).
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Print a confidential receive address.
    Address {
        /// The key file.
        #[arg(long)]
        key_file: PathBuf,
        /// Derivation index on the external chain (offline). Default 0.
        #[arg(long, conflicts_with = "next")]
        index: Option<u32>,
        /// Sync first, then print the first address not yet used.
        #[arg(long)]
        next: bool,
    },
    /// Print the CT descriptor: public, cannot spend, but holds the blinding
    /// key, so it reveals every amount and asset. Sensitive for privacy.
    Descriptor {
        /// The key file.
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Sync and print the balance per asset.
    Balance {
        /// The key file.
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Sync and print the unsigned reserve attestation and its SHA-256.
    Attest {
        /// The key file.
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Fetch the reserve asset's registry entry and verify it against the pin.
    CheckAsset,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("usd-reserve: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Points every HTTP client this process builds at `proxy`, before any is built.
///
/// LWK's Esplora and registry clients are reqwest clients that read the
/// proxy from the environment when they are built; setting the variables
/// here, single-threaded and first, covers all of them. `NO_PROXY` is
/// cleared so no host bypasses the proxy.
fn route_through(proxy: &str) -> Result<()> {
    validate_proxy_url(proxy)?;
    for var in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"] {
        std::env::set_var(var, proxy);
    }
    for var in [
        "https_proxy",
        "http_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        std::env::remove_var(var);
    }
    Ok(())
}

fn synced(key_file: &Path, esplora_url: &str) -> Result<ReserveWallet> {
    let mut wallet = ReserveWallet::new(ReserveKey::load(key_file)?.descriptor()?)?;
    wallet.sync(esplora_url)?;
    Ok(wallet)
}

fn run(cli: Cli) -> Result<()> {
    if let Some(proxy) = &cli.proxy {
        route_through(proxy)?;
    }
    match cli.command {
        Command::Init { key_file } => {
            let key = ReserveKey::create(&key_file)?;
            let wallet = ReserveWallet::new(key.descriptor()?)?;
            eprintln!(
                "wrote a new reserve mnemonic to {} (mode 0400); back it up offline",
                key_file.display()
            );
            println!("{}", wallet.address(Some(0))?);
        }
        Command::Address {
            key_file,
            index,
            next,
        } => {
            let address = if next {
                synced(&key_file, &cli.esplora_url)?.address(None)?
            } else {
                ReserveWallet::new(ReserveKey::load(&key_file)?.descriptor()?)?
                    .address(Some(index.unwrap_or(0)))?
            };
            println!("{address}");
        }
        Command::Descriptor { key_file } => {
            eprintln!(
                "CT descriptor: cannot spend, but holds the blinding key and reveals every \
                 amount and asset; sensitive for privacy"
            );
            println!("{}", ReserveKey::load(&key_file)?.descriptor()?);
        }
        Command::Balance { key_file } => {
            let wallet = synced(&key_file, &cli.esplora_url)?;
            let snapshot = wallet.snapshot()?;
            println!("tip {} {}", snapshot.tip.height, snapshot.tip.hash);
            let balance = wallet.balance()?;
            if balance.is_empty() {
                println!("no funds");
            }
            for (asset, amount) in balance {
                let label = if asset == reserve_asset() {
                    " (reserve asset)"
                } else if asset == wallet.policy_asset() {
                    " (L-BTC)"
                } else {
                    ""
                };
                println!("{asset} {amount}{label}");
            }
        }
        Command::Attest { key_file } => {
            let wallet = synced(&key_file, &cli.esplora_url)?;
            let time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let attestation = attest(&wallet.snapshot()?, &reserve_asset(), time)?;
            println!("{}", attestation.canonical_json());
            println!("sha256 {}", attestation.digest());
        }
        Command::CheckAsset => {
            let entry = fetch_registry_entry()?;
            println!(
                "{} verified: ticker {}, name {:?}, issuer domain {}, precision {}; the contract \
                 and issuance prevout commit to the pinned id",
                reserve_asset(),
                entry.ticker(),
                entry.name(),
                entry.domain(),
                entry.precision()
            );
            println!(
                "sources: {REGISTRY_URL}/{} and {ISSUER_SOURCE_URL}",
                reserve_asset()
            );
        }
    }
    Ok(())
}
