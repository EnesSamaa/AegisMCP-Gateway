//! # aegis-cli
//!
//! Command-line audit log verification tool for `AegisMCP-Gateway`.
//!
//! ## Commands
//!
//! ```text
//! aegis-cli verify --proof <proof.json> --root <root_hash>
//! aegis-cli inspect --ledger <ledger.json>
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(missing_docs)]

use aegis_proof::AuditMerkleProof;
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// CLI structure
// ---------------------------------------------------------------------------

/// AegisMCP-Gateway — Cryptographic Audit Verification CLI.
#[derive(Debug, Parser)]
#[command(
    name = "aegis-cli",
    version,
    about = "Offline Merkle inclusion proof verifier and audit ledger inspector for AegisMCP-Gateway",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Verify a Merkle inclusion proof JSON file against a known root hash.
    ///
    /// Exits with code 0 on success, 1 on failure.
    Verify {
        /// Path to the JSON file containing an `AuditMerkleProof`.
        #[arg(long, short = 'p', value_name = "FILE")]
        proof: PathBuf,

        /// Expected Merkle root hash (64-char lowercase hex SHA-256).
        #[arg(long, short = 'r', value_name = "HEX")]
        root: String,
    },

    /// Inspect a JSON-serialised ledger snapshot and display its summary.
    Inspect {
        /// Path to a JSON file containing an array of `AuditMerkleProof` entries
        /// (as exported from the `/v1/proofs/*` endpoints).
        #[arg(long, short = 'l', value_name = "FILE")]
        ledger: PathBuf,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify { proof, root } => cmd_verify(&proof, &root),
        Commands::Inspect { ledger } => cmd_inspect(&ledger),
    }
}

// ---------------------------------------------------------------------------
// `verify` sub-command
// ---------------------------------------------------------------------------

/// Reads an `AuditMerkleProof` from `path`, verifies it against `root_hex`,
/// and prints a human-readable result.
fn cmd_verify(path: &PathBuf, root_hex: &str) -> Result<()> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read proof file: {}", path.display()))?;

    let proof: AuditMerkleProof =
        serde_json::from_str(&raw).context("Failed to deserialise AuditMerkleProof JSON")?;

    validate_hex_root(root_hex)?;

    println!("╔══════════════════════════════════════════════════════╗");
    println!("║       AegisMCP-Gateway — Merkle Proof Verifier       ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();
    println!("  Proof file   : {}", path.display());
    println!("  Leaf index   : {}", proof.leaf_index);
    println!("  Leaf hash    : {}", truncate_hex(&proof.leaf_hash, 16));
    println!("  Sibling path : {} nodes", proof.sibling_hashes.len());
    println!("  Proof root   : {}", truncate_hex(&proof.root_hash, 16));
    println!("  Expected root: {}", truncate_hex(root_hex, 16));
    println!();

    if proof.verify(root_hex) {
        println!("  ✅  VERIFICATION PASSED — audit entry is authentic");
        println!();
        Ok(())
    } else {
        println!("  ❌  VERIFICATION FAILED — proof does not match root");
        println!();
        bail!("Merkle proof verification failed")
    }
}

// ---------------------------------------------------------------------------
// `inspect` sub-command
// ---------------------------------------------------------------------------

/// Reads a JSON array of `AuditMerkleProof` values from `path` and prints
/// a structured summary including the sequence of leaf hashes and stored root.
fn cmd_inspect(path: &PathBuf) -> Result<()> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read ledger file: {}", path.display()))?;

    // Accept either a single proof or an array of proofs.
    let proofs: Vec<AuditMerkleProof> = if raw.trim_start().starts_with('[') {
        serde_json::from_str(&raw).context("Failed to parse proof array")?
    } else {
        let single: AuditMerkleProof =
            serde_json::from_str(&raw).context("Failed to parse single proof")?;
        vec![single]
    };

    println!("╔══════════════════════════════════════════════════════╗");
    println!("║       AegisMCP-Gateway — Audit Ledger Inspector      ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();
    println!("  Ledger file  : {}", path.display());
    println!("  Entry count  : {}", proofs.len());
    println!();

    if proofs.is_empty() {
        println!("  (ledger is empty)");
        return Ok(());
    }

    // Display table header
    println!(
        "  {:<6}  {:<20}  {:<8}  Root Hash (prefix)",
        "Index", "Leaf Hash (prefix)", "Siblings"
    );
    println!("  {}", "-".repeat(70));

    for proof in &proofs {
        println!(
            "  {:<6}  {:<20}  {:<8}  {}",
            proof.leaf_index,
            truncate_hex(&proof.leaf_hash, 18),
            proof.sibling_hashes.len(),
            truncate_hex(&proof.root_hash, 18),
        );
    }

    println!();

    // Latest root — last entry's root_hash
    if let Some(last) = proofs.last() {
        println!("  Latest Merkle Root : {}", last.root_hash);
    }

    println!();
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validates that `hex` is a 64-character lowercase hexadecimal string.
fn validate_hex_root(hex: &str) -> Result<()> {
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("Invalid root hash '{hex}': expected a 64-character lowercase hex string");
    }
    Ok(())
}

/// Returns `{prefix_len} chars...` of a hex string for compact display.
fn truncate_hex(hex: &str, prefix_len: usize) -> String {
    if hex.len() <= prefix_len {
        hex.to_string()
    } else {
        format!("{}…", &hex[..prefix_len])
    }
}
