//! EIP-712 Utilities
//!
//! This CLI provides utilities for working with EIP-712 typed data hashing and verification.
//!
//! ### Codegen
//!
//! Given a Solidity file, the CLI will look for all structs and generate a new Solidity file which
//! contains the EIP-712 type hashes and functions for encoding complex structs with nested types.
//!
//! ### Verification
//!
//! The CLI also provides a function for verifying EIP-712 signatures.
//!
//! ### Usage
//!
//! ```bash
//! cargo run --bin eip712-cli -- -i <input-solidity-file> -o <output-solidity-file>
//! ```
//!
//! ### Verification
//!
//! ```bash
//! cargo run --bin eip712-cli -- verify -s <signature> -d <domain-separator> -t <typed-data> -p <public-key>
//! ```
use clap::Parser;
use codegen::StructParser;
use proc_macro2::TokenStream;
use std::str::FromStr;
use syn_solidity::parse2;

mod codegen;
#[cfg(test)]
mod tests;
mod types;
mod utils;
mod verify;

/// The EIP-712 CLI arguments
#[derive(Debug, Parser)]
#[clap(about, version)]
enum Cli {
    /// Generate EIP-712 type hashes and functions for encoding complex structs with nested types
    Generate(GenerateCmd),
    /// Verify an EIP-712 signature
    Verify(VerifyCmd),
}

/// Subcommand for generating EIP-712 type hashes and functions for encoding complex structs with
/// nested types
#[derive(Debug, clap::Parser)]
struct GenerateCmd {
    /// Input solidity file
    #[arg(short, long)]
    input: String,
    /// The output file for the generated code
    #[arg(short, long, default_value = "output.sol")]
    output: String,
    /// Solc version
    #[arg(short, long, default_value = "0.8.20")]
    solc: String,
}

/// Subcommand for verifying EIP-712 signatures
#[derive(Debug, clap::Parser)]
struct VerifyCmd {
    /// Signature
    #[arg(short, long)]
    signature: String,
    /// Domain separator
    #[arg(short, long)]
    domain_separator: String,
    /// Typed data
    #[arg(short, long)]
    typed_data: String,
    /// Public key
    #[arg(short, long)]
    public_key: String,
}

fn main() {
    match Cli::parse() {
        Cli::Generate(cmd) => {
            let input = std::fs::read_to_string(&cmd.input).unwrap();
            let token_stream = TokenStream::from_str(&input).unwrap();
            let ast = parse2(token_stream).unwrap();
            let struct_parser = StructParser::init(&ast).unwrap();
            let output = struct_parser.generate_file(&cmd.solc);

            std::fs::write(&cmd.output, output).unwrap();
        }
        Cli::Verify(cmd) => {
            unimplemented!()
        }
    }
}
