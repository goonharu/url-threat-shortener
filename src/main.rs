mod scanner;
mod shortener;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

use scanner::{RiskLevel, load_blocklist, scan_url};
use shortener::{UrlMapping, generate_code, resolve, save_mapping, timestamp_now};

#[derive(Parser)]
#[command(
    name = "linkcutter",
    about = "A CLI tool that shortens URLs with scanning them for potential threats.",
    version
)]
struct Cli {
    /// Path to the known-bad domains blocklist file
    #[arg(long, default_value = "data/known_bad.txt")]
    blocklist: PathBuf,

    /// Path to JSON store file for shortened URLs
    #[arg(long, default_value = "url_store.json")]
    store: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a URL for potential threats without shortening
    Scan {
        /// The URL to scan
        url: String,
    },
    /// Scan a URL for threats and generate a short code
    Shorten {
        /// The URL to shorten
        url: String,
    },
    /// Look up a previously shortened URL by its code
    Resolve {
        /// The short code to look up
        code: String,
    },
}

/// Format and print a scan result to the terminal
fn print_scan_result(result: &scanner::ScanResult) {
    let risk_label = match &result.risk {
        RiskLevel::Low => "LOW RISK",
        RiskLevel::Medium => "MEDIUM RISK",
        RiskLevel::High => "HIGH RISK",
    };

    println!("\n[{}] Score: {}/7", risk_label, result.score);

    if result.flags.is_empty() {
        println!("No threats detected.");
    } else {
        println!("\nFlags:");
        for flag in &result.flags {
            println!(" ! {}", flag);
        }
    }
}

fn main() {
    let cli = Cli::parse();

    // Load blocklist once at startup
    let blocklist = load_blocklist(&cli.blocklist);
    if blocklist.is_empty() {
        eprintln!(
            "Warning: Blocklist is empty or not found at {:?}, Known-bad check will be skipped.",
            cli.blocklist
        );
    }

    match cli.command {
        Commands::Scan { url } => match scan_url(&url, &blocklist) {
            Ok(result) => {
                print_scan_result(&result);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        },

        Commands::Shorten { url } => {
            // Step 1: Scan first
            let result = match scan_url(&url, &blocklist) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            };

            print_scan_result(&result);

            // Step 2: Warn if risky, but still shorten
            if result.risk == RiskLevel::High {
                println!("\n!! WARNING: This URL was flagged as HIGH RISK.");
                println!("  The short link will still be created, but use caution.");
            }

            // Step 3: Generate code and save
            let code = generate_code(6);
            let mapping = UrlMapping {
                code: code.clone(),
                original_url: url.clone(),
                scan_result: result,
                created_at: timestamp_now(),
            };

            match save_mapping(&cli.store, &mapping) {
                Ok(()) => {
                    println!("\nShort code: {}", code);
                    println!("Stored successfully.");
                }
                Err(e) => {
                    println!("Error saving: {}", e);
                    process::exit(1);
                }
            }
        }

        Commands::Resolve { code } => match resolve(&cli.store, &code) {
            Ok(mapping) => {
                println!("\nCode:   {}", mapping.code);
                println!("URL:     {}", mapping.original_url);
                let risk_label = match &mapping.scan_result.risk {
                    RiskLevel::Low => "Low",
                    RiskLevel::Medium => "Medium",
                    RiskLevel::High => "High",
                };
                println!(
                    "Risk:      {} ({}/7)",
                    risk_label, mapping.scan_result.score
                );
                if !mapping.scan_result.flags.is_empty() {
                    println!("Flags:");
                    for flag in &mapping.scan_result.flags {
                        println!("  ! {}", flag);
                    }
                }
                println!("Created: {}", mapping.created_at);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        },
    }
}
