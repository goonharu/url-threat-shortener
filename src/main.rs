use url_threat_shortener::scanner;

use clap::{Parser, Subcommand};
use dialoguer::{Input, Select};
use std::path::PathBuf;

use url_threat_shortener::scanner::{RiskLevel, load_blocklist, scan_url};
use url_threat_shortener::shortener::{
    UrlMapping, generate_unique_code, resolve, save_mapping, timestamp_now,
};

const BANNER: &str = concat!(
    "\n",
    "\x1b[38;5;51m    __    _       __   ______      __  __\x1b[0m\n",
    "\x1b[38;5;45m   / /   (_)___  / /__/ ____/_  __/ /_/ /____  _____\x1b[0m\n",
    "\x1b[38;5;39m  / /   / / __ \\/ //_/ /   / / / / __/ __/ _ \\/ ___/\x1b[0m\n",
    "\x1b[38;5;33m / /___/ / / / / ,< / /___/ /_/ / /_/ /_/  __/ /\x1b[0m\n",
    "\x1b[38;5;27m/_____/_/_/ /_/_/|_|\\____/\\__,_/\\__/\\__/\\___/_/\x1b[0m\n",
    "\n",
    "\x1b[38;5;245m        URL Threat Scanner & Shortener\x1b[0m\n",
);

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
    command: Option<Commands>,
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

/// Print the ASCII art banner
fn print_banner() {
    println!("{}", BANNER);
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

/// Run the scan command
fn cmd_scan(url: &str, blocklist: &std::collections::HashSet<String>) -> Result<(), String> {
    match scan_url(url, blocklist) {
        Ok(result) => {
            print_scan_result(&result);
            Ok(())
        }
        Err(e) => Err(format!("Error: {}", e)),
    }
}

/// Run the shorten command
fn cmd_shorten(
    url: &str,
    blocklist: &std::collections::HashSet<String>,
    store: &PathBuf,
) -> Result<(), String> {
    let result = match scan_url(url, blocklist) {
        Ok(r) => r,
        Err(e) => return Err(format!("Error: {}", e)),
    };

    print_scan_result(&result);

    if result.risk == RiskLevel::High {
        println!("\n!! WARNING: This URL was flagged as HIGH RISK.");
        println!("   The short link will still be created, but use caution.");
    }

    let code = match generate_unique_code(store, 6) {
        Ok(c) => c,
        Err(e) => return Err(format!("Error reading store: {}", e)),
    };
    let mapping = UrlMapping {
        code: code.clone(),
        original_url: url.to_string(),
        scan_result: result,
        created_at: timestamp_now(),
    };

    match save_mapping(store, &mapping) {
        Ok(()) => {
            println!("\nShort code: {}", code);
            println!("Stored successfully.");
            Ok(())
        }
        Err(e) => Err(format!("Error saving: {}", e)),
    }
}

/// Run the resolve command
fn cmd_resolve(code: &str, store: &PathBuf) -> Result<(), String> {
    match resolve(store, code) {
        Ok(mapping) => {
            println!("\nCode:    {}", mapping.code);
            println!("URL:     {}", mapping.original_url);
            let risk_label = match &mapping.scan_result.risk {
                RiskLevel::Low => "Low",
                RiskLevel::Medium => "Medium",
                RiskLevel::High => "High",
            };
            println!("Risk:    {} ({}/7)", risk_label, mapping.scan_result.score);
            if !mapping.scan_result.flags.is_empty() {
                println!("Flags:");
                for flag in &mapping.scan_result.flags {
                    println!("  ! {}", flag);
                }
            }
            println!("Created: {}", mapping.created_at);
            Ok(())
        }
        Err(e) => Err(format!("Error: {}", e)),
    }
}

/// Run the interactive menu loop
fn interactive_mode(blocklist: &std::collections::HashSet<String>, store: &PathBuf) {
    print_banner();
    println!("Welcome to LinkCutter! Run with --help for direct command usage.\n");

    loop {
        let choices = &[
            "Scan a URL",
            "Shorten a URL",
            "Resolve a short code",
            "Exit",
        ];

        let selection = Select::new()
            .with_prompt("What would you like to do?")
            .items(choices)
            .default(0)
            .interact();

        let selection = match selection {
            Ok(s) => s,
            Err(_) => {
                println!("\nGoodbye!");
                break;
            }
        };

        let result = match selection {
            0 => {
                let url: String = match Input::new()
                    .with_prompt("Enter URL to scan")
                    .interact_text()
                {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                cmd_scan(&url, blocklist)
            }
            1 => {
                let url: String = match Input::new()
                    .with_prompt("Enter URL to shorten")
                    .interact_text()
                {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                cmd_shorten(&url, blocklist, store)
            }
            2 => {
                let code: String =
                    match Input::new().with_prompt("Enter short code").interact_text() {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                cmd_resolve(&code, store)
            }
            3 => {
                println!("\nGoodbye!");
                break;
            }
            _ => unreachable!(),
        };

        // Print error but keep the loop running
        if let Err(e) = result {
            eprintln!("{}", e);
        }

        println!();
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
        Some(Commands::Scan { url }) => {
            print_banner();
            if let Err(e) = cmd_scan(&url, &blocklist) {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Shorten { url }) => {
            print_banner();
            if let Err(e) = cmd_shorten(&url, &blocklist, &cli.store) {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Resolve { code }) => {
            print_banner();
            if let Err(e) = cmd_resolve(&code, &cli.store) {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
        None => {
            interactive_mode(&blocklist, &cli.store);
        }
    }
}
