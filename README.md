# LinkCutter

A CLI tool that shortens URLs while scanning them for potential security threats.

## The Problem

URL shorteners like bit.ly are convenient but blind — they'll happily shorten a phishing link, a typosquatted domain, or a malware distribution URL without any warning. Users clicking shortened links have no idea what they're walking into.

LinkCutter flips this by scanning every URL through 7 threat-detection heuristics before shortening it. Each shortened link carries a security verdict, so you always know the risk level of the destination.

## Who Is This For

- Security students learning about URL-based attacks
- Analysts who want a quick command-line check on suspicious links
- Anyone who wants to understand *why* a URL looks sketchy, not just whether it does

## What It Does

- Scans URLs against 7 heuristic checks:
  - **IP literal detection** — flags raw IP addresses instead of domain names
  - **Suspicious TLD** — flags TLDs heavily abused in phishing (`.tk`, `.xyz`, `.click`, etc.)
  - **Typosquat detection** — Levenshtein distance against popular domains (`paypa1.com` → `paypal.com`)
  - **@ symbol trick** — catches `google.com@evil.com` style deception
  - **Punycode / homograph** — flags internationalized domain name abuse (`xn--` prefixes)
  - **Excessive length** — flags abnormally long URLs and deeply nested subdomains
  - **Known-bad blocklist** — matches against a local threat intelligence blocklist
- Assigns a risk score (0-7) and risk level (Low / Medium / High)
- Generates short codes for URLs with scan results attached
- Stores and retrieves shortened URL mappings with their security verdicts

## What It Does NOT Do

- Does not make live HTTP requests to the scanned URL
- Does not query external threat intelligence APIs
- Does not provide a web server or redirect service
- Is not a replacement for a full threat intelligence platform

## Installation

**Requirements:** Rust toolchain (1.70+)

```bash
git clone https://github.com/goonharu/url-threat-shortener.git
cd url-threat-shortener
cargo build --release
```

**Option A — run from the project directory:**

```bash
./target/release/linkcutter scan "https://example.com"
```

**Option B — install system-wide (recommended):**

```bash
cargo install --path .
```

After this, `linkcutter` is available globally from any directory:

```bash
linkcutter scan "https://example.com"
```

## Quick Start

**Interactive mode** — run with no arguments for a menu-driven interface:

```bash
linkcutter
```

**Direct commands:**

```bash
# Scan a URL for threats
linkcutter scan "https://paypa1-login.tk/verify"

# Shorten a URL (scans first, then generates a short code)
linkcutter shorten "https://example.com"

# Look up a previously shortened URL
linkcutter resolve <short-code>
```

> **Note:** If you haven't installed system-wide, replace `linkcutter` with `cargo run --release --` or `./target/release/linkcutter` in the commands above.

## Example

```
$ linkcutter scan "https://paypa1-login.tk/verify"

    __    _       __   ______      __  __
   / /   (_)___  / /__/ ____/_  __/ /_/ /____  _____
  / /   / / __ \/ //_/ /   / / / / __/ __/ _ \/ ___/
 / /___/ / / / / ,< / /___/ /_/ / /_/ /_/  __/ /
/_____/_/_/ /_/_/|_|\____/\__,_/\__/\__/\___/_/

        URL Threat Scanner & Shortener

[MEDIUM RISK] Score: 1/7

Flags:
  ! Suspicious TLD detected: .tk
```

## Options

```
Usage: linkcutter [OPTIONS] [COMMAND]

Commands:
  scan      Scan a URL for potential threats without shortening
  shorten   Scan a URL for threats and generate a short code
  resolve   Look up a previously shortened URL by its code

Options:
  --blocklist <PATH>   Path to known-bad domains file [default: data/known_bad.txt]
  --store <PATH>       Path to JSON store file [default: url_store.json]
  -h, --help           Print help
  -V, --version        Print version
```

When run without a command, LinkCutter enters interactive mode with an arrow-key menu.

## Blocklist

LinkCutter ships with a sample blocklist sourced from [Phishing Army](https://phishing.army). Users can replace `data/known_bad.txt` with any plain-text domain list (one domain per line). Lines starting with `#` are treated as comments.

## Known Limitations

- **Heuristic-based, not definitive.** The scanner uses pattern matching and string analysis, not live threat intelligence feeds. False positives and false negatives are possible.
- **Typosquat detection uses a small built-in list** of ~15 popular domains. A production tool would use a much larger reference set.
- **Levenshtein distance threshold (1-2)** may miss creative typosquats with more edits or catch unrelated short domains.
- **No live URL fetching.** The tool analyzes the URL string itself, not the content at the destination.
- **JSON file storage** reads and rewrites the entire file on each save. Suitable for small-scale use, not high-throughput production.
- **Timestamp is approximate** — uses a simple calculation without timezone handling.

## Safety and Ethical Use

LinkCutter is a **defensive, educational tool**. It is designed to help users identify potentially dangerous URLs, not to facilitate attacks. The tool:

- Makes no network requests to scanned URLs
- Uses only local data (blocklist file, JSON store)
- Contains no offensive capabilities
- Should only be used to analyze URLs you have legitimate reason to inspect

The included blocklist contains domains sourced from public threat intelligence feeds for demonstration purposes.

## Project Structure

```
url-threat-shortener/
├── src/
│   ├── main.rs          # CLI entry point and interactive menu
│   ├── lib.rs           # Library exports
│   ├── scanner.rs       # 7 threat-detection heuristics
│   └── shortener.rs     # URL shortening and JSON storage
├── tests/
│   └── integration_test.rs
├── data/
│   └── known_bad.txt    # Blocklist (Phishing Army)
├── examples/
│   ├── safe-urls.txt
│   ├── suspicious-urls.txt
│   └── mixed-urls.txt
├── README.md
├── MANUAL.md
├── LICENSE
└── Cargo.toml
```

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
