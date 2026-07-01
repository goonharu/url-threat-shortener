# LinkCutter — User Manual

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Usage Overview](#usage-overview)
4. [Interactive Mode](#interactive-mode)
5. [Commands](#commands)
   - [scan](#scan)
   - [shorten](#shorten)
   - [resolve](#resolve)
6. [Global Options](#global-options)
7. [Input Format](#input-format)
8. [Output Fields](#output-fields)
9. [Threat Heuristics Explained](#threat-heuristics-explained)
10. [Blocklist Configuration](#blocklist-configuration)
11. [Storage Format](#storage-format)
12. [Worked Example](#worked-example)
13. [Troubleshooting](#troubleshooting)

---

## Requirements

- **Rust toolchain** version 1.70 or later
- **Operating system:** macOS, Linux, or Windows (with a terminal that supports ANSI colors)
- **Disk space:** ~50 MB for compiled binary and dependencies
- No internet connection required at runtime — all scanning is performed locally

Verify your Rust installation:

```bash
rustc --version
cargo --version
```

If Rust is not installed, visit [https://rustup.rs](https://rustup.rs).

---

## Installation

### From source

```bash
git clone https://github.com/goonharu/url-threat-shortener.git
cd url-threat-shortener
cargo build --release
```

### System-wide install

```bash
cargo install --path .
```

After this, `linkcutter` is available from any directory. If you skip this step, run the binary directly:

```bash
./target/release/linkcutter <command>
```

Or during development:

```bash
cargo run -- <command>
```

---

## Usage Overview

LinkCutter operates in two modes:

**Direct command mode** — pass a subcommand and argument:

```bash
linkcutter scan <url>
linkcutter shorten <url>
linkcutter resolve <code>
```

**Interactive mode** — run without arguments for a menu-driven interface:

```bash
linkcutter
```

---

## Interactive Mode

When launched with no subcommand, LinkCutter presents an arrow-key navigable menu:

```
What would you like to do?
> Scan a URL
  Shorten a URL
  Resolve a short code
  Exit
```

Use the up/down arrow keys to select an action, then press Enter. LinkCutter will prompt you for the required input (URL or short code), perform the action, display the result, and return to the menu.

Errors in interactive mode (such as an invalid URL) are printed but do not exit the program — you are returned to the menu to try again.

Press Ctrl+C at any time to exit.

---

## Commands

### scan

Scan a URL for potential threats without shortening or storing it.

```bash
linkcutter scan <url>
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `url` | Yes | The URL to scan. If no scheme is provided (e.g. `google.com`), `https://` is automatically prepended. |

**Example:**

```bash
linkcutter scan "https://paypa1.com/login"
```

**Output:**

```
[MEDIUM RISK] Score: 2/7

Flags:
  ! Suspicious TLD detected: .com
  ! Possible typosquat: "paypa1.com" is 1 edit(s) from "paypal.com"
```

**Exit codes:**

- `0` — scan completed successfully (regardless of risk level)
- `1` — invalid input or internal error

---

### shorten

Scan a URL for threats, then generate a short code and store the mapping.

```bash
linkcutter shorten <url>
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `url` | Yes | The URL to shorten. Automatically normalized if scheme is missing. |

**Behavior:**

1. Runs all 7 heuristic checks (same as `scan`)
2. Displays the scan result
3. If risk is HIGH, prints a warning but still creates the short code
4. Generates a random 6-character alphanumeric code
5. Saves the mapping (code, URL, scan result, timestamp) to the JSON store

**Example:**

```bash
linkcutter shorten "https://example.com"
```

**Output:**

```
[LOW RISK] Score: 0/7
No threats detected.

Short code: a3Bf9x
Stored successfully.
```

---

### resolve

Look up a previously shortened URL by its short code.

```bash
linkcutter resolve <code>
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `code` | Yes | The 6-character short code returned by the `shorten` command. |

**Example:**

```bash
linkcutter resolve a3Bf9x
```

**Output:**

```
Code:    a3Bf9x
URL:     https://example.com
Risk:    Low (0/7)
Created: 2026-07-01T12:34:56Z
```

If flags were present at the time of shortening, they are also displayed.

**Error:** If the code does not exist in the store:

```
Error: Short code "xyz123" not found
```

---

## Global Options

These options can be used with any subcommand or in interactive mode:

| Option | Default | Description |
|--------|---------|-------------|
| `--blocklist <PATH>` | `data/known_bad.txt` | Path to a plain-text file of known-bad domains (one per line). |
| `--store <PATH>` | `url_store.json` | Path to the JSON file where shortened URL mappings are stored. |
| `-h, --help` | — | Print help information. |
| `-V, --version` | — | Print version number. |

**Example with custom paths:**

```bash
linkcutter --blocklist /path/to/my_blocklist.txt --store /path/to/my_store.json scan "https://example.com"
```

---

## Input Format

### URLs

- Full URLs with scheme: `https://example.com/path`
- URLs without scheme: `example.com` (automatically prepended with `https://`)
- URLs with ports: `http://example.com:8080/page`
- IP-based URLs: `http://192.168.1.1/admin`

**Invalid inputs** that will produce an error:

- Empty string
- Strings with spaces and no dots (e.g. `not a url`)
- Completely malformed strings

### Blocklist file (`known_bad.txt`)

- One domain per line
- Lines starting with `#` are comments (ignored)
- Blank lines are ignored
- Domains are case-insensitive (`Evil.Com` matches `evil.com`)
- Do not include the scheme — use `evil.com`, not `https://evil.com`

Example:

```
# Phishing domains
evil-phishing-site.com
malware-download.net

# Scam sites
fake-bank-login.com
```

---

## Output Fields

### Scan Result

| Field | Description |
|-------|-------------|
| Risk Level | `LOW RISK` (0 flags), `MEDIUM RISK` (1-2 flags), or `HIGH RISK` (3+ flags) |
| Score | Number of heuristics that flagged, out of 7 total |
| Flags | List of human-readable reasons explaining each triggered heuristic |

### Resolve Result

| Field | Description |
|-------|-------------|
| Code | The 6-character short code |
| URL | The original full URL |
| Risk | Risk level and score at the time of shortening |
| Flags | Any flags that were triggered (if applicable) |
| Created | Timestamp when the URL was shortened |

---

## Threat Heuristics Explained

### 1. IP Literal Detection

**What it catches:** URLs using raw IP addresses instead of domain names (e.g. `http://192.168.1.1/login`).

**Why it matters:** Legitimate websites use domain names. Raw IP addresses are commonly used by attackers because they are cheap, disposable, and harder to blocklist by name.

### 2. Suspicious TLD

**What it catches:** URLs using top-level domains with historically high abuse rates: `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.click`, `.buzz`, `.rest`, `.work`, `.fit`, `.loan`.

**Why it matters:** These TLDs are free or very cheap to register, making them popular for throwaway phishing campaigns.

### 3. Typosquat Detection

**What it catches:** Domains that are 1-2 character edits (Levenshtein distance) away from popular domains like `google.com`, `paypal.com`, `amazon.com`, etc.

**Why it matters:** Attackers register lookalike domains (`paypa1.com`, `gooogle.com`) to trick users into entering credentials on fake sites.

**Reference list:** google.com, facebook.com, amazon.com, apple.com, microsoft.com, paypal.com, netflix.com, instagram.com, twitter.com, linkedin.com, github.com, yahoo.com, chase.com, wellsfargo.com, bankofamerica.com.

### 4. @ Symbol Trick

**What it catches:** URLs containing `@` in the authority section (e.g. `https://google.com@evil.com`).

**Why it matters:** In URL syntax, everything before `@` is treated as userinfo (username). The actual destination is after `@`. This tricks users into thinking they are visiting a trusted site.

### 5. Punycode / Homograph Attack

**What it catches:** Domain labels starting with `xn--`, which indicates Punycode-encoded internationalized domain names.

**Why it matters:** Attackers use Unicode characters that look identical to ASCII letters (e.g. Cyrillic `а` looks like Latin `a`) to create domains visually indistinguishable from legitimate ones.

### 6. Excessive Length

**What it catches:** URLs longer than 100 characters, or domains with more than 3 subdomain levels.

**Why it matters:** Phishing URLs are often padded with keywords or random strings to push the real domain out of the browser's visible address bar.

### 7. Known-Bad Blocklist

**What it catches:** Domains that exactly match an entry in the local `known_bad.txt` blocklist.

**Why it matters:** This is signature-based detection — it catches known threats from threat intelligence feeds. Complements the heuristic checks which catch unknown/new threats.

---

## Blocklist Configuration

The default blocklist is located at `data/known_bad.txt` and is sourced from [Phishing Army](https://phishing.army).

### Using a custom blocklist

```bash
linkcutter --blocklist /path/to/custom_list.txt scan "https://example.com"
```

### Updating the blocklist

Download the latest Phishing Army feed and replace the file:

```bash
curl -o data/known_bad.txt https://phishing.army/download/phishing_army_blocklist.txt
```

### Disabling the blocklist

If the blocklist file is missing or empty, LinkCutter will print a warning and continue scanning with the remaining 6 heuristics. The known-bad check will simply be skipped.

---

## Storage Format

Shortened URL mappings are stored in a JSON file (default: `url_store.json`). Each entry contains:

```json
{
  "code": "a3Bf9x",
  "original_url": "https://example.com",
  "scan_result": {
    "risk": "Low",
    "score": 0,
    "flags": []
  },
  "created_at": "2026-07-01T12:34:56Z"
}
```

The file is a JSON array of these objects. It is human-readable and can be inspected or edited manually.

---

## Worked Example

A complete walkthrough from installation to scanning, shortening, and resolving.

**Step 1: Clone and build**

```bash
git clone https://github.com/goonharu/url-threat-shortener.git
cd url-threat-shortener
cargo build --release
cargo install --path .
```

**Step 2: Scan a suspicious URL**

```bash
linkcutter scan "paypa1-login.tk/verify"
```

Output:

```
[MEDIUM RISK] Score: 1/7

Flags:
  ! Suspicious TLD detected: .tk
```

The URL was auto-normalized to `https://paypa1-login.tk/verify` and flagged for its suspicious TLD.

**Step 3: Shorten a clean URL**

```bash
linkcutter shorten "https://github.com/goonharu/url-threat-shortener"
```

Output:

```
[LOW RISK] Score: 0/7
No threats detected.

Short code: Kx9mP2
Stored successfully.
```

**Step 4: Resolve the short code**

```bash
linkcutter resolve Kx9mP2
```

Output:

```
Code:    Kx9mP2
URL:     https://github.com/goonharu/url-threat-shortener
Risk:    Low (0/7)
Created: 2026-07-01T15:30:22Z
```

**Step 5: Try interactive mode**

```bash
linkcutter
```

Use the arrow keys to navigate the menu, scan a few URLs, and select Exit when done.

---

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `Warning: Blocklist is empty or not found` | The blocklist file is missing or the path is wrong | Ensure `data/known_bad.txt` exists, or pass `--blocklist <path>` |
| `Error: Invalid URL` | The input could not be parsed as a URL | Check for typos. If no scheme was provided, ensure the input contains a dot (e.g. `example.com`, not just `example`) |
| `Error: Short code "xyz" not found` | The code doesn't exist in the store | Verify the code. Check that you're using the same `--store` path that was used during shortening |
| `Error saving: Storage I/O error` | Cannot write to the store file | Check file permissions. Ensure the directory exists |
| Banner colors not showing | Terminal does not support ANSI 256-color | Use a modern terminal (iTerm2, Windows Terminal, most Linux terminals). Basic functionality is not affected |
| `cargo build` fails | Missing Rust toolchain or outdated version | Run `rustup update` to get the latest toolchain |
| Typosquat not detected for a known-bad domain | Domain is more than 2 edits from any reference domain, or is an exact match | This is expected — the threshold is intentionally conservative to reduce false positives |
