#!/usr/bin/env python3
# Shebang: allows executing the file directly on Unix-like systems (./phishing_scanner.py)
# It tells the OS to use python3 to run this script.

"
Phishing Link Scanner (Heuristic)
Author: Raymond Favour Joshua 
Description:
  - Scores URLs based on common phishing indicators (no external APIs required).
  - Works in two modes:
      1) Single URL via --url
      2) Batch mode via --input_csv and optional --output_csv
  - Optional live checks (HEAD/GET) if --live flag is used (may be blocked by your network).
"
# Multi-line string used as a module docstring describing what the script does.

# ===== imports =====
import argparse               # CLI argument parsing
import math                   # math functions (we use log2 inside entropy)
import re                     # regular expressions
import sys                    # system utilities (e.g., stderr)
import json                   # to optionally print JSON output
import csv                    # to use the in-built CSV 
from urllib.parse import urlparse  # parse URLs into components
from collections import Counter     # count character frequencies for entropy

# The following imports are optional and we handle their absence gracefully.
try:
    import tldextract         # extracts subdomain/domain/suffix cleanly
except ImportError:
    # If tldextract is missing, print a friendly message and re-raise the error
    print("Missing dependency: tldextract. Install with: pip install tldextract", file=sys.stderr)
    raise

# Optional libs for batch/reporting (pandas) and HTTP live checks (requests)
try:
    import pandas as pd
except Exception:
    pd = None  # If pandas isn't installed, batch mode won't work; we set pd=None and handle later.

try:
    import requests
except Exception:
    requests = None  # If requests isn't installed, --live features will be disabled.

# ===== constant sets & patterns (heuristics) =====
SUSPICIOUS_TLDS = {
    "zip","mov","work","top","xyz","gq","cf","tk","ml","cam","rest","country","tokyo","click","fit","link"
}
# A small list of TLDs often abused for malicious campaigns — used as a heuristic flag.

URL_SHORTENERS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","adf.ly","cutt.ly","rb.gy","rebrand.ly","tiny.cc"
}
# Known URL shortener registered domains — shorteners hide final destination, raising suspicion.

SENSITIVE_KEYWORDS = {
    "login","signin","verify","update","secure","account","bank","wallet","password","reset","confirm","billing",
    "invoice","payment","office365","microsoft","paypal","apple","meta","facebook","instagram","whatsapp","telegram"
}
# Keywords often used in phishing paths or hosts to trick users.

BRAND_SPOOF_WORDS = {
    "rnicrosoft","paypa1","faceb00k","microsof7","app1e","go0gle","0ffice","0utlook","0fficial"
}
# Typical visual / keyboard-typo variants of brand names (simple example list).

SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"/\d{6,}"),            # path contains long numeric id sequences
    re.compile(r"/[a-z]{10,}\d+"),     # long alpha sequence followed by digits
    re.compile(r"(?:base64|data:)"),   # URL embedding data or base64 payloads
]
# Precompiled regex patterns for suspicious path structures.

IP_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
# Regex to detect raw IPv4 addresses used as the host.

# ===== helper functions =====

def shannon_entropy(s: str) -> float:
    "
    Compute Shannon entropy of a string (approx measure of randomness).
    Higher values suggest random-looking hostnames (e.g., DGA-generated).
    "
    if not s:
        return 0.0  # empty string entropy is 0
    counts = Counter(s)  # frequency of each character
    n = len(s)           # total length
    # entropy formula: -sum(p_i * log2(p_i)) for each char probability p_i
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

def features_from_url(url: str) -> dict:
    "
    Extract a set of features/flags from a URL used for scoring.
    Returns a dictionary of features (both numeric and flags).
    "
    fe = {}  # feature dict we will populate
    # Ensure urlparse works even if scheme missing — prefix with http:// if needed
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname or ""  # hostname portion (might be None)
    # construct path + query together for pattern checks
    path_q = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    ext = tldextract.extract(url)  # separate subdomain / domain / suffix robustly
    # registered_domain Example: 'example.com' or 'bit.ly' (domain + suffix)
    registered_domain = ".".join([p for p in [ext.domain, ext.suffix] if p])

    # Basic parsed flags and lengths
    fe["scheme"] = parsed.scheme or "http"  # e.g., 'http' or 'https'
    fe["uses_https"] = 1 if parsed.scheme.lower() == "https" else 0  # 1 if https
    fe["has_at_symbol"] = 1 if "@" in url else 0  # @ in url often used to obfuscate
    fe["url_length"] = len(url)  # full url length (chars)
    fe["host_length"] = len(host)  # host length
    fe["path_length"] = len(parsed.path or "")  # path length
    fe["num_dots"] = url.count(".")  # count of dots in the whole URL
    fe["num_hyphens"] = url.count("-")  # hyphen count
    fe["num_digits"] = sum(ch.isdigit() for ch in url)  # how many digits in URL
    fe["has_ip_host"] = 1 if IP_HOST_RE.match(host or "") else 0  # 1 if host is raw IP
    # detect url shorteners by matching registered domain against known shorteners
    fe["is_url_shortener"] = 1 if registered_domain in URL_SHORTENERS else 0
    # check if the last suffix portion is in our suspicious tld list
    fe["tld_in_suspicious_list"] = 1 if ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS else 0
    fe["contains_punycode"] = 1 if "xn--" in host else 0  # punycode indicator for IDN homograph attacks
    # subdomain_count: total host parts minus 2 (domain + suffix), floor at 0
    fe["subdomain_count"] = max(0, len([p for p in host.split(".") if p]) - 2)

    # Combine host + path for keyword scanning (lowercased)
    lower_combo = (host + path_q).lower()
    fe["has_sensitive_keyword"] = 1 if any(k in lower_combo for k in SENSITIVE_KEYWORDS) else 0
    fe["has_brand_spoof_word"] = 1 if any(k in lower_combo for k in BRAND_SPOOF_WORDS) else 0
    # path suspicious if it matches any of the compiled regex patterns
    fe["path_has_suspicious_pattern"] = 1 if any(p.search(path_q.lower()) for p in SUSPICIOUS_PATH_PATTERNS) else 0
    # host_entropy: entropy of the hostname (rounded to 3 decimals)
    fe["host_entropy"] = round(shannon_entropy(host), 3)

    # add some raw fields for traceability / output
    fe["registered_domain"] = registered_domain
    fe["host"] = host
    fe["path_q"] = path_q
    fe["raw_url"] = url
    return fe

def score_url(fe: dict) -> dict:
    "
    Rule-based scoring. Returns a dictionary containing:
      - score: 0..100 numeric
      - label: Likely OK / Suspicious / High-Risk
      - reasons: list of human-readable reasons for points added
    "
    score = 0
    reasons = []

    # helper to add points and a reason (keeps code tidy)
    def add(points, reason):
        nonlocal score
        score += points
        reasons.append(f"+{points}: {reason}")

    # Apply each rule and award points if condition met
    if fe["uses_https"] == 0:
        add(10, "URL does not use HTTPS")
    if fe["has_at_symbol"]:
        add(10, "Contains '@' symbol (possible redirection)")
    if fe["has_ip_host"]:
        add(15, "Uses raw IP as host")
    if fe["tld_in_suspicious_list"]:
        add(10, "Suspicious/abused TLD")
    if fe["is_url_shortener"]:
        add(10, "Known URL shortener (conceals destination)")
    if fe["contains_punycode"]:
        add(10, "Punycode in hostname")
    if fe["subdomain_count"] >= 3:
        add(10, "Excessive subdomains")
    if fe["num_hyphens"] >= 4:
        add(5, "Many hyphens in URL")
    if fe["num_digits"] >= 10:
        add(5, "Many digits in URL")
    if fe["url_length"] >= 90:
        add(5, "Very long URL")
    if fe["has_sensitive_keyword"]:
        add(10, "Contains sensitive keywords")
    if fe["has_brand_spoof_word"]:
        add(15, "Contains brand-spoofing patterns")
    if fe["path_has_suspicious_pattern"]:
        add(5, "Suspicious path pattern")
    if fe["host_entropy"] >= 3.6:
        add(10, "High host entropy (random-looking)")

    # Cap the score at 100 so it remains bounded
    score = min(100, score)

    # Map score to a human label
    if score >= 40:
        label = "High-Risk"
    elif score >= 20:
        label = "Suspicious"
    else:
        label = "Likely OK"

    # Return result
    return {
        "score": score,
        "label": label,
        "reasons": reasons,
    }

def live_checks(url: str, timeout=6):
    "
    Optional lightweight live checks using HTTP requests.
    - Follows redirects to reveal final landing URL
    - Returns status code, final_url, redirect_count, and optional page title
    If requests is not installed or network blocked, returns a dict with live_error.
    "
    if requests is None:
        return {"live_error": "requests not installed"}  # graceful failure mode for missing requests

    info = {}
    try:
        # Try a HEAD request first (faster, no body)
        resp = requests.head(url, allow_redirects=True, timeout=timeout)
        info["status_code"] = resp.status_code
        info["final_url"] = resp.url
        info["redirect_count"] = len(resp.history)
        # Some servers disallow HEAD or return minimal headers; attempt GET if needed
        if resp.status_code >= 400 or "text/html" in resp.headers.get("Content-Type",""):
            r2 = requests.get(url, allow_redirects=True, timeout=timeout)
            info["final_url"] = r2.url
            info["status_code"] = r2.status_code
            # Try to extract page title for context (don't download large content)
            m = re.search(r"<title>(.*?)</title>", r2.text, flags=re.IGNORECASE|re.DOTALL)
            if m:
                info["page_title"] = m.group(1).strip()[:150]
    except Exception as e:
        # Network errors or timeouts are captured here
        info["live_error"] = str(e)
    return info

def scan_url(url: str, do_live=False) -> dict:
    "
    High-level function scanning a single URL.
    - Extract features
    - Score URL
    - Optionally run live checks and merge their outputs
    Returns a flattened record (dictionary)
    "
    fe = features_from_url(url)             # extract features
    scored = score_url(fe)                  # apply rules and score
    record = {**fe, **scored}               # merge feature dict & score dict
    if do_live:
        # prefix live check keys with 'live_' to avoid clashing field names
        record.update({f"live_{k}": v for k, v in live_checks(url).items()})
    return record

def main():
    "
    CLI entrypoint. Supports:
     - --url <single url>
     - --input_csv <csvpath> --output_csv <csvpath>
     - --json (print single result as JSON)
     - --live (perform HTTP live checks)
    "
    ap = argparse.ArgumentParser(description="Phishing Link Scanner (Heuristic)")
    ap.add_argument("--url", help="Single URL to scan")
    ap.add_argument("--input_csv", help="CSV with a column named 'url' for batch scanning")
    ap.add_argument("--output_csv", help="Where to write the batch report CSV")
    ap.add_argument("--json", action="store_true", help="Print result as JSON to stdout (single URL mode)")
    ap.add_argument("--live", action="store_true", help="Perform optional live checks (network)")
    args = ap.parse_args()

    # Single URL mode branch
    if args.url:
        rec = scan_url(args.url, do_live=args.live)  # scan single URL, live if requested
        if args.json:
            # Print the full record as pretty JSON to stdout
            print(json.dumps(rec, indent=2))
        else:
            # Print short human-friendly summary + reasons
            print(f"[{rec['label']}] score={rec['score']} url={rec['raw_url']}")
            for r in rec["reasons"]:
                print("  -", r)
        return 0

    # Batch CSV mode branch
    if args.input_csv:
        if pd is None:
            # If pandas not installed, inform the user and exit with code 2
            print("pandas not available. Install with: pip install pandas", file=sys.stderr)
            return 2
        df = pd.read_csv(args.input_csv)  # load CSV into DataFrame
        # Require the CSV to have a column named 'url' to know which column to scan
        if "url" not in df.columns:
            print("Input CSV must have a 'url' column", file=sys.stderr)
            return 2
        rows = []
        # Iterate each url string, scan and append the result dict to rows
        for u in df["url"].astype(str):
            rows.append(scan_url(u, do_live=args.live))
        out = pd.DataFrame(rows)  # convert list of dicts to DataFrame for saving
        if args.output_csv:
            out.to_csv(args.output_csv, index=False)  # write report CSV
            print(f"Wrote report: {args.output_csv}")
        else:
            # If no output path provided, print a preview of results
            print(out.head().to_string(index=False))
        return 0

    # If no arguments provided, print help
    ap.print_help()
    return 0

if __name__ == "__main__":
    # Execute CLI main when run as a script
    sys.exit(main())
