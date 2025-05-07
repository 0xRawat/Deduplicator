# 🧠 Domain Content Deduplicator

This Python script analyzes a list of domains or subdomains by fetching their page content, normalizing it (removing scripts/styles and HTML), and hashing it. The goal is to detect **duplicate**, **unique**, and **restricted (401/403)** domains based on the content returned.

Useful for:
- Identifying domain aliases or misconfigured subdomains.
- Detecting mirrored content across multiple hosts.
- Cleaning domain lists during recon or asset inventory.

---

## 🚀 Features

- Classifies domains as:
  - ✅ Unique – distinct content.
  - 📎 Duplicate – identical content hash.
  - 🔒 Restricted – returns HTTP 401 or 403.
- Uses HEAD requests first for speed, then falls back to GET.
- Robust normalization (removes tags, whitespace, scripts/styles).
- Optional verbose mode for debugging.
- Outputs to console or to `_unique.txt`, `_duplicate.txt`, and `_restricted.txt` files.
- Handles non-HTTP URLs automatically (adds `http://` if needed).

---

## 📦 Requirements

- Python 3.7+
- Install dependencies via:

      pip install requests

  ---
  
## 🧰 Usage

    python deduplicator.py -i input.txt [-o output_prefix] [-v]

| Argument          | Description                                                       |
| ----------------- | ----------------------------------------------------------------- |
| `-i`, `--input`   | Input file containing domains (one per line) – **required**       |
| `-o`, `--output`  | Base name for output files (`output_unique.txt`, etc.) – optional |
| `-v`, `--verbose` | Print detailed progress and HTTP errors – optional                |

# Output files
    results_unique.txt
    results_duplicate.txt
    results_restricted.txt


