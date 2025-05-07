#!/usr/bin/env python3
# Domain Content Classifier Tool
#
# This script reads a list of domains/subdomains from an input file, fetches each domain's page content
# (first via a HEAD request, falling back to GET if needed), normalizes the content, and hashes it.
# Domains are classified into unique (distinct content), duplicate (same content as another), and restricted (HTTP 401/403).
# Results can be written to output files or printed, with optional verbose progress messages.
#
# Uses: requests (for HTTP), hashlib (for hashing), argparse (for CLI), re (for regex), sys/os (for file handling).
# Target Python 3.7+ compatibility.
import requests
import hashlib
import argparse
import sys
import os
import re

def normalize_content(html):
    """
    Normalize HTML content by removing scripts/styles and extra whitespace, to create a consistent text for hashing.
    """
    # Remove script elements with their content (case-insensitive, dot matches newlines)
    html = re.sub(r'(?is)<script.*?>.*?</script>', '', html)
    # Remove style elements with their content
    html = re.sub(r'(?is)<style.*?>.*?</style>', '', html)

    # Remove all remaining HTML tags, leaving only the text
    text = re.sub(r'<[^>]+>', '', html)

    # Collapse multiple whitespace characters into a single space
    text = re.sub(r'\s+', ' ', text)

    # Strip leading/trailing whitespace
    normalized = text.strip()
    return normalized

def fetch_content(domain, verbose=False, timeout=10):
    """
    Fetches the content of the domain by first attempting a HEAD request.
    If HEAD is not allowed or fails (except 401/403), it falls back to GET.
    Returns a tuple: (status_code, content or None, error_flag, restricted_flag).
    - restricted_flag=True means HTTP 401/403 (no content returned).
    - error_flag=True means some error occurred (no content).
    """
    # Ensure the URL has a scheme (default to http if missing)
    if not domain.startswith(('http://', 'https://')):
        url = 'http://' + domain
    else:
        url = domain

    # Set a user-agent to mimic a real browser (some servers block default UA)
    headers = {'User-Agent': 'Mozilla/5.0 (compatible)'}

    try:
        # Attempt HEAD request first to quickly check status and redirects
        head_response = requests.head(url, headers=headers, allow_redirects=True, timeout=timeout)
        status = head_response.status_code

        # If HEAD returns 401 or 403, mark domain as restricted (no content)
        if status == 401 or status == 403:
            return status, None, False, True

        # If HEAD indicates "Method Not Allowed" or server error, do GET instead
        if status == 405 or status >= 500 or head_response.headers.get('Content-Length') == '0':
            get_response = requests.get(url, headers=headers, allow_redirects=True, timeout=timeout)
            status = get_response.status_code
            if status == 401 or status == 403:
                return status, None, False, True
            elif status >= 400:
                # Other HTTP error on GET (like 404) is treated as an error (skip this domain)
                return status, None, True, False
            return status, get_response.text, False, False
        else:
            # HEAD succeeded (not restricted or error), now fetch content with GET
            get_response = requests.get(url, headers=headers, allow_redirects=True, timeout=timeout)
            status = get_response.status_code
            if status == 401 or status == 403:
                return status, None, False, True
            elif status >= 400:
                return status, None, True, False
            return status, get_response.text, False, False

    except requests.exceptions.SSLError as e:
        # SSL error (e.g., certificate issue)
        if verbose:
            print(f"SSL error for {domain}: {e}")
        return None, None, True, False
    except requests.exceptions.Timeout:
        # Request timed out
        if verbose:
            print(f"Timeout when connecting to {domain}")
        return None, None, True, False
    except requests.exceptions.RequestException as e:
        # Other request-related errors (connection error, DNS failure, etc.)
        if verbose:
            print(f"Request failed for {domain}: {e}")
        return None, None, True, False

def main():
    parser = argparse.ArgumentParser(description="Classify domains by page content (unique, duplicate, restricted).")
    parser.add_argument('--input', '-i', required=True, help="Path to input file containing domains (one per line).")
    parser.add_argument('--output', '-o', help="Base path/prefix for output files (unique, duplicate, restricted).")
    parser.add_argument('--verbose', '-v', action='store_true', help="Enable verbose output.")
    args = parser.parse_args()

    # Read domains from the input file (ignore empty lines or commented lines starting with '#')
    try:
        with open(args.input, 'r') as f:
            domains = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)

    if not domains:
        print("No domains found in input.")
        sys.exit(0)

    # Map to store content hash -> list of domains with that content
    hash_map = {}
    # List to collect restricted domains (HTTP 401/403)
    restricted_domains = []

    # Process each domain one by one
    for domain in domains:
        if args.verbose:
            print(f"Checking domain: {domain}")

        status, content, error, restricted = fetch_content(domain, verbose=args.verbose)

        if restricted:
            # Domain is restricted (401 or 403)
            restricted_domains.append(domain)
            if args.verbose:
                print(f"Restricted domain (status {status}): {domain}")
            continue
        if error:
            # Error retrieving domain (other than restricted), skip it
            if args.verbose:
                print(f"Skipped domain due to error or no content: {domain}")
            continue
        if content is None:
            # No content retrieved, skip
            if args.verbose:
                print(f"No content retrieved for {domain}")
            continue

        # Normalize the HTML content for consistent hashing
        norm_content = normalize_content(content)
        # Hash the normalized content to detect duplicates (SHA-256 for uniqueness)
        content_hash = hashlib.sha256(norm_content.encode('utf-8')).hexdigest()

        # Group domains by content hash
        hash_map.setdefault(content_hash, []).append(domain)

    # Prepare lists of unique and duplicate domains based on hash groups
    unique_domains = []
    duplicate_domains = []

    for content_hash, domain_list in hash_map.items():
        if len(domain_list) == 1:
            # Only one domain for this hash => unique content
            unique_domains.extend(domain_list)
        else:
            # Multiple domains share the same hash => duplicates
            duplicate_domains.extend(domain_list)

    # Sort the lists for consistent output
    unique_domains.sort()
    duplicate_domains.sort()
    restricted_domains.sort()

    # Output results: write to files if --output provided, else print to console
    if args.output:
        base = args.output
        unique_file = f"{base}_unique.txt"
        duplicate_file = f"{base}_duplicate.txt"
        restricted_file = f"{base}_restricted.txt"

        try:
            with open(unique_file, 'w') as uf:
                uf.write("\n".join(unique_domains))
            with open(duplicate_file, 'w') as df:
                df.write("\n".join(duplicate_domains))
            with open(restricted_file, 'w') as rf:
                rf.write("\n".join(restricted_domains))
            if args.verbose:
                print(f"Results written to {unique_file}, {duplicate_file}, {restricted_file}")
        except Exception as e:
            print(f"Error writing output files: {e}")
            sys.exit(1)
    else:
        # Print results to console
        print("Unique domains:")
        for d in unique_domains:
            print(d)
        print("\nDuplicate domains:")
        for d in duplicate_domains:
            print(d)
        print("\nRestricted domains:")
        for d in restricted_domains:
            print(d)

if __name__ == "__main__":
    main()
