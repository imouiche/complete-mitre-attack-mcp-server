#!/usr/bin/env python3
"""
Download MITRE ATT&CK data using the official mitreattack-python library.

This module handles downloading STIX data for all three domains:
- Enterprise (Windows, Linux, macOS, Cloud, Network)
- Mobile (iOS, Android)
- ICS (Industrial Control Systems)
"""
import os
from pathlib import Path
from typing import List, Tuple

from mitreattack import download_stix, release_info



# Base data directory (default: ~/.mitre-mcp-server/data))
BASE_DATA_DIR = Path(
    os.getenv(
        "MITRE_MCP_DATA_DIR",
        Path.home() / ".mitre-mcp-server" / "data",
    )
)

DATA_DIR = BASE_DATA_DIR
print(f"Using data directory: {DATA_DIR}")
DOMAINS = ["enterprise", "mobile", "ics"]



def check_existing_data() -> List[str]:
    """Check which domains already have data downloaded.
    
    Returns:
        List of domain names that have existing data files
    """
    existing_domains = []
    
    for domain in DOMAINS:
        domain_key = f"{domain}-attack"
        # Check in versioned directory
        version_dir = DATA_DIR / f"v{release_info.LATEST_VERSION}"
        stix_path = version_dir / f"{domain_key}.json"
        
        if stix_path.exists():
            existing_domains.append(domain)
    
    return existing_domains


def download_domain_data(domain: str, force: bool = False) -> Tuple[str, Path]:
    """Download STIX data for a specific domain.
    
    Args:
        domain: Domain name ('enterprise', 'mobile', or 'ics')
        force: If True, download even if file already exists
        
    Returns:
        Tuple of (domain, file_path) for the downloaded file
        
    Raises:
        ValueError: If domain is not valid
        RuntimeError: If download fails
    """
    if domain not in DOMAINS:
        raise ValueError(f"Invalid domain '{domain}'. Must be one of: {DOMAINS}")
    
    domain_key = f"{domain}-attack"
    version_dir = DATA_DIR / f"v{release_info.LATEST_VERSION}"
    stix_path = version_dir / f"{domain_key}.json"
    
    # Check if file already exists and skip if not forcing
    if stix_path.exists() and not force:
        print(f"✓ {domain.capitalize()} domain data already exists (use --force to re-download)")
        return (domain, stix_path)
    
    # Get release information and hash for verification
    releases = release_info.STIX21[domain]
    known_hash = releases[release_info.LATEST_VERSION]
    
    print(f"⬇ Downloading {domain.capitalize()} domain (version {release_info.LATEST_VERSION})...")
    
    try:
        # Download STIX data
        download_stix.download_stix(
            stix_version="2.1",
            domain=domain,
            download_dir=str(DATA_DIR),
            release=release_info.LATEST_VERSION,
            known_hash=known_hash,
        )
        
        # Verify the file was created
        if stix_path.exists():
            file_size_mb = stix_path.stat().st_size / (1024 * 1024)
            print(f"✓ {domain.capitalize()} domain downloaded successfully ({file_size_mb:.2f} MB)")
            return (domain, stix_path)
        else:
            raise RuntimeError(f"Download completed but file not found at {stix_path}")
            
    except Exception as e:
        raise RuntimeError(f"Failed to download {domain} domain: {str(e)}")


def download_all_domains(force: bool = False) -> List[Tuple[str, Path]]:
    """Download STIX data for all domains (with caching).
    
    Args:
        force: If True, re-download even if files exist
        
    Returns:
        List of tuples containing (domain, file_path) for each domain
    """
    print(f"📥 MITRE ATT&CK Data Downloader (Version {release_info.LATEST_VERSION})")
    print("=" * 70)
    
    # Check existing data if not forcing
    if not force:
        existing = check_existing_data()
        if existing:
            print(f"\n✓ Found existing data for: {', '.join(existing)}")
            print("  (Use --force to re-download)")
    
    # Create data directory if it doesn't exist
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # Download each domain
    downloaded_files = []
    failed_domains = []
    
    for domain in DOMAINS:
        try:
            domain_data = download_domain_data(domain, force=force)
            downloaded_files.append(domain_data)
        except Exception as e:
            print(f"✗ Error downloading {domain}: {e}")
            failed_domains.append(domain)
    
    # Summary
    print("\n" + "=" * 70)
    print(f"✓ Successfully downloaded: {len(downloaded_files)}/{len(DOMAINS)} domains")
    
    if failed_domains:
        print(f"✗ Failed domains: {', '.join(failed_domains)}")
    
    # Print file locations
    if downloaded_files:
        print("\n📁 Data files:")
        for domain, path in downloaded_files:
            print(f"   {domain.capitalize()}: {path}")
    
    return downloaded_files


def get_data_stats() -> dict:
    """Get statistics about downloaded data.
    
    Returns:
        Dictionary with stats about each domain
    """
    stats = {}
    
    for domain in DOMAINS:
        domain_key = f"{domain}-attack"
        version_dir = DATA_DIR / f"v{release_info.LATEST_VERSION}"
        stix_path = version_dir / f"{domain_key}.json"
        
        if stix_path.exists():
            file_size_mb = stix_path.stat().st_size / (1024 * 1024)
            stats[domain] = {
                "exists": True,
                "path": str(stix_path),
                "size_mb": round(file_size_mb, 2),
                "version": release_info.LATEST_VERSION
            }
        else:
            stats[domain] = {
                "exists": False,
                "path": None,
                "size_mb": 0,
                "version": None
            }
    
    return stats


def main():
    """Main entry point for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Download MITRE ATT&CK STIX data"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-download even if files exist"
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show statistics about downloaded data"
    )
    parser.add_argument(
        "--domain",
        choices=DOMAINS,
        help="Download only a specific domain (default: all)"
    )
    
    args = parser.parse_args()
    
    if args.stats:
        # Show statistics
        stats = get_data_stats()
        print("\n📊 MITRE ATT&CK Data Statistics:")
        print("=" * 70)
        for domain, info in stats.items():
            status = "✓ Downloaded" if info["exists"] else "✗ Not downloaded"
            print(f"\n{domain.capitalize()}: {status}")
            if info["exists"]:
                print(f"   Path: {info['path']}")
                print(f"   Size: {info['size_mb']} MB")
                print(f"   Version: {info['version']}")
    elif args.domain:
        # Download specific domain
        try:
            download_domain_data(args.domain, force=args.force)
        except Exception as e:
            print(f"Error: {e}")
            return 1
    else:
        # Download all domains
        download_all_domains(force=args.force)
    
    return 0


if __name__ == "__main__":
    exit(main())