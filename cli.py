#!/usr/bin/env python3
"""
YouTube Summarizer CLI
Easy command-line interface for processing YouTube videos
"""

import sys
import argparse
from pathlib import Path
from youtube_summarizer_enhanced import (
    process_youtube_url,
    process_watch_later_playlist,
    DashboardGenerator,
    VAULT_PATH
)

def process_from_file(filepath: str, vault_path: str):
    """Process URLs from a text file (one URL per line)"""
    try:
        with open(filepath, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if not urls:
            print(f"No valid URLs found in {filepath}")
            return
        
        print(f"Found {len(urls)} URLs in {filepath}")
        process_watch_later_playlist(urls, vault_path)
        
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
    except Exception as e:
        print(f"Error reading file: {e}")

def interactive_mode(vault_path: str):
    """Interactive mode for entering URLs"""
    print("\n=== YouTube Summarizer - Interactive Mode ===")
    print("Enter YouTube URLs (one per line)")
    print("Enter 'done' when finished, or 'quit' to exit\n")
    
    urls = []
    while True:
        try:
            url = input(f"URL #{len(urls) + 1}: ").strip()
            
            if url.lower() == 'quit':
                print("Exiting...")
                return
            
            if url.lower() == 'done':
                break
            
            if url and ('youtube.com' in url or 'youtu.be' in url):
                urls.append(url)
                print(f"  ✓ Added ({len(urls)} total)")
            elif url:
                print("  ✗ Invalid YouTube URL")
        
        except KeyboardInterrupt:
            print("\nOperation cancelled")
            return
    
    if urls:
        print(f"\nProcessing {len(urls)} videos...")
        process_watch_later_playlist(urls, vault_path)
    else:
        print("No URLs to process")

def main():
    parser = argparse.ArgumentParser(
        description="YouTube Video Summarizer for Obsidian",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process a single video
  python cli.py -u "https://www.youtube.com/watch?v=VIDEO_ID"
  
  # Process multiple videos from a file
  python cli.py -f watch_later.txt
  
  # Interactive mode
  python cli.py -i
  
  # Generate dashboard only
  python cli.py --dashboard
  
  # Custom vault path
  python cli.py -u "https://youtube.com/..." --vault ~/MyVault
        """
    )
    
    parser.add_argument(
        '-u', '--url',
        help='Single YouTube video URL to process'
    )
    
    parser.add_argument(
        '-f', '--file',
        help='Text file containing YouTube URLs (one per line)'
    )
    
    parser.add_argument(
        '-i', '--interactive',
        action='store_true',
        help='Interactive mode - enter URLs manually'
    )
    
    parser.add_argument(
        '--dashboard',
        action='store_true',
        help='Generate weekly dashboard from existing notes'
    )
    
    parser.add_argument(
        '--vault',
        default=VAULT_PATH,
        help=f'Path to Obsidian vault (default: {VAULT_PATH})'
    )
    
    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='Number of days to include in dashboard (default: 7)'
    )
    
    args = parser.parse_args()
    
    # Validate vault path
    vault_path = Path(args.vault)
    if not vault_path.exists():
        print(f"Warning: Vault path does not exist: {vault_path}")
        create = input("Create this directory? (y/n): ").lower()
        if create == 'y':
            vault_path.mkdir(parents=True, exist_ok=True)
            print(f"Created: {vault_path}")
        else:
            print("Exiting...")
            return
    
    # Process based on arguments
    if args.dashboard:
        print("Generating dashboard...")
        dashboard_gen = DashboardGenerator(str(vault_path))
        dashboard_gen.generate_weekly_dashboard()
        
    elif args.url:
        process_youtube_url(args.url, str(vault_path))
        
    elif args.file:
        process_from_file(args.file, str(vault_path))
        
    elif args.interactive:
        interactive_mode(str(vault_path))
        
    else:
        parser.print_help()
        print("\nNo action specified. Use -h for help.")

if __name__ == "__main__":
    main()
