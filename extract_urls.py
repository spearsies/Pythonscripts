"""
YouTube Watch Later URL Extractor
Helper script to extract video URLs from your browser

Since YouTube doesn't provide a direct export, this provides instructions
and helper functions for different methods.
"""

import re
import sys
from pathlib import Path

def extract_urls_from_text(text: str) -> list:
    """
    Extract YouTube video URLs from any text
    Handles various YouTube URL formats
    """
    patterns = [
        r'https?://(?:www\.)?youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})',
        r'https?://youtu\.be/([a-zA-Z0-9_-]{11})',
        r'youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})',
        r'youtu\.be/([a-zA-Z0-9_-]{11})'
    ]
    
    urls = set()
    for pattern in patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            video_id = match.group(1)
            urls.add(f"https://www.youtube.com/watch?v={video_id}")
    
    return sorted(list(urls))

def process_file(input_file: str, output_file: str = None):
    """
    Process a text file and extract all YouTube URLs
    """
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        urls = extract_urls_from_text(content)
        
        if not urls:
            print(f"No YouTube URLs found in {input_file}")
            return
        
        print(f"Found {len(urls)} unique YouTube URLs")
        
        # Output
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# Extracted YouTube URLs\n")
                f.write(f"# Extracted from: {input_file}\n")
                f.write(f"# Total videos: {len(urls)}\n\n")
                for url in urls:
                    f.write(f"{url}\n")
            print(f"Saved to: {output_file}")
        else:
            print("\nExtracted URLs:")
            for i, url in enumerate(urls, 1):
                print(f"{i}. {url}")
    
    except FileNotFoundError:
        print(f"Error: File not found: {input_file}")
    except Exception as e:
        print(f"Error: {e}")

def process_clipboard():
    """
    Extract URLs from clipboard content
    """
    try:
        import pyperclip
        content = pyperclip.paste()
        urls = extract_urls_from_text(content)
        
        if not urls:
            print("No YouTube URLs found in clipboard")
            return
        
        print(f"Found {len(urls)} YouTube URLs in clipboard\n")
        
        # Copy back to clipboard
        output = "\n".join(urls)
        pyperclip.copy(output)
        
        print("URLs copied to clipboard!")
        print("\nExtracted URLs:")
        for i, url in enumerate(urls, 1):
            print(f"{i}. {url}")
        
        # Save to file
        save = input("\nSave to file? (y/n): ").lower()
        if save == 'y':
            filename = input("Filename (default: watch_later.txt): ").strip()
            if not filename:
                filename = "watch_later.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("# Extracted YouTube URLs\n")
                f.write(f"# Total videos: {len(urls)}\n\n")
                f.write(output)
            
            print(f"Saved to: {filename}")
    
    except ImportError:
        print("Error: pyperclip not installed")
        print("Install with: pip install pyperclip")
    except Exception as e:
        print(f"Error: {e}")

def print_instructions():
    """
    Print instructions for getting Watch Later URLs
    """
    instructions = """
================================
YouTube Watch Later URL Extraction
================================

METHOD 1: Browser DevTools (Recommended)
-----------------------------------------
1. Open your Watch Later playlist:
   https://www.youtube.com/playlist?list=WL

2. Scroll down to load all videos
   (or use Console command below to auto-scroll)

3. Open DevTools (F12 or Cmd+Option+I)

4. Go to Console tab

5. Paste this JavaScript and press Enter:

   // Extract all video URLs
   const urls = Array.from(document.querySelectorAll('a#video-title'))
     .map(a => a.href)
     .filter(url => url.includes('watch?v='));
   
   // Copy to clipboard
   copy(urls.join('\\n'));
   console.log(`Copied ${urls.length} URLs to clipboard!`);

6. The URLs are now in your clipboard!
   Paste them into a text file


METHOD 2: Browser Extension
----------------------------
Install "Copy All URLs" or similar extension:
- Chrome: https://chrome.google.com/webstore (search "Copy All URLs")
- Firefox: https://addons.mozilla.org (search "Copy All URLs")

1. Open Watch Later playlist
2. Click extension icon
3. Click "Copy All URLs"
4. Paste into text file


METHOD 3: Manual Copy
----------------------
1. Right-click each video title
2. Select "Copy link address"
3. Paste into text file
(Only practical for small numbers of videos)


METHOD 4: YouTube Data API (Advanced)
--------------------------------------
Use Google's YouTube Data API to programmatically fetch:
- Requires API key setup
- Can automate the entire process
- See: https://developers.google.com/youtube/v3


USING THIS SCRIPT
-----------------
After getting URLs in a file:

# Extract and clean URLs from a file
python extract_urls.py -f raw_data.txt -o watch_later.txt

# Extract URLs from clipboard
python extract_urls.py --clipboard

# Process and pipe directly to CLI
python extract_urls.py -f urls.txt | python cli.py -f -


TIPS
----
- Watch Later max: 5,000 videos
- Scroll to load all videos before extracting
- Some videos may be private/deleted (will be skipped)
- Consider breaking large lists into batches
"""
    print(instructions)

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print_instructions()
        return
    
    import argparse
    parser = argparse.ArgumentParser(description="Extract YouTube URLs from various sources")
    parser.add_argument('-f', '--file', help='Input file containing YouTube URLs')
    parser.add_argument('-o', '--output', help='Output file for cleaned URLs')
    parser.add_argument('-c', '--clipboard', action='store_true', help='Process clipboard content')
    parser.add_argument('--instructions', action='store_true', help='Show detailed instructions')
    
    args = parser.parse_args()
    
    if args.instructions:
        print_instructions()
    elif args.clipboard:
        process_clipboard()
    elif args.file:
        process_file(args.file, args.output)
    else:
        print_instructions()

if __name__ == "__main__":
    main()
