#!/usr/bin/env python3
"""
YouTube Summarizer Enhanced
Processes YouTube URLs and generates AI summaries for Obsidian
"""

import os
import re
import time
from datetime import datetime
from pathlib import Path
from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api._errors import TranscriptsDisabled, NoTranscriptFound
import anthropic
from anthropic import APIError, RateLimitError
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import config
import config

# Export config values for CLI
VAULT_PATH = config.VAULT_PATH


def extract_video_id(url):
    """Extract video ID from various YouTube URL formats"""
    patterns = [
        r'(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]{11})',
        r'youtube\.com\/embed\/([a-zA-Z0-9_-]{11})',
        r'youtube\.com\/v\/([a-zA-Z0-9_-]{11})'
    ]

    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None


def get_video_info(video_id):
    """Get video metadata from YouTube"""
    try:
        # Use YouTube oEmbed API (no auth required)
        url = f"https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v={video_id}&format=json"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return {
                'title': data.get('title', 'Unknown Title'),
                'channel': data.get('author_name', 'Unknown Channel'),
                'id': video_id
            }
    except:
        pass

    return {
        'title': f'Video {video_id}',
        'channel': 'Unknown Channel',
        'id': video_id
    }


def get_transcript(video_id):
    """Get transcript for a YouTube video"""
    try:
        api = YouTubeTranscriptApi()
        transcript = api.fetch(video_id, languages=config.PREFERRED_LANGUAGES)
        full_transcript = ' '.join([snippet.text for snippet in transcript.snippets])
        return full_transcript
    except (TranscriptsDisabled, NoTranscriptFound):
        # Try auto-generated with English
        try:
            api = YouTubeTranscriptApi()
            transcript = api.fetch(video_id, languages=['en'])
            full_transcript = ' '.join([snippet.text for snippet in transcript.snippets])
            return full_transcript
        except:
            return None
    except Exception as e:
        print(f"  ⚠️  Transcript error: {str(e)}")
        return None


def truncate_transcript(transcript, max_length=None):
    """Truncate transcript if needed"""
    if max_length is None:
        max_length = config.MAX_TRANSCRIPT_LENGTH

    if len(transcript) <= max_length:
        return transcript

    # Take beginning and end
    half = max_length // 2
    return f"{transcript[:half]}\n\n[...truncated...]\n\n{transcript[-half:]}"


def summarize_with_claude(video_info, transcript):
    """Generate summary using Claude"""
    if not config.ANTHROPIC_API_KEY:
        return None

    try:
        client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)

        processed_transcript = truncate_transcript(transcript)

        prompt = f"""You are analyzing a YouTube video to create a comprehensive summary for note-taking.

**Video Details:**
- Title: {video_info['title']}
- Channel: {video_info['channel']}

**Transcript:**
{processed_transcript}

**Create a detailed summary with these sections:**

## Overview
Write 2-3 sentences capturing the main topic and key takeaway.

## Key Points
- List 5-8 main points from the video
- Focus on actionable insights and important concepts
- Use clear bullet points

## Notable Insights
- Include 2-3 memorable quotes or unique perspectives
- Highlight surprising or counterintuitive points

## Target Audience
- Who would benefit most from watching this
- Specific use cases

## Practical Applications
- How to apply what was learned
- Any resources or next steps mentioned

Format as clean markdown."""

        message = client.messages.create(
            model=config.SUMMARY_MODEL,
            max_tokens=config.MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}]
        )

        summary = message.content[0].text

        # Calculate cost
        usage = message.usage
        cost = (usage.input_tokens / 1_000_000 * 3.00) + (usage.output_tokens / 1_000_000 * 15.00)

        print(f"  💰 Tokens: {usage.input_tokens} in, {usage.output_tokens} out (${cost:.4f})")

        return summary

    except RateLimitError:
        print(f"  ⚠️  Rate limit hit, waiting...")
        time.sleep(5)
        return None
    except Exception as e:
        print(f"  ❌ Claude API error: {str(e)}")
        return None


def create_obsidian_note(video_info, summary, vault_path):
    """Create markdown note in Obsidian vault"""
    vault = Path(vault_path)
    notes_folder = vault / config.VIDEOS_FOLDER
    notes_folder.mkdir(parents=True, exist_ok=True)

    # Sanitize filename
    safe_title = re.sub(r'[<>:"/\\|?*]', '', video_info['title'])
    safe_title = safe_title[:config.MAX_FILENAME_LENGTH]

    filename = f"{safe_title}.md"
    filepath = notes_folder / filename

    # Create note content
    content = f"""---
title: {video_info['title']}
channel: {video_info['channel']}
video_id: {video_info['id']}
url: https://www.youtube.com/watch?v={video_info['id']}
date: {datetime.now().strftime('%Y-%m-%d')}
tags: [{config.DEFAULT_TAG}]
---

# {video_info['title']}

**Channel:** [[{video_info['channel']}]]
**Watch:** [YouTube](https://www.youtube.com/watch?v={video_info['id']})

---

{summary}

---

*Generated by YouTube Summarizer on {datetime.now().strftime('%Y-%m-%d at %I:%M %p')}*
"""

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"  ✅ Saved to: {filepath.name}")
    return filepath


def process_youtube_url(url, vault_path):
    """Process a single YouTube URL"""
    print(f"\n📹 Processing: {url}")

    # Extract video ID
    video_id = extract_video_id(url)
    if not video_id:
        print(f"  ❌ Invalid YouTube URL")
        return False

    # Get video info
    print(f"  📊 Fetching video info...")
    video_info = get_video_info(video_id)
    print(f"  ✓ {video_info['title']}")

    # Get transcript
    print(f"  📝 Fetching transcript...")
    transcript = get_transcript(video_id)

    if not transcript:
        print(f"  ❌ No transcript available, skipping")
        return False

    print(f"  ✓ Transcript found ({len(transcript.split())} words)")

    # Generate summary
    print(f"  🤖 Generating AI summary...")
    summary = summarize_with_claude(video_info, transcript)

    if not summary:
        print(f"  ❌ Failed to generate summary")
        return False

    # Save to Obsidian
    create_obsidian_note(video_info, summary, vault_path)

    return True


def process_watch_later_playlist(urls, vault_path):
    """Process multiple URLs"""
    print(f"\n🚀 Processing {len(urls)} videos...")
    print(f"📂 Vault: {vault_path}\n")

    successful = 0
    failed = 0

    for i, url in enumerate(urls, 1):
        print(f"\n[{i}/{len(urls)}]", end=" ")

        if process_youtube_url(url, vault_path):
            successful += 1
        else:
            failed += 1

        # Pause between videos to avoid rate limits
        if i < len(urls) and i % config.BATCH_SIZE == 0:
            print(f"\n⏸  Pausing {config.PAUSE_BETWEEN_BATCHES}s to avoid rate limits...")
            time.sleep(config.PAUSE_BETWEEN_BATCHES)

    # Summary
    print("\n" + "="*60)
    print(f"📈 Processing Complete!")
    print(f"   ✅ Successful: {successful}")
    print(f"   ❌ Failed: {failed}")
    print(f"   📁 Notes saved to: {Path(vault_path) / config.VIDEOS_FOLDER}")
    print("="*60)


class DashboardGenerator:
    """Generate Obsidian dashboard from notes"""
    def __init__(self, vault_path):
        self.vault_path = Path(vault_path)

    def generate_weekly_dashboard(self):
        """Generate a weekly summary dashboard"""
        print("📊 Dashboard generation not yet implemented")
        print("   Your notes are ready in the YouTube Notes folder!")
