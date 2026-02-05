#!/usr/bin/env python3
"""
YouTube Watch Later Summarizer
Fetches videos from your YouTube Watch Later playlist and generates detailed summaries.
Enhanced with advanced Claude API integration.
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api._errors import TranscriptsDisabled, NoTranscriptFound
import anthropic
from anthropic import APIError, RateLimitError, APIConnectionError

# ============================================================================
# CONFIGURATION - Customize these settings
# ============================================================================

# YouTube API Configuration
SCOPES = ['https://www.googleapis.com/auth/youtube.readonly']
TOKEN_FILE = 'token.json'
CREDENTIALS_FILE = 'credentials.json'

# Claude API Configuration
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
CLAUDE_MODEL = 'claude-sonnet-4-5-20250929'  # Options: claude-opus-4-5-20251101, claude-sonnet-4-5-20250929, claude-haiku-4-5-20251001
MAX_TOKENS = 2000  # Increase for longer, more detailed summaries
TEMPERATURE = 1.0  # 0.0 = focused, 1.0 = creative

# Retry Configuration
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds
BACKOFF_MULTIPLIER = 2

# Processing Options
MAX_TRANSCRIPT_LENGTH = 50000  # characters to send to Claude
CACHE_SUMMARIES = True  # Cache summaries to avoid re-processing
CACHE_FILE = 'summary_cache.json'

# Output Configuration
OUTPUT_FILE = f'watch_later_summaries_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def load_cache():
    """Load cached summaries from file."""
    if CACHE_SUMMARIES and os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}


def save_cache(cache):
    """Save summaries to cache file."""
    if CACHE_SUMMARIES:
        try:
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(cache, f, indent=2)
        except Exception as e:
            print(f"⚠️  Warning: Could not save cache: {e}")


def estimate_tokens(text):
    """Rough token estimation (1 token ≈ 4 characters)."""
    return len(text) // 4


def estimate_cost(input_tokens, output_tokens, model=CLAUDE_MODEL):
    """Estimate API cost based on model pricing."""
    # Pricing as of early 2026 (verify current rates)
    pricing = {
        'claude-opus-4-5-20251101': {'input': 15.00, 'output': 75.00},  # per 1M tokens
        'claude-sonnet-4-5-20250929': {'input': 3.00, 'output': 15.00},
        'claude-haiku-4-5-20251001': {'input': 0.80, 'output': 4.00}
    }

    rates = pricing.get(model, pricing['claude-sonnet-4-5-20250929'])
    input_cost = (input_tokens / 1_000_000) * rates['input']
    output_cost = (output_tokens / 1_000_000) * rates['output']

    return input_cost + output_cost


def get_youtube_service():
    """Authenticate and return YouTube API service."""
    creds = None

    # Load existing token if available
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    # If no valid credentials, authenticate
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(CREDENTIALS_FILE):
                print(f"❌ Error: {CREDENTIALS_FILE} not found!")
                print("Please follow the setup instructions to get your OAuth credentials.")
                exit(1)

            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)

        # Save credentials for next time
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())

    return build('youtube', 'v3', credentials=creds)


def get_watch_later_videos(youtube):
    """Fetch all videos from Watch Later playlist."""
    print("📺 Fetching Watch Later videos...")

    videos = []
    request = youtube.playlistItems().list(
        part='snippet,contentDetails',
        playlistId='WL',  # WL is the Watch Later playlist ID
        maxResults=50
    )

    while request:
        response = request.execute()

        for item in response['items']:
            video_info = {
                'id': item['contentDetails']['videoId'],
                'title': item['snippet']['title'],
                'channel': item['snippet']['channelTitle'],
                'added_at': item['snippet']['publishedAt'],
                'description': item['snippet']['description']
            }
            videos.append(video_info)

        request = youtube.playlistItems().list_next(request, response)

    print(f"✅ Found {len(videos)} videos in Watch Later")
    return videos


def get_video_transcript(video_id):
    """Get transcript for a video."""
    try:
        transcript_list = YouTubeTranscriptApi.get_transcript(video_id)
        # Combine all transcript segments
        full_transcript = ' '.join([segment['text'] for segment in transcript_list])
        return full_transcript
    except (TranscriptsDisabled, NoTranscriptFound):
        return None
    except Exception as e:
        print(f"⚠️  Error getting transcript: {str(e)}")
        return None


def truncate_transcript(transcript, max_length=MAX_TRANSCRIPT_LENGTH):
    """Intelligently truncate transcript while preserving context."""
    if len(transcript) <= max_length:
        return transcript

    # Take beginning and end to preserve context
    half_length = max_length // 2
    beginning = transcript[:half_length]
    end = transcript[-half_length:]

    return f"{beginning}\n\n[... middle section truncated for length ...]\n\n{end}"


def summarize_with_claude(video_info, transcript, retry_count=0):
    """Generate detailed summary using Claude API with retry logic."""
    if not ANTHROPIC_API_KEY:
        return None, "No API key"

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

        # Truncate transcript if needed
        processed_transcript = truncate_transcript(transcript)

        # Enhanced prompt for better summaries
        prompt = f"""You are analyzing a YouTube video to create a comprehensive, actionable summary.

**Video Details:**
- Title: {video_info['title']}
- Channel: {video_info['channel']}
- Description: {video_info['description'][:200]}

**Transcript:**
{processed_transcript}

**Please create a detailed summary with the following sections:**

**Overview:** Write 2-3 sentences that capture the main topic, purpose, and key takeaway of this video.

**Key Points:**
- List 5-8 main points or arguments presented in the video
- Focus on actionable insights and important concepts
- Use bullet points for clarity

**Notable Quotes or Insights:**
- Include 2-3 memorable quotes or unique perspectives (if any)
- Highlight any surprising or counterintuitive points

**Who Should Watch:**
- Describe the target audience
- List specific scenarios where this video would be valuable

**Practical Applications:**
- How can viewers apply what they learned?
- Any resources or next steps mentioned?

Format your response in clean markdown with clear headers."""

        # Estimate input tokens
        input_tokens = estimate_tokens(prompt)

        # Make API call
        message = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
            messages=[{"role": "user", "content": prompt}]
        )

        # Extract response
        summary = message.content[0].text

        # Calculate actual usage and cost
        usage = message.usage
        cost = estimate_cost(usage.input_tokens, usage.output_tokens, CLAUDE_MODEL)

        print(f"  💰 Tokens: {usage.input_tokens} in, {usage.output_tokens} out (${cost:.4f})")

        return summary, cost

    except RateLimitError as e:
        print(f"  ⚠️  Rate limit hit. Waiting before retry...")
        if retry_count < MAX_RETRIES:
            time.sleep(RETRY_DELAY * (BACKOFF_MULTIPLIER ** retry_count))
            return summarize_with_claude(video_info, transcript, retry_count + 1)
        else:
            print(f"  ❌ Max retries exceeded. Falling back to basic summary.")
            return None, "Rate limit exceeded"

    except APIConnectionError as e:
        print(f"  ⚠️  Connection error. Retrying...")
        if retry_count < MAX_RETRIES:
            time.sleep(RETRY_DELAY * (BACKOFF_MULTIPLIER ** retry_count))
            return summarize_with_claude(video_info, transcript, retry_count + 1)
        else:
            print(f"  ❌ Connection failed after {MAX_RETRIES} retries.")
            return None, "Connection error"

    except APIError as e:
        print(f"  ❌ Claude API error: {str(e)}")
        return None, str(e)

    except Exception as e:
        print(f"  ❌ Unexpected error: {str(e)}")
        return None, str(e)


def create_basic_summary(video_info, transcript):
    """Create basic summary without AI."""
    if not transcript:
        return f"**Description:** {video_info['description'][:500]}\n\n*No transcript available for detailed summary.*"

    # Simple extraction: first few sentences
    sentences = transcript.split('. ')[:5]
    preview = '. '.join(sentences) + '.'

    word_count = len(transcript.split())
    duration_estimate = word_count // 150  # Rough estimate: 150 words per minute

    return f"""**Overview:** {preview}

**Video Stats:**
- Estimated duration: ~{duration_estimate} minutes
- Transcript length: {word_count} words

*For detailed AI-powered summaries, set your ANTHROPIC_API_KEY environment variable.*"""


def generate_markdown_report(videos_with_summaries, output_file, total_cost):
    """Generate markdown report with all summaries."""
    print(f"📝 Generating markdown report...")

    with open(output_file, 'w', encoding='utf-8') as f:
        # Header
        f.write(f"# YouTube Watch Later Summaries\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%B %d, %Y at %I:%M %p')}\n\n")
        f.write(f"**Total Videos:** {len(videos_with_summaries)}\n\n")

        if ANTHROPIC_API_KEY and total_cost > 0:
            f.write(f"**AI Model:** {CLAUDE_MODEL}\n\n")
            f.write(f"**Estimated Cost:** ${total_cost:.4f}\n\n")

        f.write("---\n\n")

        # Table of contents
        f.write("## 📑 Table of Contents\n\n")
        for i, video in enumerate(videos_with_summaries, 1):
            # Create URL-safe anchor
            anchor = video['title'].lower()
            anchor = ''.join(c if c.isalnum() or c == ' ' else '' for c in anchor)
            anchor = anchor.replace(' ', '-')[:50]
            f.write(f"{i}. [{video['title']}](#{i}-{anchor})\n")
        f.write("\n---\n\n")

        # Individual summaries
        for i, video in enumerate(videos_with_summaries, 1):
            anchor = video['title'].lower()
            anchor = ''.join(c if c.isalnum() or c == ' ' else '' for c in anchor)
            anchor = anchor.replace(' ', '-')[:50]

            f.write(f"## {i}. {video['title']}\n\n")
            f.write(f"**Channel:** {video['channel']}\n\n")
            f.write(f"**Watch:** https://youtube.com/watch?v={video['id']}\n\n")
            f.write(f"**Added to Watch Later:** {video['added_at'][:10]}\n\n")
            f.write("### Summary\n\n")
            f.write(f"{video['summary']}\n\n")
            f.write("---\n\n")

    print(f"✅ Report saved to: {output_file}")


def main():
    """Main execution flow."""
    print("🚀 YouTube Watch Later Summarizer")
    print(f"📊 Using Claude model: {CLAUDE_MODEL}\n")

    # Load cache
    cache = load_cache()
    cache_hits = 0

    # Authenticate with YouTube
    youtube = get_youtube_service()

    # Get Watch Later videos
    videos = get_watch_later_videos(youtube)

    if not videos:
        print("No videos found in Watch Later!")
        return

    # Check if Claude API is configured
    if ANTHROPIC_API_KEY:
        print(f"✅ Claude API configured ({CLAUDE_MODEL})")
    else:
        print("⚠️  Claude API key not set. Will use basic summaries.")
        print("   Set ANTHROPIC_API_KEY environment variable for AI-powered summaries.\n")

    # Process each video
    videos_with_summaries = []
    total_cost = 0.0

    for i, video in enumerate(videos, 1):
        print(f"\n[{i}/{len(videos)}] Processing: {video['title'][:60]}...")

        # Check cache first
        if video['id'] in cache:
            print(f"  ✓ Using cached summary")
            video['summary'] = cache[video['id']]
            cache_hits += 1
            videos_with_summaries.append(video)
            continue

        # Get transcript
        transcript = get_video_transcript(video['id'])

        if transcript:
            print(f"  ✓ Transcript found ({len(transcript.split())} words)")

            # Generate summary with Claude if API key is available
            if ANTHROPIC_API_KEY:
                print(f"  🤖 Generating AI summary...")
                summary, cost = summarize_with_claude(video, transcript)

                if summary:
                    video['summary'] = summary
                    if isinstance(cost, float):
                        total_cost += cost
                    # Cache the summary
                    cache[video['id']] = summary
                else:
                    # Fallback to basic summary
                    video['summary'] = create_basic_summary(video, transcript)
            else:
                video['summary'] = create_basic_summary(video, transcript)
        else:
            print(f"  ⚠️  No transcript available")
            video['summary'] = create_basic_summary(video, None)

        videos_with_summaries.append(video)

        # Save cache after each video
        save_cache(cache)

    # Print statistics
    print("\n" + "="*60)
    print(f"📈 Processing Statistics:")
    print(f"   Total videos: {len(videos)}")
    print(f"   Cache hits: {cache_hits}")
    print(f"   New summaries: {len(videos) - cache_hits}")
    if total_cost > 0:
        print(f"   Total cost: ${total_cost:.4f}")
        print(f"   Avg cost per video: ${total_cost / (len(videos) - cache_hits):.4f}")
    print("="*60 + "\n")

    # Generate final report
    generate_markdown_report(videos_with_summaries, OUTPUT_FILE, total_cost)
    print(f"\n🎉 Done! Check out {OUTPUT_FILE}")

    if CACHE_SUMMARIES:
        print(f"💾 Summaries cached to {CACHE_FILE} for future runs")


if __name__ == '__main__':
    main()
