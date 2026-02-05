# YouTube Summarizer for Obsidian

Automatically fetch YouTube video transcripts, generate AI-powered summaries, and create organized notes in your Obsidian vault.

## Features

✅ **Transcript Extraction** - Automatically fetches transcripts from YouTube videos  
✅ **AI Summaries** - Generates comprehensive summaries using Claude  
✅ **Key Points** - Extracts 5-7 main takeaways from each video  
✅ **Smart Tagging** - Auto-generates relevant tags for categorization  
✅ **Obsidian Integration** - Creates beautifully formatted Markdown notes  
✅ **Dashboard Generation** - Automatically organizes videos by tags and channels  
✅ **Batch Processing** - Handle multiple videos from Watch Later playlists  
✅ **Channel Organization** - Groups videos by YouTube channel  

## Installation

### 1. Clone or Download

```bash
git clone <repository-url>
cd youtube-summarizer
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `youtube-transcript-api` - Fetches video transcripts
- `anthropic` - Generates AI summaries with Claude

### 3. Set Up API Key

Get your Anthropic API key from https://console.anthropic.com/

**Option A: Environment Variable (Recommended)**
```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

**Option B: .env File**
Create a `.env` file:
```
ANTHROPIC_API_KEY=your-api-key-here
```

### 4. Configure Vault Path

Edit `youtube_summarizer_enhanced.py` or create `config.py`:

```python
VAULT_PATH = "/Users/stanley/ObsidianVault"  # Update this
```

## Usage

### Command Line Interface (Recommended)

#### Process a Single Video

```bash
python cli.py -u "https://www.youtube.com/watch?v=VIDEO_ID"
```

#### Process Multiple Videos from File

Create a text file `watch_later.txt`:
```
https://www.youtube.com/watch?v=VIDEO_ID_1
https://www.youtube.com/watch?v=VIDEO_ID_2
https://www.youtube.com/watch?v=VIDEO_ID_3
```

Then run:
```bash
python cli.py -f watch_later.txt
```

#### Interactive Mode

```bash
python cli.py -i
```

Enter URLs one at a time, type `done` when finished.

#### Generate Dashboard Only

```bash
python cli.py --dashboard
```

### Python API

```python
from youtube_summarizer_enhanced import process_youtube_url

# Process a single video
url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
note_path = process_youtube_url(url)

# Process multiple videos
from youtube_summarizer_enhanced import process_watch_later_playlist

urls = [
    "https://www.youtube.com/watch?v=VIDEO_1",
    "https://www.youtube.com/watch?v=VIDEO_2",
]
process_watch_later_playlist(urls)
```

## Generated Note Structure

Each video note includes:

```markdown
# Video Title

## Metadata
- **Video ID:** abc123
- **URL:** https://youtube.com/watch?v=abc123
- **Channel:** [[Channel Name]]
- **Created:** 2024-12-23
- **Tags:** #youtube #security #malware

## Summary
AI-generated comprehensive summary (2-3 paragraphs)

## Key Points
- Main takeaway 1
- Main takeaway 2
- Main takeaway 3
...

## Transcript
```
[00:15] First line of transcript
[00:32] Second line of transcript
...
```
```

## Dashboard Organization

The script automatically generates dashboards:

### Weekly Dashboard
- Groups videos by tags
- Groups videos by channels
- Shows chronological list

### Monthly Dashboard (Coming Soon)
- Links to all weekly dashboards
- Monthly statistics

### Directory Structure

```
ObsidianVault/
├── YouTube Notes/
│   ├── Video Title 1.md
│   ├── Video Title 2.md
│   └── ...
├── Channels/
│   └── (Future: channel-specific pages)
└── Dashboards/
    ├── Week_2024-12-23.md
    ├── Week_2024-12-16.md
    └── ...
```

## How It Works

1. **Extract Video ID** - Parses YouTube URL to get video ID
2. **Fetch Transcript** - Uses YouTube Transcript API to get captions
3. **Generate Summary** - Sends transcript to Claude for analysis
4. **Extract Metadata** - Parses video title, channel, tags
5. **Create Note** - Generates formatted Markdown in Obsidian vault
6. **Update Dashboard** - Organizes videos by category

## Configuration Options

Edit `config_template.py` and save as `config.py`:

```python
# Vault Settings
VAULT_PATH = "~/ObsidianVault"
VIDEOS_FOLDER = "YouTube Notes"

# Summary Settings
SUMMARY_MODEL = "claude-sonnet-4-20250514"
MAX_TRANSCRIPT_LENGTH = 8000

# Transcript Settings
PREFERRED_LANGUAGES = ['en', 'en-US', 'en-GB']

# Dashboard Settings
WEEKLY_LOOKBACK_DAYS = 7
DEFAULT_TAG = "#youtube"
```

## Troubleshooting

### No Transcript Available

Some videos don't have transcripts (disabled by creator or auto-captions unavailable). The script will create a basic note with metadata only.

### API Rate Limits

If processing many videos, you may hit Anthropic API rate limits. The script handles this gracefully and continues with remaining videos.

### File Permission Errors

Ensure your Obsidian vault path is correct and you have write permissions.

### Module Not Found

Make sure you've installed all dependencies:
```bash
pip install -r requirements.txt
```

## Advanced Features

### Custom Note Templates

Modify `_build_note_content()` in `ObsidianNoteCreator` class to customize note format.

### Tag Customization

The AI automatically generates relevant tags, but you can add your own in the `DEFAULT_TAG` setting.

### Batch Processing

Process large playlists efficiently:

```python
# In youtube_summarizer_enhanced.py
BATCH_SIZE = 10  # Process 10 videos at a time
PAUSE_BETWEEN_BATCHES = 5  # 5 second pause between batches
```

## Getting YouTube Watch Later URLs

### Method 1: Manual Export
1. Go to https://www.youtube.com/playlist?list=WL
2. Copy each video URL
3. Paste into a text file

### Method 2: Browser Extension
Use a browser extension like "Copy All URLs" to export all URLs at once.

### Method 3: YouTube Data API (Advanced)
Use Google's YouTube Data API to programmatically fetch your Watch Later playlist.

## Examples

### Process Security Conference Talks

```bash
# Create a file with DefCon talks
cat > defcon_talks.txt << EOF
https://www.youtube.com/watch?v=TALK_1
https://www.youtube.com/watch?v=TALK_2
https://www.youtube.com/watch?v=TALK_3
EOF

# Process them
python cli.py -f defcon_talks.txt
```

### Daily Research Workflow

```bash
# 1. Export today's Watch Later videos to file
# 2. Process them
python cli.py -f todays_videos.txt

# 3. Generate dashboard
python cli.py --dashboard

# 4. Open Obsidian and review your notes!
```

## Contributing

Improvements welcome! Some ideas:

- [ ] YouTube Data API integration for automatic Watch Later sync
- [ ] Support for playlists
- [ ] Video thumbnail download
- [ ] Speaker identification in transcripts
- [ ] Custom summary prompts
- [ ] Export to other note-taking apps

## License

MIT License - feel free to use and modify!

## Credits

- Built with [youtube-transcript-api](https://github.com/jdepoix/youtube-transcript-api)
- Powered by [Anthropic Claude](https://www.anthropic.com/)
- Designed for [Obsidian](https://obsidian.md/)

## Support

For issues or questions:
1. Check the Troubleshooting section
2. Review the examples
3. Open an issue on GitHub

---

**Happy note-taking! 📝**
