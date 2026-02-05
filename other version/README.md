# YouTube Watch Later Summarizer 📺

Automatically fetch and summarize videos from your YouTube Watch Later playlist with detailed AI-powered summaries.

## Features ✨

- 🔐 **OAuth Authentication**: Secure access to your private Watch Later playlist
- 📝 **AI-Powered Summaries**: Detailed analysis with key points, insights, and actionable takeaways
- 🎯 **Automatic Transcripts**: Extracts and processes video transcripts automatically
- 📊 **Beautiful Reports**: Generates organized markdown files with table of contents
- 🤖 **Claude API Integration**: Advanced summarization with Opus, Sonnet, or Haiku models
- 💾 **Smart Caching**: Saves summaries to avoid re-processing (saves money!)
- 🔄 **Retry Logic**: Automatic retry with exponential backoff for API failures
- 💰 **Cost Tracking**: Real-time cost estimates and total spend reporting
- ⚡ **Flexible Fallback**: Works with or without API key

## Setup Instructions 🚀

### Step 1: Install Dependencies

First, install the required Python packages:

```bash
pip install -r requirements.txt
```

Or install with `--break-system-packages` if needed:

```bash
pip install -r requirements.txt --break-system-packages
```

### Step 2: Get YouTube OAuth Credentials

You need to create OAuth credentials to access your Watch Later playlist:

1. **Go to Google Cloud Console**
   - Visit: https://console.cloud.google.com/

2. **Create a New Project** (or use existing)
   - Click "Select a project" at the top
   - Click "New Project"
   - Name it something like "YouTube Summarizer"
   - Click "Create"

3. **Enable YouTube Data API v3**
   - In the search bar, type "YouTube Data API v3"
   - Click on it and click "Enable"

4. **Create OAuth Credentials**
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - If prompted, configure the OAuth consent screen:
     - Choose "External" user type
     - Fill in app name (e.g., "YouTube Summarizer")
     - Add your email as developer contact
     - Click "Save and Continue" through the scopes and test users screens
   - Back at "Create OAuth client ID":
     - Application type: "Desktop app"
     - Name: "YouTube Summarizer Desktop"
     - Click "Create"

5. **Download Credentials**
   - Click the download icon (⬇️) next to your newly created OAuth client
   - Save the file as `credentials.json` in the same folder as the script

### Step 3: (Optional) Set Up Claude API for Better Summaries

For AI-powered detailed summaries, you'll need an Anthropic API key:

1. **Get API Key**
   - Visit: https://console.anthropic.com/
   - Sign up or log in
   - Go to "API Keys" and create a new key

2. **Set Environment Variable**

   On Mac/Linux:
   ```bash
   export ANTHROPIC_API_KEY='your-api-key-here'
   ```

   On Windows (Command Prompt):
   ```cmd
   set ANTHROPIC_API_KEY=your-api-key-here
   ```

   On Windows (PowerShell):
   ```powershell
   $env:ANTHROPIC_API_KEY='your-api-key-here'
   ```

   Or add it directly in the script by editing the `ANTHROPIC_API_KEY` variable.

**Note:** Without an API key, the script will still work but will provide basic summaries based on transcript excerpts.

## Usage 🎬

1. **Make sure you have videos in your Watch Later playlist**

2. **Run the script:**
   ```bash
   python youtube_watch_later_summarizer.py
   ```

3. **First-time authentication:**
   - A browser window will open
   - Log in to your Google account
   - Grant permission to access your YouTube data
   - The script will save a `token.json` file for future runs

4. **Wait for processing:**
   - The script will fetch all your Watch Later videos
   - For each video with transcripts, it will generate detailed summaries
   - Progress will be shown in the terminal

5. **Check the output:**
   - A markdown file will be created: `watch_later_summaries_YYYYMMDD_HHMMSS.md`
   - Open it to see your organized summaries!

## Output Format 📄

The generated markdown file includes:

- **Header** with generation date and total video count
- **Table of Contents** with links to each summary
- **Detailed summaries** for each video including:
  - Video title and channel
  - Direct link to watch on YouTube
  - Date added to Watch Later
  - Overview paragraph
  - Key points as bullet points
  - Notable quotes and insights
  - Target audience

## Troubleshooting 🔧

### "credentials.json not found"
- Make sure you downloaded the OAuth credentials from Google Cloud Console
- Place the file in the same directory as the script
- The filename must be exactly `credentials.json`

### "No transcript available"
- Some videos don't have captions/transcripts
- The script will use the video description instead
- Auto-generated captions work fine!

### "Error with Claude API"
- Check that your API key is set correctly
- Verify you have credits remaining in your Anthropic account
- The script will fall back to basic summaries if Claude API fails

### "Too many videos / Script is slow"
- The script processes all videos sequentially
- For large playlists (50+ videos), consider taking a break
- API rate limits: YouTube allows 10,000 units/day (plenty for personal use)

## File Structure 📁

```
youtube_watch_later_summarizer/
├── youtube_watch_later_summarizer.py  # Main script
├── requirements.txt                    # Python dependencies
├── credentials.json                    # OAuth credentials (you create this)
├── token.json                         # Auto-generated after first login
└── watch_later_summaries_*.md         # Generated summary reports
```

## Customization 🎨

### Configuration Options (at top of script)

**Claude API Settings:**
- `CLAUDE_MODEL`: Choose between Opus, Sonnet, or Haiku
- `MAX_TOKENS`: Control summary length (1000-8000)
- `TEMPERATURE`: Adjust creativity (0.0-1.0)
- `MAX_TRANSCRIPT_LENGTH`: Characters sent to Claude

**Processing Options:**
- `CACHE_SUMMARIES`: Enable/disable caching
- `MAX_RETRIES`: Number of retry attempts
- `RETRY_DELAY`: Wait time between retries

### Advanced Customization

- **Change summary structure:** Edit the prompt in `summarize_with_claude()`
- **Limit video count:** Modify `maxResults` in `get_watch_later_videos()`
- **Custom output format:** Modify `generate_markdown_report()` function
- **Add filtering:** Skip videos by channel, length, or date
- **Model selection:** Switch between Claude models for different quality/cost

📖 **For detailed configuration, see `CLAUDE_API_GUIDE.md`**

## Privacy & Security 🔒

- OAuth credentials are stored locally in `token.json`
- Only you have access to your Watch Later playlist
- No data is sent anywhere except to Claude API (optional) for summarization
- YouTube API credentials are for read-only access
- You can revoke access anytime from Google Account settings

## Enhanced Features 🚀

### Smart Caching System
- Summaries are cached to `summary_cache.json`
- Re-running the script is **free** - uses cached summaries
- Edit cache file to manually update summaries
- Share cache with teammates for collaboration

### Cost Management
- Real-time cost tracking per video
- Total cost summary at end of run
- Model comparison: Opus (best quality), Sonnet (balanced), Haiku (fastest)
- Typical costs: $0.01-0.05 per video with Sonnet

### Robust Error Handling
- Automatic retry with exponential backoff
- Rate limit detection and smart waiting
- Fallback to basic summaries on API failure
- Detailed error messages for troubleshooting

### Intelligent Transcript Processing
- Handles videos of any length
- Preserves context from beginning and end for long videos
- Optimizes token usage for cost efficiency

## Tips 💡

1. **Start small**: Test on 2-3 videos before processing entire playlist
2. **Use caching**: Re-run script freely after first run
3. **Choose the right model**: Sonnet for most users, Haiku for budget, Opus for quality
4. **Monitor costs**: Check console output during processing
5. **Archive reports**: Keep track of what you've watched over time
6. **Check transcripts**: Educational and professional videos usually have best results

## License & Credits

Built with:
- Google YouTube Data API v3
- youtube-transcript-api
- Anthropic Claude API
- Python 3.8+

---

Enjoy your summarized Watch Later playlist! 🎉
