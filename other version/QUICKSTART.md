# Quick Start Guide 🚀

Get up and running in 5 minutes!

## Fastest Path to Your First Summary

### 1. Install Dependencies (2 minutes)
```bash
pip install -r requirements.txt
```

### 2. Get YouTube Credentials (2 minutes)
1. Go to https://console.cloud.google.com/
2. Create a new project
3. Enable "YouTube Data API v3"
4. Create OAuth credentials (Desktop app)
5. Download as `credentials.json` and put it in this folder

### 3. Run the Script! (1 minute)
```bash
python youtube_watch_later_summarizer.py
```

The first time, you'll log in via your browser. After that, it runs automatically!

---

## What You'll Get (Without Claude API)

Even without setting up the Claude API, you'll still get:
- ✅ List of all your Watch Later videos
- ✅ Video descriptions
- ✅ Transcript previews
- ✅ Organized markdown report

## Want Better Summaries? (Optional)

For AI-powered detailed summaries with bullet points and insights:

1. Get Claude API key: https://console.anthropic.com/
2. Set it:
   ```bash
   export ANTHROPIC_API_KEY='your-key-here'
   ```
3. Run the script again!

---

## Common First-Time Issues

**"Can't find credentials.json"**
→ Make sure the file is in the same folder as the Python script

**"Browser didn't open for login"**
→ Check the terminal for a URL you can copy/paste

**"Some videos have no summary"**
→ Normal! Some videos don't have transcripts. The script will note this.

---

## Next Steps

Once you have your first summary:
- Check the markdown file - it's formatted and ready to read!
- Add more videos to Watch Later and run again
- Customize the script (see README.md for ideas)
- Set up Claude API for even better summaries

Happy summarizing! 📚
