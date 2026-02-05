# 🚀 Quick Start Guide

Get started with YouTube Summarizer in 5 minutes!

## Files Included

```
youtube-summarizer/
├── youtube_summarizer_enhanced.py  # Main script (18KB)
├── cli.py                          # Command-line interface (4.4KB)
├── extract_urls.py                 # URL extraction utility (6.4KB)
├── setup.sh                        # Setup automation script (1.9KB)
├── requirements.txt                # Python dependencies
├── config_template.py              # Configuration template
├── watch_later_example.txt         # Example URL file
├── README.md                       # Full documentation (7.1KB)
└── CYBERSECURITY_WORKFLOW.md       # Security-specific guide (9.4KB)
```

## Installation (60 seconds)

```bash
# 1. Install dependencies
pip install youtube-transcript-api anthropic

# 2. Set API key
export ANTHROPIC_API_KEY="your-api-key-here"

# 3. Edit config and set your vault path
# Edit line 16 in youtube_summarizer_enhanced.py:
VAULT_PATH = "/Users/stanley/ObsidianVault"  # ← Change this
```

## Usage (Pick One)

### Option 1: Single Video (Fastest)
```bash
python cli.py -u "https://www.youtube.com/watch?v=VIDEO_ID"
```

### Option 2: Multiple Videos from File
```bash
# Create a text file with URLs (one per line)
cat > my_videos.txt << EOF
https://www.youtube.com/watch?v=VIDEO_1
https://www.youtube.com/watch?v=VIDEO_2
EOF

# Process them
python cli.py -f my_videos.txt
```

### Option 3: Interactive Mode
```bash
python cli.py -i
# Then paste URLs one at a time
```

## What It Does

For each video, creates an Obsidian note with:
- ✅ Full transcript with timestamps
- ✅ AI-generated summary (2-3 paragraphs)
- ✅ 5-7 key points/takeaways
- ✅ Smart tags for organization
- ✅ Video metadata (channel, URL, etc.)

Plus:
- 📊 Weekly dashboards grouped by tags and channels
- 🔗 Automatic wiki-linking in Obsidian
- 🗂️ Clean folder organization

## Example Output

```markdown
# Advanced Malware Analysis Techniques

## Metadata
- **Video ID:** abc123xyz
- **URL:** https://youtube.com/watch?v=abc123xyz
- **Channel:** [[DEFCONConference]]
- **Created:** 2024-12-23
- **Tags:** #youtube #malware #defcon #analysis

## Summary
This DefCon talk covers advanced techniques for analyzing modern
malware including static and dynamic analysis approaches. The
speaker demonstrates practical examples using IDA Pro and
custom Python scripts...

## Key Points
- Use IDA Pro for static analysis of obfuscated code
- Implement dynamic analysis in isolated sandbox environments
- Develop YARA rules for malware detection
- Common anti-VM techniques and their bypasses
- Automate analysis workflows with Python scripting

## Transcript
[00:45] Today I'll show you advanced techniques for...
[02:15] First, let's start with static analysis using IDA...
[05:30] Now moving to dynamic analysis, we'll use...
```

## Getting Your Watch Later URLs

**Easiest method:**
```bash
# 1. Go to https://www.youtube.com/playlist?list=WL
# 2. Open browser console (F12)
# 3. Paste this code:

copy(Array.from(document.querySelectorAll('a#video-title'))
  .map(a => a.href)
  .filter(url => url.includes('watch?v='))
  .join('\n'));

# 4. URLs are now in your clipboard!
# 5. Paste into a text file
```

Full instructions: `python extract_urls.py --instructions`

## Vault Structure

After processing, your Obsidian vault will have:

```
ObsidianVault/
├── YouTube Notes/
│   ├── Advanced Malware Analysis Techniques.md
│   ├── CrowdStrike Falcon Tutorial.md
│   └── YARA Rule Development.md
└── Dashboards/
    └── Week_2024-12-23.md
```

## For Cybersecurity Research

Perfect for:
- 🎯 **Conference talks** (DefCon, Black Hat, BSides)
- 🔍 **Malware analysis** walkthroughs
- 🛡️ **Tool tutorials** (CrowdStrike, Splunk, SIEM)
- 📚 **Training content** (SANS, Offensive Security)
- 💼 **Interview prep** (SOC analyst workflows)

See `CYBERSECURITY_WORKFLOW.md` for detailed examples!

## Troubleshooting

**No transcript available?**
- Some videos disable transcripts
- Script creates basic note with metadata only

**API errors?**
- Check your ANTHROPIC_API_KEY is set
- Verify API key is valid at console.anthropic.com

**Module not found?**
- Run: `pip install -r requirements.txt`

**Permission denied?**
- Check vault path exists and is writable
- Update VAULT_PATH in config

## Next Steps

1. ✅ Process a test video
2. ✅ Open the note in Obsidian
3. ✅ Process your Watch Later playlist
4. ✅ Generate weekly dashboard
5. ✅ Start cross-linking with your research

## Links

- Full docs: `README.md`
- Security workflow: `CYBERSECURITY_WORKFLOW.md`
- Get help: `python cli.py -h`

---

**You're ready to go! Start with one video to test it out.**

```bash
python cli.py -u "https://www.youtube.com/watch?v=YOUR_VIDEO_HERE"
```

Then check `ObsidianVault/YouTube Notes/` for your new note! 🎉
