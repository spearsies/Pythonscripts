# Claude API Configuration Guide 🤖

This guide covers everything you need to know about using Claude API with the YouTube summarizer.

## Why Use Claude API?

The Claude API provides **significantly better summaries** compared to basic text extraction:

- ✅ **Detailed Analysis**: Comprehensive breakdown with key points, insights, and practical applications
- ✅ **Structured Format**: Organized sections with clear headers and bullet points
- ✅ **Context Understanding**: Claude understands the video content and extracts meaningful insights
- ✅ **Actionable Insights**: Identifies who should watch and how to apply the knowledge
- ✅ **Quality Consistency**: Professional summaries across all video types

## Getting Your API Key

### Step 1: Create an Anthropic Account

1. Visit: https://console.anthropic.com/
2. Sign up with your email or Google account
3. Verify your email address

### Step 2: Add Credits

1. Go to "Settings" → "Billing"
2. Add credits to your account ($5 minimum)
3. For reference: $5 can summarize ~100-200 videos depending on length

### Step 3: Create an API Key

1. Navigate to "API Keys" in the console
2. Click "Create Key"
3. Give it a name (e.g., "YouTube Summarizer")
4. Copy the key immediately (you won't see it again!)

### Step 4: Set Environment Variable

**On Mac/Linux:**
```bash
export ANTHROPIC_API_KEY='sk-ant-...'
```

To make it permanent, add to your `~/.bashrc` or `~/.zshrc`:
```bash
echo 'export ANTHROPIC_API_KEY="sk-ant-..."' >> ~/.bashrc
source ~/.bashrc
```

**On Windows (PowerShell):**
```powershell
$env:ANTHROPIC_API_KEY='sk-ant-...'
```

To make it permanent:
```powershell
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_API_KEY', 'sk-ant-...', 'User')
```

**On Windows (Command Prompt):**
```cmd
set ANTHROPIC_API_KEY=sk-ant-...
```

### Alternative: Set in Script

Edit `youtube_watch_later_summarizer.py` and replace line 32:
```python
ANTHROPIC_API_KEY = 'sk-ant-your-key-here'
```

⚠️ **Security Note**: Don't commit API keys to Git repositories!

## Model Selection

The script supports three Claude models. Edit line 33 in the script to change:

### Sonnet 4.5 (Default - Recommended)
```python
CLAUDE_MODEL = 'claude-sonnet-4-5-20250929'
```
- **Best balance** of quality, speed, and cost
- **Cost**: ~$0.03 per 1M input tokens, ~$0.15 per 1M output tokens
- **Best for**: Most users - excellent quality at reasonable cost
- **Typical video**: ~$0.01-0.05 per summary

### Opus 4.5 (Highest Quality)
```python
CLAUDE_MODEL = 'claude-opus-4-5-20251101'
```
- **Highest quality** and deepest analysis
- **Cost**: ~$15 per 1M input tokens, ~$75 per 1M output tokens
- **Best for**: When you need the absolute best analysis for important videos
- **Typical video**: ~$0.05-0.20 per summary

### Haiku 4.5 (Fastest & Cheapest)
```python
CLAUDE_MODEL = 'claude-haiku-4-5-20251001'
```
- **Fastest** responses and lowest cost
- **Cost**: ~$0.80 per 1M input tokens, ~$4 per 1M output tokens
- **Best for**: Quick summaries of many videos when cost is a concern
- **Typical video**: ~$0.005-0.02 per summary

## Configuration Options

All configuration is at the top of `youtube_watch_later_summarizer.py`:

### Summary Length
```python
MAX_TOKENS = 2000  # Increase for longer summaries (max ~8000)
```

### Creativity vs Focus
```python
TEMPERATURE = 1.0  # 0.0 = very focused, 1.0 = more creative
```
- **0.0-0.3**: Consistent, factual summaries
- **0.4-0.7**: Balanced approach
- **0.8-1.0**: More varied language and perspectives

### Transcript Processing
```python
MAX_TRANSCRIPT_LENGTH = 50000  # chars to send to Claude
```
- Longer = better context but higher cost
- Script intelligently truncates (keeps beginning and end)

### Caching
```python
CACHE_SUMMARIES = True  # Save summaries to avoid re-processing
```
- Saves summaries to `summary_cache.json`
- Re-running script uses cached summaries (no API calls!)
- Perfect for iterating on output format

### Retry Logic
```python
MAX_RETRIES = 3           # Attempts before giving up
RETRY_DELAY = 2           # Initial wait (seconds)
BACKOFF_MULTIPLIER = 2    # Exponential backoff
```

## Cost Management

### Estimate Costs Before Running

For a rough estimate:
- **Short videos** (5-10 min): ~$0.01-0.02 per summary with Sonnet
- **Medium videos** (15-30 min): ~$0.02-0.04 per summary with Sonnet
- **Long videos** (45+ min): ~$0.04-0.08 per summary with Sonnet

**Example**: 50 medium videos ≈ $1.50-2.00 with Sonnet

### Monitor Costs While Running

The script shows cost per video in real-time:
```
[5/50] Processing: How to Build AI Apps...
  ✓ Transcript found (8234 words)
  🤖 Generating AI summary...
  💰 Tokens: 12,450 in, 1,876 out ($0.0561)
```

At the end, you'll see total statistics:
```
📈 Processing Statistics:
   Total videos: 50
   Cache hits: 12
   New summaries: 38
   Total cost: $1.8234
   Avg cost per video: $0.048
```

### Cost Saving Tips

1. **Use caching**: Run script multiple times without reprocessing
2. **Start with Haiku**: Test on a few videos first
3. **Limit videos**: Edit script to process only recent additions
4. **Adjust MAX_TOKENS**: Reduce to 1000-1500 for shorter summaries
5. **Truncate transcripts**: Reduce MAX_TRANSCRIPT_LENGTH to 30000

## Advanced Features

### Enhanced Prompts

The script uses a carefully crafted prompt that asks Claude for:
- Overview (2-3 sentences)
- Key points (5-8 bullet points)
- Notable quotes and insights
- Target audience
- Practical applications

### Intelligent Retry Logic

If API calls fail:
1. **Rate limits**: Automatically waits and retries with exponential backoff
2. **Connection errors**: Retries up to 3 times
3. **API errors**: Falls back to basic summaries
4. **No API key**: Uses basic text extraction

### Smart Transcript Handling

For very long videos:
- Keeps first 25,000 and last 25,000 characters
- Preserves context from beginning and end
- Adds clear marker for truncated section

### Cache Management

The `summary_cache.json` file stores:
```json
{
  "video_id_123": "**Overview:** This video discusses...",
  "video_id_456": "**Overview:** In this tutorial..."
}
```

Benefits:
- ✅ Free to re-run script
- ✅ Preserve summaries even if you change models
- ✅ Manually edit summaries and keep edits
- ✅ Share cache file with teammates

To force re-summarization: Delete `summary_cache.json`

## Troubleshooting

### "Error: Invalid API key"
- Verify key starts with `sk-ant-`
- Check for extra spaces or quotes
- Confirm key in environment: `echo $ANTHROPIC_API_KEY`

### "RateLimitError"
- Script automatically retries with backoff
- If persistent, you may have exceeded account limits
- Check usage in Anthropic console

### "Summaries are too short"
- Increase `MAX_TOKENS` from 2000 to 3000-4000
- Ensure video has good transcripts
- Try Opus model for more detailed analysis

### "Costs are too high"
- Switch to Haiku model
- Reduce MAX_TRANSCRIPT_LENGTH
- Enable caching to avoid reprocessing
- Process fewer videos per run

### "Connection timeout"
- Script retries automatically
- Check internet connection
- Increase RETRY_DELAY if on slow connection

## Comparison: With vs Without Claude API

### Without Claude API
```markdown
**Overview:** Welcome to this video. Today I'm going to show you how
to build a machine learning model. We'll start with data preprocessing.
Then we'll train the model. Finally we'll evaluate results.

**Video Stats:**
- Estimated duration: ~45 minutes
- Transcript length: 6,234 words
```

### With Claude API (Sonnet)
```markdown
**Overview:** This comprehensive tutorial walks through building a
production-ready machine learning model, covering data preprocessing,
feature engineering, model selection, and deployment considerations.
The instructor emphasizes practical, real-world approaches that address
common pitfalls in ML projects.

**Key Points:**
- Data quality matters more than model complexity - spend 70% of time
  on preprocessing and validation
- Feature engineering techniques: handling missing values, encoding
  categorical variables, and creating interaction terms
- Model selection involves trade-offs between interpretability and
  accuracy
- Cross-validation prevents overfitting and gives realistic performance
  estimates
- Hyperparameter tuning with grid search or Bayesian optimization
- Model evaluation should use business metrics, not just technical ones
- Deployment requires monitoring, versioning, and rollback strategies
- Common mistakes: data leakage, ignoring class imbalance, over-tuning
  on validation set

**Notable Quotes:**
- "A simple model that you understand beats a complex model you don't"
- "Your model is only as good as your data pipeline"

**Who Should Watch:**
- Data scientists learning ML model development
- Engineers transitioning into ML roles
- Anyone building production ML systems
- Students wanting practical ML implementation experience

**Practical Applications:**
- Building your first ML project from scratch
- Debugging model performance issues
- Setting up ML pipelines in production
- Creating reproducible ML experiments
```

## Best Practices

1. **Test First**: Run on 2-3 videos before processing entire playlist
2. **Use Caching**: Always keep `CACHE_SUMMARIES = True`
3. **Start with Sonnet**: Best quality/cost ratio for most users
4. **Monitor Costs**: Check console output and Anthropic dashboard
5. **Version Control**: Keep copies of cache files for different runs
6. **Backup Output**: Save markdown reports before re-running

## Getting Help

- **API Issues**: Check Anthropic's status page and documentation
- **Rate Limits**: Contact Anthropic support to increase limits
- **Cost Questions**: Review usage in Anthropic console
- **Script Issues**: Check the error messages - they're designed to be helpful!

---

Happy summarizing with Claude! 🎉
