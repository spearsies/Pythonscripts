# YouTube Summarizer Configuration
# Copy this to config.py and customize for your setup

import os

# Obsidian Vault Settings
VAULT_PATH = os.path.expanduser("~/ObsidianVault")  # Update this path
VIDEOS_FOLDER = "YouTube Notes"
CHANNELS_FOLDER = "Channels"
DASHBOARD_FOLDER = "Dashboards"

# API Keys (Set as environment variables for security)
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# Summary Settings
SUMMARY_MODEL = "claude-sonnet-4-20250514"
MAX_TRANSCRIPT_LENGTH = 8000  # Characters to send for summary
MAX_TOKENS = 2000  # Max tokens for summary response

# Transcript Settings
PREFERRED_LANGUAGES = ['en', 'en-US', 'en-GB']
FALLBACK_LANGUAGES = ['auto']

# Dashboard Settings
WEEKLY_LOOKBACK_DAYS = 7
DEFAULT_TAG = "#youtube"

# Note Template Settings
INCLUDE_TIMESTAMPS = True
INCLUDE_FULL_TRANSCRIPT = True
CREATE_CHANNEL_LINKS = True

# File Naming
MAX_FILENAME_LENGTH = 200
SANITIZE_FILENAMES = True

# Batch Processing
BATCH_SIZE = 10  # Process this many videos before pausing
PAUSE_BETWEEN_BATCHES = 5  # Seconds to pause between batches
