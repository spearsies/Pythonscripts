#!/bin/bash

# YouTube Summarizer Setup Script
# Run this to get started quickly

set -e

echo "================================"
echo "YouTube Summarizer Setup"
echo "================================"
echo ""

# Check Python version
echo "Checking Python version..."
python3 --version || { echo "Error: Python 3 not found. Please install Python 3.8+"; exit 1; }
echo "✓ Python 3 found"
echo ""

# Check if pip is installed
echo "Checking pip..."
python3 -m pip --version || { echo "Error: pip not found. Please install pip"; exit 1; }
echo "✓ pip found"
echo ""

# Install dependencies
echo "Installing dependencies..."
pip3 install -r requirements.txt
echo "✓ Dependencies installed"
echo ""

# Check for API key
echo "Checking for Anthropic API key..."
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "⚠ Warning: ANTHROPIC_API_KEY environment variable not set"
    echo ""
    echo "To set it:"
    echo "  export ANTHROPIC_API_KEY='your-api-key-here'"
    echo ""
    echo "Or create a .env file:"
    echo "  echo 'ANTHROPIC_API_KEY=your-api-key-here' > .env"
    echo ""
else
    echo "✓ ANTHROPIC_API_KEY is set"
fi
echo ""

# Create config if it doesn't exist
if [ ! -f "config.py" ]; then
    echo "Creating config.py from template..."
    cp config_template.py config.py
    echo "✓ Created config.py"
    echo "⚠ Please edit config.py to set your Obsidian vault path"
else
    echo "✓ config.py already exists"
fi
echo ""

# Make scripts executable
chmod +x cli.py
echo "✓ Made scripts executable"
echo ""

echo "================================"
echo "Setup Complete!"
echo "================================"
echo ""
echo "Next steps:"
echo "1. Edit config.py and set your VAULT_PATH"
echo "2. Set your ANTHROPIC_API_KEY environment variable"
echo "3. Run: python3 cli.py -i (for interactive mode)"
echo "   Or: python3 cli.py -f watch_later.txt"
echo ""
echo "For help: python3 cli.py -h"
echo ""
