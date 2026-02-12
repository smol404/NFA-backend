#!/bin/bash
# Bot startup script with correct architecture

echo "🚀 Starting Telegram Echo BSC bot..."

# Use python3 (native architecture)
if command -v python3 &> /dev/null; then
    python3 main.py
else
    echo "❌ Python3 not found. Please install Python 3."
    exit 1
fi
