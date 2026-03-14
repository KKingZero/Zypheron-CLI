#!/bin/bash
# Zypheron Demo Recording Script
# Records an asciinema session showing AutoPent in action.
#
# Prerequisites:
#   pip install asciinema
#   # OR: apt install asciinema
#
# Usage:
#   ./scripts/record_demo.sh [target]
#
# After recording:
#   asciinema upload demo.cast
#   # Copy the URL into README.md
#
# To convert to GIF (optional):
#   pip install agg
#   agg demo.cast demo.gif --cols 120 --rows 35

set -e

TARGET="${1:-10.10.10.1}"
CAST_FILE="demo.cast"

echo "=== Zypheron Demo Recorder ==="
echo "Target: $TARGET"
echo "Output: $CAST_FILE"
echo ""
echo "This will record your terminal session."
echo "Press Ctrl+D or type 'exit' when done."
echo ""

# Check asciinema is installed
if ! command -v asciinema &>/dev/null; then
    echo "ERROR: asciinema not installed."
    echo "Install: pip install asciinema  OR  apt install asciinema"
    exit 1
fi

# Record
asciinema rec "$CAST_FILE" \
    --title "Zypheron AutoPent Demo" \
    --cols 120 \
    --rows 35 \
    --idle-time-limit 3 \
    --command "bash -c '
echo \"$ zypheron autopent $TARGET\"
sleep 1
zypheron autopent $TARGET --save-session
'"

echo ""
echo "Recording saved: $CAST_FILE"
echo ""
echo "Next steps:"
echo "  1. Upload:  asciinema upload $CAST_FILE"
echo "  2. Or GIF:  agg $CAST_FILE demo.gif --cols 120 --rows 35"
echo "  3. Update README.md with the asciinema embed URL"
