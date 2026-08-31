#!/usr/bin/env bash
# Run the full read-only audit: agent command history + system sweep.
set -u
cd "$(dirname "$0")"
echo "=== 1/2: extracting Claude agent shell history ==="
python3 collect_claude_bash_runs.py
echo
echo "=== 2/2: system integrity sweep (read-only) ==="
bash system_integrity_sweep.sh
echo
echo "Done. Review output/claude_bash_flagged.txt and output/integrity_sweep.txt."
echo "For an exhaustive AI-assisted pass over every command, see review-guide.md."
