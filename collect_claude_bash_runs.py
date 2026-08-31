#!/usr/bin/env python3
"""Defensive audit: collect every shell command Claude Code ran on this machine.

Reads all session transcripts under ~/.claude/projects/ (including nested
subagent/workflow transcripts), extracts tool_use entries that execute shell
commands, and writes into ./output/:

  claude_bash_runs_all.jsonl   - every run, one JSON object per line
  claude_bash_runs_recent.txt  - human-readable, last N hours (default 48,
                                 override: AUDIT_RECENT_HOURS=168)
  claude_bash_flagged.txt      - runs matching watch patterns (network
                                 downloads, installs, persistence writes,
                                 encoded execution, ...)

Read-only with respect to everything outside its own output directory.
"""

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECTS_DIR = Path.home() / ".claude" / "projects"
OUT_DIR = Path(__file__).resolve().parent / "output"
RECENT_HOURS = int(os.environ.get("AUDIT_RECENT_HOURS", "48"))

# Tools whose invocation means "a shell command ran on this machine".
SHELL_TOOL_EXACT = {"Bash"}
SHELL_TOOL_SUBSTR = ("execute_shell", "shell_command", "run_command")

# Watch patterns: things worth a human look in a defensive review.
WATCH_PATTERNS = [
    ("network-fetch", re.compile(r"\b(curl|wget|aria2c)\b")),
    ("fetch-piped-to-shell", re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(ba|z|da)?sh\b")),
    ("package-install", re.compile(
        r"\b(pip3?\s+install|npm\s+(install|i|add|exec|x)\b|npx\b|pnpm\s+(install|add|dlx)|yarn\s+(add|dlx)|cargo\s+install|gem\s+install|uv\s+(pip\s+install|tool\s+install|add)|uvx\b|dnf\s+install|apt(-get)?\s+install|rpm\s+-i|flatpak\s+install)")),
    ("git-clone", re.compile(r"\bgit\s+clone\b")),
    ("privilege", re.compile(r"\bsudo\b|\bpkexec\b|\bsu\s+-")),
    ("make-executable", re.compile(r"\bchmod\s+(\+x|a\+x|u\+x|7\d\d|\d*[1357]\d\d)")),
    ("setuid-bit", re.compile(r"\bchmod\b[^;|&]*\b([42]\d{3}|u\+s|g\+s)\b")),
    ("shell-rc-write", re.compile(r"(>>?|tee\s+(-a\s+)?)\s*(~|\$HOME|/home/\w+)?/?\.(bashrc|bash_profile|profile|zshrc|zprofile|config/fish)")),
    ("ssh-dir", re.compile(r"\.ssh/")),
    ("cron-or-systemd", re.compile(r"\bcrontab\b|systemctl\s+(--user\s+)?(enable|start|daemon-reload)|/etc/systemd|\.config/systemd")),
    ("autostart", re.compile(r"\.config/autostart|/rw/config")),
    ("encoded-exec", re.compile(
        r"base64\s+(-d|--decode)|\b(base32|base16|basenc|uudecode)\b"
        r"|\bxxd\s+-r|openssl\s+enc\b[^|;&\n]*-d"
        r"|\b(b64decode|bytes\.fromhex|codecs\.decode|marshal\.loads|pickle\.loads)\b"
        r"|Buffer\.from\s*\([^)]*(base64|hex)|\batob\s*\("
        r"|echo\s+[A-Za-z0-9+/=]{40,}")),
    ("decode-piped-to-shell", re.compile(
        r"(base64|base32|basenc|xxd|uudecode|openssl\s+enc)[^|;&\n]*\|\s*(ba|z|da)?sh\b"
        r"|\b(zcat|gunzip)[^|;&\n]*\|\s*(ba|z|da)?sh\b")),
    ("raw-net-tool", re.compile(r"\b(ncat|netcat|socat)\b|(?<![\w./-])nc\s+-|/dev/tcp/")),
    ("eval-exec", re.compile(r"\beval\s+[\"$]|\bexec\s+\d?<")),
    ("delete-recursive", re.compile(r"\brm\s+(-\w*r\w*f|-\w*f\w*r)\b")),
    ("outbound-copy", re.compile(r"\b(scp|rsync)\b[^|;&]*\w+@")),
    ("kernel-module", re.compile(r"\b(insmod|modprobe|rmmod)\b")),
    ("ld-preload", re.compile(r"LD_PRELOAD|ld\.so\.preload")),
    ("dd-or-mkfs", re.compile(r"\bdd\s+if=|\bmkfs\b")),
]


def iso_parse(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def is_shell_tool(name):
    if name in SHELL_TOOL_EXACT:
        return True
    return any(s in name for s in SHELL_TOOL_SUBSTR)


def walk_tool_uses(obj):
    """Yield (tool_name, input_dict) for every tool_use block in a record."""
    if isinstance(obj, dict):
        if obj.get("type") == "tool_use" and isinstance(obj.get("name"), str):
            yield obj["name"], obj.get("input") or {}
        for v in obj.values():
            yield from walk_tool_uses(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_tool_uses(item)


def classify(command):
    return [label for label, rx in WATCH_PATTERNS if rx.search(command)]


def main():
    if not PROJECTS_DIR.is_dir():
        sys.exit(f"No Claude Code transcripts found at {PROJECTS_DIR}")
    OUT_DIR.mkdir(exist_ok=True)
    runs = []
    files_scanned = 0
    parse_errors = 0

    # rglob catches nested subagent/workflow transcripts too — a top-level-only
    # glob misses most of the fan-out agents' commands.
    for jsonl in sorted(PROJECTS_DIR.rglob("*.jsonl")):
        rel = jsonl.relative_to(PROJECTS_DIR)
        project = rel.parts[0]
        session = rel.parts[1]
        if session.endswith(".jsonl"):
            session = session[:-6]
        agent = jsonl.stem if len(rel.parts) > 2 else ""
        files_scanned += 1
        try:
            with open(jsonl, "r", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or '"tool_use"' not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        parse_errors += 1
                        continue
                    ts = rec.get("timestamp") or ""
                    for name, tin in walk_tool_uses(rec):
                        if not is_shell_tool(name):
                            continue
                        cmd = tin.get("command")
                        if not isinstance(cmd, str) or not cmd.strip():
                            continue
                        runs.append({
                            "timestamp": ts,
                            "project": project,
                            "session": session,
                            "agent": agent,
                            "tool": name,
                            "background": bool(tin.get("run_in_background")),
                            "sandbox_disabled": bool(tin.get("dangerouslyDisableSandbox")),
                            "description": tin.get("description") or "",
                            "command": cmd,
                            "flags": classify(cmd),
                        })
        except OSError as e:
            print(f"WARN: cannot read {jsonl}: {e}", file=sys.stderr)

    runs.sort(key=lambda r: r["timestamp"])

    with open(OUT_DIR / "claude_bash_runs_all.jsonl", "w") as fh:
        for r in runs:
            fh.write(json.dumps(r) + "\n")

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=RECENT_HOURS)
    recent = [r for r in runs if (iso_parse(r["timestamp"]) or now) >= cutoff]
    flagged = [r for r in runs if r["flags"]]
    flagged_recent = [r for r in recent if r["flags"]]

    def fmt(r):
        local_ts = ""
        dt = iso_parse(r["timestamp"])
        if dt:
            local_ts = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        head = f"[{local_ts}] project={r['project']} session={r['session'][:8]}"
        if r["agent"]:
            head += f" agent={r['agent'][:16]}"
        if r["flags"]:
            head += "  FLAGS: " + ",".join(r["flags"])
        if r["sandbox_disabled"]:
            head += "  [SANDBOX-DISABLED]"
        return head + "\n    " + r["command"].replace("\n", "\n    ")

    with open(OUT_DIR / "claude_bash_runs_recent.txt", "w") as fh:
        fh.write(f"# Claude shell runs in the last {RECENT_HOURS}h "
                 f"(cutoff {cutoff.astimezone().strftime('%Y-%m-%d %H:%M %Z')})\n"
                 f"# {len(recent)} of {len(runs)} total runs\n\n")
        for r in recent:
            fh.write(fmt(r) + "\n\n")

    with open(OUT_DIR / "claude_bash_flagged.txt", "w") as fh:
        fh.write(f"# All flagged runs (whole history): {len(flagged)}\n"
                 f"# Flagged within last {RECENT_HOURS}h: {len(flagged_recent)}\n\n")
        for r in flagged:
            fh.write(fmt(r) + "\n\n")

    by_day = {}
    for r in runs:
        day = (r["timestamp"] or "unknown")[:10]
        by_day[day] = by_day.get(day, 0) + 1
    flag_counts = {}
    for r in runs:
        for f in r["flags"]:
            flag_counts[f] = flag_counts.get(f, 0) + 1

    print(f"transcript files scanned : {files_scanned}")
    print(f"json parse errors        : {parse_errors}")
    print(f"total shell runs found   : {len(runs)}")
    print(f"runs in last {RECENT_HOURS}h        : {len(recent)}")
    print(f"flagged (all time)       : {len(flagged)}")
    print(f"flagged (last {RECENT_HOURS}h)      : {len(flagged_recent)}")
    print("\nruns per day (last 14 days with activity):")
    for day in sorted(by_day)[-14:]:
        print(f"  {day}: {by_day[day]}")
    print("\nflag counts (all time):")
    for f in sorted(flag_counts, key=flag_counts.get, reverse=True):
        print(f"  {f}: {flag_counts[f]}")
    print(f"\nreports written to {OUT_DIR}/")
    print("NOTE: these outputs contain your full command history — treat them "
          "as sensitive and do not share them.")


if __name__ == "__main__":
    main()
