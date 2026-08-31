#!/usr/bin/env python3
"""Exhaustive review bundle for the defensive audit.

Builds, from output/claude_bash_runs_all.jsonl:
  output/review_deep_research_cmds.txt - EVERY command (deduped) run by sessions
                                         that invoked deep-research or Workflow
  output/review_last48h_cmds.txt       - EVERY command (deduped) of last 48h
  output/review_targeted_flags.txt     - all-time runs in high-risk categories
  output/review_downloads_vs_exec.txt  - files written by curl/wget + any
                                         command that later executes from those
                                         paths
  output/review_domains_alltime.txt    - every unique host in any command, with counts
"""
import json
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent / "output"
RUNS = [json.loads(l) for l in open(OUT / "claude_bash_runs_all.jsonl")]

# --- sessions that invoked deep-research or Workflow ---------------------
PROJ = Path.home() / ".claude" / "projects"
ids = set()
grep = subprocess.run(
    ["grep", "-l", "-E", r'"skill": ?"deep-research|"name": ?"Workflow"']
    + [str(p) for p in PROJ.glob("*/*.jsonl")],
    capture_output=True, text=True)
for f in grep.stdout.splitlines():
    ids.add(Path(f).stem)

def fmt(r, maxlen=None):
    ts = r["timestamp"][:19].replace("T", " ")
    who = r["session"][:8] + ("/" + r["agent"] if r.get("agent") else "")
    flags = (" FLAGS:" + ",".join(r["flags"])) if r["flags"] else ""
    cmd = r["command"]
    if maxlen and len(cmd) > maxlen:
        cmd = cmd[:maxlen] + f" ...[+{len(cmd)-maxlen} chars]"
    return f"[{ts}Z {r['project'].split('-')[-1]} {who}]{flags}\n  " + \
        cmd.replace("\n", "\n  ")

def dedup(runs):
    seen, out = set(), []
    for r in runs:
        key = (r["timestamp"], r["command"])
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out

dr = dedup([r for r in RUNS if r["session"] in ids])
dr.sort(key=lambda r: r["timestamp"])
with open(OUT / "review_deep_research_cmds.txt", "w") as fh:
    fh.write(f"# EVERY command from deep-research/Workflow sessions: "
             f"{len(dr)} (deduped), {len(ids)} sessions\n\n")
    for r in dr:
        fh.write(fmt(r) + "\n\n")

now = datetime.now(timezone.utc)
cutoff = (now - timedelta(hours=48)).isoformat()
recent = dedup([r for r in RUNS if r["timestamp"] >= cutoff])
recent.sort(key=lambda r: r["timestamp"])
with open(OUT / "review_last48h_cmds.txt", "w") as fh:
    fh.write(f"# EVERY command of last 48h: {len(recent)} (deduped)\n\n")
    for r in recent:
        fh.write(fmt(r) + "\n\n")

HIGH = {"fetch-piped-to-shell", "make-executable", "git-clone", "encoded-exec",
        "raw-net-tool", "outbound-copy", "privilege", "setuid-bit",
        "cron-or-systemd", "ssh-dir", "dd-or-mkfs", "eval-exec",
        "kernel-module", "ld-preload", "shell-rc-write"}
tf = dedup([r for r in RUNS if HIGH & set(r["flags"])])
tf.sort(key=lambda r: (sorted(HIGH & set(r["flags"]))[0], r["timestamp"]))
with open(OUT / "review_targeted_flags.txt", "w") as fh:
    fh.write(f"# All-time runs in high-risk categories: {len(tf)} (deduped)\n\n")
    for r in tf:
        fh.write(fmt(r) + "\n\n")

# --- download -> execution cross-reference -------------------------------
w_rx = re.compile(r"\b(?:curl|wget)\b[^|;&\n]*?(?:-o|--output|-O)\s+(\S+)")
writes = []          # (timestamp, path, run)
for r in RUNS:
    for m in w_rx.finditer(r["command"]):
        p = m.group(1).strip("'\"")
        if p in ("/dev/null", "-"):
            continue
        writes.append((r["timestamp"], p, r))
exec_rx = re.compile(r"(?:^|[|;&]\s*|\b(?:bash|sh|zsh|python3?|node|perl|ruby|source|\.)\s+)(\S+)")
with open(OUT / "review_downloads_vs_exec.txt", "w") as fh:
    fh.write(f"# curl/wget commands that WROTE a file: {len(writes)}\n\n")
    for ts, p, r in sorted(writes, key=lambda w: (w[0], w[1])):
        fh.write(f"{ts}  ->  {p}\n")
    fh.write("\n# Any command referencing a downloaded path in an exec "
             "position (manual review):\n\n")
    paths = {p for _, p, _ in writes}
    basenames = {Path(p).name for p in paths if Path(p).name}
    hits = []
    for r in RUNS:
        for b in basenames:
            if b in r["command"] and w_rx.search(r["command"]) is None:
                hits.append((b, r))
                break
    for b, r in sorted(hits, key=lambda x: x[1]["timestamp"]):
        fh.write(f"### references {b}\n" + fmt(r, 500) + "\n\n")

doms = {}
d_rx = re.compile(r"https?://([a-zA-Z0-9._-]+)")
for r in RUNS:
    for d in d_rx.findall(r["command"]):
        doms[d] = doms.get(d, 0) + 1
with open(OUT / "review_domains_alltime.txt", "w") as fh:
    fh.write("# Every host referenced in any Claude command, all time\n")
    for d in sorted(doms, key=doms.get, reverse=True):
        fh.write(f"{doms[d]:5d}  {d}\n")

print(f"deep-research/workflow sessions : {len(ids)}")
print(f"  their commands (deduped)      : {len(dr)}")
print(f"last-48h commands (deduped)     : {len(recent)}")
print(f"high-risk flagged (all time)    : {len(tf)}")
print(f"download-writes / exec-refs     : {len(writes)} / {len(hits)}")
print(f"unique hosts all time           : {len(doms)}")
