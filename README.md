# claude-audit-kit

A defensive, read-only audit kit for machines where AI coding agents
(Claude Code and similar) run shell commands. It answers two questions:

1. **What did the agents actually run?** Every shell command from every local
   Claude Code session — including nested subagent and workflow transcripts —
   is extracted, timestamped, and pattern-flagged.
2. **Did anything change that shouldn't have?** A system sweep of persistence
   locations (shell rc files, cron, systemd, autostart, SSH), loader injection
   points, setuid inventory, package integrity, recent executables, listening
   sockets, and more.

**What this is:** an audit/review tool. It reads state and writes reports.

**What this is not:** a hardening tool, an antivirus, or a guarantee. It does
not change, remove, or block anything. A kernel-level compromise could in
principle hide from any in-system userland check.

## Requirements

**Linux:** `python3`, standard coreutils, `ss`, `find`. Package verification
auto-detects Debian (`dpkg`) or Fedora/RHEL (`rpm`). Qubes OS specifics
(`/rw` persistence, dom0 kernel) are handled automatically.

**macOS:** `python3` (comes with the Xcode Command Line Tools). The sweep
uses macOS equivalents automatically: LaunchAgents/LaunchDaemons instead of
systemd/cron.d, `DYLD_INSERT_LIBRARIES` checks instead of `LD_PRELOAD`,
`lsof` for sockets, third-party kext/system-extension listing, SIP and
Gatekeeper status plus `codesign` spot checks instead of package checksums,
and Homebrew/Applications change tracking instead of dpkg/rpm logs.
Grant your terminal **Full Disk Access** (System Settings → Privacy &
Security) first, or some `~/Library` checks silently come back empty.
No sudo is needed on either OS; one optional root-only macOS step
(`sudo sfltool dumpbtm` for login items) is noted in the report instead of
run.

## Usage

```bash
bash audit.sh
```

or run the two parts individually:

```bash
python3 collect_claude_bash_runs.py          # agent command history
bash system_integrity_sweep.sh               # system state sweep
SWEEP_DAYS=7 bash system_integrity_sweep.sh  # wider look-back window
AUDIT_RECENT_HOURS=168 python3 collect_claude_bash_runs.py
```

Everything lands in `./output/`.

## Reading the results

Start with the collector's stdout summary (runs per day, flag counts), then:

- `output/claude_bash_flagged.txt` — commands matching watch patterns
  (network fetches, package installs, chmod +x, encoded data, persistence
  paths, sudo, ...). Read every entry in your time window. Most flags are
  benign development activity; you are looking for commands you can't map to
  work you asked for.
- `output/integrity_sweep.txt` — section by section. The healthy answers:
  no rc-file/systemd/cron changes you didn't make, `/etc/ld.so.preload`
  absent, no deleted-binary processes, package verify clean (modified
  conffiles with *old* mtimes are usually your own past config edits),
  no new setuid files, no PATH shadowing, and every listening socket
  attributable to something you run.

Red flags that warrant deeper investigation: fetch-piped-to-shell to a host
you don't recognize, a downloaded file that later gets executed, writes to
persistence locations during agent sessions, sockets or processes you can't
attribute, package-verify mismatches on *binaries* (not conffiles).

## Optional: exhaustive AI-assisted review

Pattern-matching misses things by design — an injected command doesn't have
to look like a download. `review-guide.md` contains review criteria you can
hand to Claude Code (or any capable agent) to read **every** extracted
command and report anything suspicious. See that file for the workflow.

## Privacy

The reports contain your full agent command history, hostnames, IPs, and
process lists. **Never share the `output/` directory.** Share only the kit
itself. `output/` is gitignored for this reason.
