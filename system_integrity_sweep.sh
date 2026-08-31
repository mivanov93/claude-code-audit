#!/usr/bin/env bash
# Defensive integrity sweep for a workstation where AI coding agents run.
# Read-only: every check only reads system state; all output goes to ./output/.
# Focus: what changed recently in persistent locations, common persistence
# mechanisms, and basic tamper indicators.
#
# Portable: Linux (Debian/Fedora families, Qubes-aware) and macOS.
# Usage:  bash system_integrity_sweep.sh          # 2-day look-back
#         SWEEP_DAYS=7 bash system_integrity_sweep.sh
#
# macOS notes: no sudo needed, but grant your terminal Full Disk Access
# (System Settings > Privacy & Security) or some ~/Library checks come back
# empty. System binaries are SIP-protected, so the sweep checks SIP/Gatekeeper
# status instead of per-package checksums.

set -u
OUT="$(cd "$(dirname "$0")" && pwd)/output"
mkdir -p "$OUT"
R="$OUT/integrity_sweep.txt"
: > "$R"

H="$HOME"
DAYS="${SWEEP_DAYS:-2}"
OS="$(uname -s)"          # Linux | Darwin

# ---- per-OS shims ----------------------------------------------------------
if [ "$OS" = "Darwin" ]; then
  PERM_SUID="+6000"; PERM_EXEC="+111"
  lsl()  { ls -laT "$@"; }
  lslR() { ls -laRT "$@"; }
else
  PERM_SUID="/6000"; PERM_EXEC="/111"
  lsl()  { ls -la --time-style=full-iso "$@"; }
  lslR() { ls -laR --time-style=full-iso "$@"; }
fi

section() { printf '\n===== %s =====\n' "$1" >> "$R"; }
run()     { printf -- '--- %s\n' "$*" >> "$R"; "$@" >> "$R" 2>&1; }

# ---- basics ----------------------------------------------------------------
section "BASICS"
run date
run uname -a
run uptime
if [ "$OS" = "Darwin" ]; then
  run sw_vers
  printf -- '--- SIP status (should be enabled)\n' >> "$R"
  csrutil status >> "$R" 2>&1
  printf -- '--- Gatekeeper status (should be enabled)\n' >> "$R"
  spctl --status >> "$R" 2>&1
else
  if command -v qubesdb-read >/dev/null 2>&1; then
    printf -- '--- qubes vm name\n' >> "$R"; qubesdb-read /name >> "$R" 2>&1
  fi
  printf -- '--- kernel taint value (0 = untainted; 512 = kernel warning, common/benign)\n' >> "$R"
  cat /proc/sys/kernel/tainted >> "$R" 2>&1
fi

# ---- shell startup files ---------------------------------------------------
section "PERSISTENCE FILES: shell startup (content-relevant mtimes)"
RC_FILES="$H/.bashrc $H/.bash_profile $H/.profile $H/.bash_logout
          $H/.zshrc $H/.zprofile $H/.zshenv $H/.zlogin $H/.zlogout"
run lsl $RC_FILES /etc/profile.d /etc/zshrc /etc/zprofile /etc/zshenv
printf -- '--- shell rc files changed in last %s days\n' "$DAYS" >> "$R"
find $RC_FILES /etc/profile.d /etc/bashrc /etc/profile \
     /etc/zshrc /etc/zprofile /etc/zshenv \
     -mtime -"$DAYS" 2>/dev/null >> "$R"
echo "(no output above = none changed in window)" >> "$R"

# ---- Qubes /rw (Linux/Qubes only) -----------------------------------------
if [ "$OS" != "Darwin" ] && [ -d /rw ]; then
  section "PERSISTENCE FILES: Qubes /rw (survives reboot in AppVM)"
  run lslR /rw/config
  for f in /rw/config/rc.local /rw/config/qubes-firewall-user-script; do
    [ -e "$f" ] || continue
    printf '### %s\n' "$f" >> "$R"; cat "$f" >> "$R" 2>&1
  done
  printf -- '--- anything in /rw changed in last %s days (excluding /rw/home)\n' "$DAYS" >> "$R"
  find /rw -xdev -path /rw/home -prune -o -mtime -"$DAYS" -print 2>/dev/null | head -200 >> "$R"
  run lsl /rw/usrlocal/bin /rw/usrlocal/sbin
fi
run lsl /usr/local/bin /usr/local/sbin
[ "$OS" = "Darwin" ] && [ -d /opt/homebrew/bin ] && run ls -la /opt/homebrew/bin | head -40

# ---- scheduled / autostart persistence -------------------------------------
section "PERSISTENCE: autostart, scheduled jobs, background services"
run crontab -l
if [ "$OS" = "Darwin" ]; then
  # launchd is macOS's cron+systemd. Third-party entries are the signal.
  run lsl "$H/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons
  for f in "$H"/Library/LaunchAgents/*.plist; do
    [ -e "$f" ] || continue
    printf '### %s\n' "$f" >> "$R"; cat "$f" >> "$R" 2>&1
  done
  printf -- '--- launchd jobs NOT from Apple (launchctl list)\n' >> "$R"
  launchctl list 2>/dev/null | grep -v 'com\.apple\.' >> "$R"
  printf -- '--- launchd plists changed in last %s days\n' "$DAYS" >> "$R"
  find "$H/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons \
       -type f -mtime -"$DAYS" 2>/dev/null >> "$R"
  echo "(no output above = none changed in window)" >> "$R"
  printf -- '--- periodic scripts\n' >> "$R"
  ls -la /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly >> "$R" 2>&1
  echo "(login items need root to dump: sudo sfltool dumpbtm — optional manual step)" >> "$R"
else
  run lsl "$H/.config/autostart"
  for f in "$H"/.config/autostart/*.desktop; do
    [ -e "$f" ] || continue; printf '### %s\n' "$f" >> "$R"; cat "$f" >> "$R"
  done
  run ls -la /var/spool/cron /etc/cron.d /etc/cron.daily /etc/cron.hourly
  run lslR "$H/.config/systemd"
  run systemctl --user list-timers --all
  run systemctl list-timers --all
  printf -- '--- systemd units (system+user dirs) changed in last %s days\n' "$DAYS" >> "$R"
  find /etc/systemd /usr/lib/systemd/system "$H/.config/systemd" \
       -mtime -"$DAYS" -type f 2>/dev/null >> "$R"
  echo "(no output above = none changed in window)" >> "$R"
fi
command -v atq >/dev/null 2>&1 && run atq

# ---- SSH -------------------------------------------------------------------
section "SSH"
run lsl "$H/.ssh"
for f in "$H/.ssh/authorized_keys" "$H/.ssh/config"; do
  [ -e "$f" ] || continue; printf '### %s\n' "$f" >> "$R"; cat "$f" >> "$R"
done

# ---- loader / library injection points -------------------------------------
section "LOADER / LIBRARY INJECTION POINTS"
if [ "$OS" = "Darwin" ]; then
  printf -- '--- launchctl getenv DYLD_INSERT_LIBRARIES (should be empty)\n' >> "$R"
  v=$(launchctl getenv DYLD_INSERT_LIBRARIES 2>/dev/null)
  if [ -n "$v" ]; then echo "PRESENT: $v" >> "$R"; else echo "empty (good)" >> "$R"; fi
  printf -- '--- DYLD_ variables in your processes (ps eww, own processes only)\n' >> "$R"
  ps axeww 2>/dev/null | grep -o 'DYLD_[A-Z_]*=[^ ]*' | sort | uniq -c >> "$R"
  echo "(no output above = none found)" >> "$R"
  printf -- '--- /etc/launchd.conf (obsolete; should not exist)\n' >> "$R"
  if [ -e /etc/launchd.conf ]; then echo "PRESENT:" >> "$R"; cat /etc/launchd.conf >> "$R"
  else echo "absent (good)" >> "$R"; fi
else
  printf -- '--- /etc/ld.so.preload (should not exist)\n' >> "$R"
  if [ -e /etc/ld.so.preload ]; then
    echo "PRESENT:" >> "$R"; cat /etc/ld.so.preload >> "$R"
  else
    echo "absent (good)" >> "$R"
  fi
  run lsl /etc/ld.so.conf.d
  printf -- '--- LD_PRELOAD/LD_LIBRARY_PATH in readable process environments\n' >> "$R"
  for p in /proc/[0-9]*/environ; do
    { tr '\0' '\n' < "$p" | grep -E '^LD_(PRELOAD|LIBRARY_PATH|AUDIT)=' \
      | sed "s|^|pid $(basename "$(dirname "$p")"): |" >> "$R"; } 2>/dev/null
  done
  echo "(no output above = none found; browser sandbox libs like libmozsandbox.so are normal)" >> "$R"
fi

# ---- processes and network -------------------------------------------------
section "PROCESSES AND NETWORK"
if [ "$OS" = "Darwin" ]; then
  printf -- '--- listening sockets (lsof)\n' >> "$R"
  lsof -i -P -n 2>/dev/null | grep -i LISTEN >> "$R"
  printf -- '--- established connections (lsof)\n' >> "$R"
  lsof -i -P -n 2>/dev/null | grep -i ESTABLISHED >> "$R"
  run ps -axo pid,ppid,user,lstart,etime,command
else
  printf -- '--- processes whose executable was deleted from disk\n' >> "$R"
  for p in /proc/[0-9]*/exe; do
    tgt=$(readlink "$p" 2>/dev/null) || continue
    case "$tgt" in *"(deleted)"*) printf '%s -> %s\n' "$p" "$tgt" >> "$R";; esac
  done
  echo "(no output above = none found)" >> "$R"
  run ss -tulpn
  printf -- '--- established outbound connections\n' >> "$R"
  ss -tpn state established >> "$R" 2>&1
  run ps -eo pid,ppid,user,lstart,etime,cmd --sort=start_time
fi

# ---- kernel extensions -----------------------------------------------------
section "KERNEL / SYSTEM EXTENSIONS"
if [ "$OS" = "Darwin" ]; then
  printf -- '--- third-party kernel extensions (should usually be none on modern macOS)\n' >> "$R"
  kmutil showloaded 2>/dev/null | grep -v 'com\.apple\.' >> "$R"
  echo "(only header or nothing above = none)" >> "$R"
  printf -- '--- system extensions\n' >> "$R"
  systemextensionsctl list >> "$R" 2>&1
else
  run lsmod
  # On Qubes the kernel comes from dom0, so modinfo/package checks don't apply.
  if ! command -v qubesdb-read >/dev/null 2>&1; then
    printf -- '--- modules not owned by any package\n' >> "$R"
    while read -r mod _; do
      [ "$mod" = "Module" ] && continue
      path=$(modinfo -n "$mod" 2>/dev/null) || { echo "no modinfo: $mod" >> "$R"; continue; }
      if [ -f /var/lib/dpkg/status ]; then
        dpkg -S "$path" > /dev/null 2>&1 || echo "NOT OWNED BY A PACKAGE: $mod ($path)" >> "$R"
      else
        rpm -qf "$path" > /dev/null 2>&1 || echo "NOT OWNED BY A PACKAGE: $mod ($path)" >> "$R"
      fi
    done < /proc/modules
    echo "(only header above = all modules owned by packages)" >> "$R"
  fi
fi

# ---- package manager activity ----------------------------------------------
section "PACKAGE MANAGER ACTIVITY"
if [ "$OS" = "Darwin" ]; then
  if command -v brew >/dev/null 2>&1; then
    BP="$(brew --prefix)"
    printf -- '--- Homebrew packages changed in last %s days (Cellar/Caskroom mtimes)\n' "$DAYS" >> "$R"
    find "$BP/Cellar" "$BP/Caskroom" -maxdepth 2 -mtime -"$DAYS" 2>/dev/null >> "$R"
    echo "(no output above = no brew changes in window)" >> "$R"
  else
    echo "homebrew not installed" >> "$R"
  fi
  printf -- '--- /Applications changed in last %s days\n' "$DAYS" >> "$R"
  find /Applications "$H/Applications" -maxdepth 1 -mtime -"$DAYS" 2>/dev/null >> "$R"
  echo "(no output above = none)" >> "$R"
  printf -- '--- installer package receipts (pkgutil sample; not time-ordered)\n' >> "$R"
  pkgutil --pkgs 2>/dev/null | tail -15 >> "$R"
elif [ -f /var/lib/dpkg/status ]; then
  printf -- '--- dpkg installs/upgrades in last %s days (from /var/log/dpkg.log*)\n' "$DAYS" >> "$R"
  since=$(date -d "-$DAYS days" +%Y-%m-%d)
  cat /var/log/dpkg.log.1 /var/log/dpkg.log 2>/dev/null \
    | awk -v s="$since" '$1 >= s && ($3 == "install" || $3 == "upgrade")' >> "$R"
  echo "(no output above = no dpkg installs in window)" >> "$R"
  printf -- '--- apt history (tail)\n' >> "$R"
  tail -30 /var/log/apt/history.log 2>/dev/null >> "$R"
else
  printf -- '--- dnf history (last 15 transactions)\n' >> "$R"
  dnf history list 2>/dev/null | head -20 >> "$R"
  printf -- '--- rpm packages installed in last %s days\n' "$DAYS" >> "$R"
  rpm -qa --qf '%{INSTALLTIME:date} %{NAME}-%{VERSION}\n' 2>/dev/null \
    | while read -r line; do
        d=$(date -d "$(echo "$line" | cut -d' ' -f1-6)" +%s 2>/dev/null) || continue
        now=$(date +%s)
        if [ $(( (now - d) / 86400 )) -lt "$DAYS" ]; then echo "$line"; fi
      done >> "$R"
  echo "(no output above = no rpm installs in window)" >> "$R"
fi

# ---- core binary integrity -------------------------------------------------
section "CORE BINARY INTEGRITY"
if [ "$OS" = "Darwin" ]; then
  # SIP covers /bin,/usr/bin etc.; verify code signatures as a spot check.
  for b in /bin/bash /bin/zsh /usr/bin/ssh /usr/bin/curl /usr/bin/sudo; do
    printf '### codesign -v %s\n' "$b" >> "$R"
    if codesign -v "$b" 2>>"$R"; then echo "valid" >> "$R"; fi
  done
  echo "(SIP status in BASICS section protects these paths when enabled)" >> "$R"
elif [ -f /var/lib/dpkg/status ]; then
  for pkg in bash coreutils login passwd sudo openssh-client curl wget \
             procps iproute2 systemd libc6; do
    printf '### dpkg --verify %s\n' "$pkg" >> "$R"
    out=$(dpkg --verify "$pkg" 2>&1)
    if [ -z "$out" ]; then echo "clean" >> "$R"; else echo "$out" >> "$R"; fi
  done
  echo "(lines starting ??5 are modified conffiles — check their mtimes; binaries should be clean)" >> "$R"
else
  for pkg in bash coreutils util-linux procps-ng iproute openssh-clients \
             systemd glibc sudo curl wget; do
    printf '### rpm -V %s\n' "$pkg" >> "$R"
    out=$(rpm -V "$pkg" 2>&1)
    if [ -z "$out" ]; then echo "clean" >> "$R"; else echo "$out" >> "$R"; fi
  done
fi

# ---- setuid ----------------------------------------------------------------
section "SETUID/SETGID FILES (and any changed recently)"
SUID_DIRS="/usr /bin /sbin /rw /home /usr/local /opt/homebrew"
printf -- '--- all setuid/setgid files\n' >> "$R"
find $SUID_DIRS -xdev -type f -perm "$PERM_SUID" 2>/dev/null | sort -u >> "$R"
printf -- '--- setuid/setgid files modified in last %s days\n' "$DAYS" >> "$R"
find $SUID_DIRS -xdev -type f -perm "$PERM_SUID" -mtime -"$DAYS" 2>/dev/null | sort -u >> "$R"
echo "(no output above = none changed in window)" >> "$R"

# ---- recent executables in home --------------------------------------------
section "RECENTLY CREATED/MODIFIED EXECUTABLES in persistent areas"
printf -- '--- executables in %s modified in last %s days (excl. big dep dirs)\n' "$H" "$DAYS" >> "$R"
find "$H" -xdev -type f -perm "$PERM_EXEC" -mtime -"$DAYS" \
     -not -path '*/node_modules/*' -not -path '*/.git/*' \
     -not -path '*/.cache/*' -not -path '*/venv/*' -not -path '*/.venv/*' \
     -not -path '*/Library/Caches/*' \
     2>/dev/null | sort >> "$R"
printf -- '--- COUNT of new executables inside dep/cache dirs\n' >> "$R"
find "$H" -xdev -type f -perm "$PERM_EXEC" -mtime -"$DAYS" \
     \( -path '*/node_modules/*' -o -path '*/.cache/*' -o -path '*/venv/*' \
        -o -path '*/.venv/*' -o -path '*/Library/Caches/*' \) \
     2>/dev/null | wc -l >> "$R"
printf -- '--- %s/.local/bin %s/bin full listing\n' "$H" "$H" >> "$R"
lsl "$H/.local/bin" "$H/bin" >> "$R" 2>&1

# ---- PATH shadowing --------------------------------------------------------
section "PATH SHADOWING CHECK"
printf -- '--- PATH\n%s\n' "$PATH" >> "$R"
printf -- '--- common commands resolving outside /usr/bin:/bin (possible shadowing)\n' >> "$R"
for c in ls cat sudo ssh curl wget git python3 bash sh; do
  w=$(command -v "$c" 2>/dev/null)
  case "$w" in /usr/bin/*|/bin/*) ;; *) echo "SHADOWED: $c -> $w" >> "$R";; esac
done
if [ "$OS" = "Darwin" ]; then
  echo "(on macOS, /opt/homebrew/bin or /usr/local/bin entries are usually intentional Homebrew installs — verify they are yours)" >> "$R"
else
  echo "(no output above = no shadowing)" >> "$R"
fi

# ---- downloads and temp ----------------------------------------------------
section "DOWNLOADS AND TEMP AREAS (last $DAYS days)"
run lsl "$H/Downloads"
find "$H/Downloads" "$H/QubesIncoming" -xdev -mtime -"$DAYS" -type f 2>/dev/null >> "$R"
printf -- '--- temp areas: files changed in window (first 100)\n' >> "$R"
find /tmp /var/tmp /dev/shm /private/tmp -xdev -mtime -"$DAYS" -type f 2>/dev/null | head -100 >> "$R"

# ---- hidden files in home --------------------------------------------------
section "HIDDEN FILES/DIRS created recently in home (top-level scan)"
find "$H" -xdev -maxdepth 2 -name '.*' -mtime -"$DAYS" 2>/dev/null \
  -not -path "$H/.cache*" -not -path "$H/.claude*" \
  -not -path "$H/Library*" | sort >> "$R"
echo "(excludes .cache and .claude which churn constantly)" >> "$R"

# ---- immutable flags -------------------------------------------------------
section "IMMUTABLE-FLAG FILES in /etc (rare; used to lock files against change)"
if [ "$OS" = "Darwin" ]; then
  ls -laO /etc 2>/dev/null | grep -E 'uchg|schg' | head -20 >> "$R"
else
  lsattr -R /etc 2>/dev/null | grep -E '^\S*i\S* ' | head -20 >> "$R"
fi
echo "(no output above = none)" >> "$R"

echo "Sweep complete. Report: $R"
echo "NOTE: the report contains hostnames, IPs, and process lists — treat it as sensitive."
wc -l "$R"
