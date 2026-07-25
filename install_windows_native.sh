#!/usr/bin/env bash
# FFLOCK Windows-native subset — userspace only (no admin needed).
LOG="C:/Users/Konne/security-multitool/install_win.log"
: > "$LOG"
log(){ echo "[FFLOCK-WIN $(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

log "starting windows-native install (pip + cargo)"

# pip userspace tools
for p in sqlmap impacket shodan wafw00f dnspython; do
  log "pip install --user $p"
  pip install --user "$p" >>"$LOG" 2>&1 && log "pip ok: $p" || log "pip FAIL: $p"
done

# cargo tools (compiled, userspace to ~/.cargo/bin)
for c in rustscan feroxbuster; do
  log "cargo install $c (compiles, may take minutes)"
  cargo install "$c" >>"$LOG" 2>&1 && log "cargo ok: $c" || log "cargo FAIL: $c"
done

log "windows-native install complete"
