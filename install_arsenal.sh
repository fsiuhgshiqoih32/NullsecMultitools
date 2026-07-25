#!/usr/bin/env bash
# FFLOCK arsenal installer — runs inside Arch WSL as root.
# Bootstraps BlackArch, syncs, then installs a curated top-tool set.
LOG=/mnt/c/Users/Konne/security-multitool/install.log
: > "$LOG"
log(){ echo "[FFLOCK $(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

log "starting arsenal install"

# 1) BlackArch repo (idempotent)
if pacman -Sl blackarch >/dev/null 2>&1; then
  log "BlackArch repo already present"
else
  log "bootstrapping BlackArch (strap.sh)"
  cd /tmp
  curl -fsSL https://blackarch.org/strap.sh -o strap.sh >>"$LOG" 2>&1
  chmod +x strap.sh
  ./strap.sh >>"$LOG" 2>&1 && log "strap.sh ok" || log "strap.sh returned non-zero"
fi

# 2) sync + upgrade (correct Arch practice; avoids partial-upgrade breakage)
log "pacman -Syu"
pacman -Syu --noconfirm >>"$LOG" 2>&1 && log "system synced" || log "sync had warnings"

# 3) curated tools, one at a time so a bad name never aborts the batch
PKGS="nmap masscan rustscan amass subfinder dnsenum dnsrecon theharvester recon-ng whatweb wafw00f \
nikto gobuster ffuf feroxbuster wfuzz sqlmap wpscan nuclei dirb commix \
metasploit exploitdb impacket crackmapexec beef routersploit set \
john hashcat hydra medusa ncrack hashid crunch cewl \
wireshark-cli tcpdump bettercap responder socat openbsd-netcat proxychains-ng \
aircrack-ng reaver hcxdumptool \
radare2 gdb binwalk foremost perl-image-exiftool steghide \
seclists wordlists"

OK=0; FAIL=0; FAILED=""
for p in $PKGS; do
  if pacman -S --noconfirm --needed "$p" >>"$LOG" 2>&1; then
    log "installed $p"; OK=$((OK+1))
  else
    log "SKIP $p (not found / failed)"; FAIL=$((FAIL+1)); FAILED="$FAILED $p"
  fi
done

log "DONE: $OK installed, $FAIL skipped"
[ -n "$FAILED" ] && log "skipped:$FAILED"
log "arsenal install complete"
