#!/bin/bash
set -eu

ScriptName="UFW-Block-IP"
LogPath="/tmp/${ScriptName}.log"
ARLog="/var/ossec/active-response/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
RunStart=$(date +%s)

WriteLog() {
  local level="$1"
  local message="$2"
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$ts][$level] $message" >&2
  echo "[$ts][$level] $message" >> "$LogPath"
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  local size_kb
  size_kb=$(du -k "$LogPath" | awk '{print $1}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  local i=$((LogKeep - 1))
  while [ $i -ge 0 ]; do
    [ -f "$LogPath.$i" ] && mv -f "$LogPath.$i" "$LogPath.$((i+1))"
    i=$((i - 1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

escape_json() {
  # minimal portable escaper
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

RotateLog
WriteLog "INFO" "=== SCRIPT START : $ScriptName ==="

# Prefer ARG1 from Velociraptor, fallback to positional $1
IP="${ARG1:-${1:-}}"

Status="error"
Reason="No IP provided"

if [ -z "${IP:-}" ]; then
  WriteLog "ERROR" "No IP address provided"
else
  if ! command -v ufw >/dev/null 2>&1; then
    WriteLog "ERROR" "ufw not installed or not in PATH"
    Status="failed"
    Reason="ufw not installed"
  else
    WriteLog "INFO" "Blocking IP address: $IP"
    # Check if already blocked (simple grep on ufw status)
    if ufw status | grep -qw "$IP"; then
      WriteLog "INFO" "IP $IP is already blocked"
      Status="already_blocked"
      Reason="IP already blocked"
    else
      if ufw deny from "$IP" >/dev/null 2>&1; then
        WriteLog "INFO" "Blocked IP $IP successfully"
        Status="blocked"
        Reason="IP blocked successfully"
      else
        WriteLog "ERROR" "Failed to block IP $IP (ufw command failed)"
        Status="failed"
        Reason="ufw command failed"
      fi
    fi
  fi
fi

# Build one-line NDJSON entry
Timestamp=$(date --iso-8601=seconds 2>/dev/null || date -Iseconds)
final_json="{\"timestamp\":\"$Timestamp\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"ip\":\"$(escape_json "$IP")\",\"status\":\"$Status\",\"reason\":\"$(escape_json "$Reason")\",\"copilot_action\":true}"

# Atomic overwrite with .new fallback
tmpfile=$(mktemp)
printf '%s\n' "$final_json" > "$tmpfile"
if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then
  mv -f "$tmpfile" "$ARLog.new"
fi

Duration=$(( $(date +%s) - RunStart ))
WriteLog "INFO" "=== SCRIPT END : duration ${Duration}s ==="
