#!/bin/bash
set -eu

ScriptName="Block-IP"
LogPath="/tmp/${ScriptName}.log"
ARLog="/var/ossec/active-response/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
RunStart=$(date +%s)

# Prefer ARG1 from Velociraptor, fallback to $1
IP="${ARG1:-${1:-}}"

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
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName ==="



Status="error"
Reason="No IP provided"

if [ -z "${IP:-}" ]; then
  WriteLog "ERROR" "No IP address provided, exiting."
else
  WriteLog "INFO" "Blocking IP address: $IP"
  if ufw status | grep -qw "$IP"; then
    WriteLog "INFO" "IP $IP is already blocked"
    Status="already_blocked"
    Reason="IP was already blocked"
  else
    if ufw deny from "$IP"; then
      WriteLog "INFO" "Blocked IP $IP successfully"
      Status="blocked"
      Reason="IP blocked successfully"
    else
      WriteLog "ERROR" "Failed to block IP $IP"
      Status="failed"
      Reason="ufw command failed"
    fi
  fi
fi

# Build NDJSON entry
Timestamp=$(date --iso-8601=seconds 2>/dev/null || date -Iseconds)
final_json="{\"timestamp\":\"$Timestamp\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"ip\":\"$(escape_json "$IP")\",\"status\":\"$Status\",\"reason\":\"$(escape_json "$Reason")\",\"copilot_action\":true}"

# Atomic write: overwrite ARLog or fallback to ARLog.new
tmpfile=$(mktemp)
printf '%s\n' "$final_json" > "$tmpfile"
if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then
  mv -f "$tmpfile" "$ARLog.new"
fi

Duration=$(( $(date +%s) - RunStart ))
WriteLog "=== SCRIPT END : duration ${Duration}s ==="
