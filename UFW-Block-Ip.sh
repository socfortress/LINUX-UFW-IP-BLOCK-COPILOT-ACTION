#!/bin/bash
set -eu

ScriptName="UFW-Block-IP"
LogPath="/tmp/${ScriptName}.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
RunStart="$(date +%s)"
IP="${ARG1:-${1:-}}"

WriteLog() {
  local msg="$1" lvl="${2:-INFO}"
  local ts; ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  local line="[$ts][$lvl] $msg"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >> "$LogPath" 2>/dev/null || true
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  local size_kb; size_kb=$(awk -v s="$(wc -c <"$LogPath")" 'BEGIN{printf "%.0f", s/1024}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  local i=$((LogKeep-1))
  while [ $i -ge 1 ]; do
    local src="$LogPath.$i" dst="$LogPath.$((i+1))"
    [ -f "$src" ] && mv -f "$src" "$dst" || true
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

iso_now(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
escape_json(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
am_root(){ [ "$(id -u)" -eq 0 ]; }
maybe_sudo(){ if am_root; then "$@"; elif command -v sudo >/dev/null 2>&1; then sudo "$@"; else "$@"; fi; }

BeginNDJSON(){ TMP_AR="$(mktemp)"; }

AddRecord(){
  local ts="$(iso_now)"
  local ip="$(escape_json "${1:-}")"
  local status="$(escape_json "${2:-}")"
  local reason="$(escape_json "${3:-}")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"ip":"%s","status":"%s","reason":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$ip" "$status" "$reason" >> "$TMP_AR"
}

AddStatus(){
  local ts; ts="$(iso_now)"
  local st="${1:-info}" msg="$(escape_json "${2:-}")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"%s","message":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$st" "$msg" >> "$TMP_AR"
}

CommitNDJSON(){
  local ar_dir; ar_dir="$(dirname "$ARLog")"
  [ -d "$ar_dir" ] || WriteLog "Directory missing: $ar_dir (will attempt write anyway)" WARN
  if mv -f "$TMP_AR" "$ARLog" 2>/dev/null; then
    :
  else
    WriteLog "Primary write FAILED to $ARLog" WARN
    if mv -f "$TMP_AR" "$ARLog.new" 2>/dev/null; then
      WriteLog "Wrote NDJSON to $ARLog.new (fallback)" WARN
    else
      local keep="/tmp/active-responses.$$.ndjson"
      cp -f "$TMP_AR" "$keep" 2>/dev/null || true
      WriteLog "Failed to write both $ARLog and $ARLog.new; saved $keep" ERROR
      rm -f "$TMP_AR" 2>/dev/null || true
      exit 1
    fi
  fi
  for p in "$ARLog" "$ARLog.new"; do
    if [ -f "$p" ]; then
      local sz ino head1
      sz=$(wc -c < "$p" 2>/dev/null || echo 0)
      ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}')
      head1=$(head -n1 "$p" 2>/dev/null || true)
      WriteLog "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}" INFO
    fi
  done
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName (host=$HostName) ==="

if [ -z "${IP:-}" ]; then
  BeginNDJSON; AddStatus "error" "No IP address provided (ARG1 or \$1)"; CommitNDJSON; exit 1
fi
if ! printf '%s' "$IP" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
  BeginNDJSON; AddRecord "$IP" "error" "Invalid IPv4 address format"; CommitNDJSON; exit 1
fi
if ! command -v ufw >/dev/null 2>&1; then
  BeginNDJSON; AddRecord "$IP" "failed" "ufw not installed"; CommitNDJSON; exit 1
fi

UFW_STATUS="$(LANG=C ufw status 2>/dev/null || true)"
UFW_ENABLED="true"
printf '%s' "$UFW_STATUS" | grep -qi '^Status: inactive' && UFW_ENABLED="false"


if echo "$UFW_STATUS" \
  | awk -v ip="$IP" '
      NR<=2 {next}
      { low=$0; for(i=1;i<=length($0);i++){} }
      { l=tolower($0) }
      l ~ /deny/ && $0 ~ ("(^|[^0-9])" ip "($|[^0-9])") { found=1 }
      END { exit !found }
    '
then
  STATUS="already_blocked"
  REASON="Rule already present"
else
  if maybe_sudo ufw deny from "$IP" >/dev/null 2>&1; then
    STATUS="blocked"; REASON="ufw deny from ${IP}"
  else
    NEW_STATUS="$(LANG=C ufw status 2>/dev/null || true)"
    if echo "$NEW_STATUS" \
      | awk -v ip="$IP" '
          NR<=2 {next}
          { l=tolower($0) }
          l ~ /deny/ && $0 ~ ("(^|[^0-9])" ip "($|[^0-9])") { found=1 }
          END { exit !found }
        '
    then
      STATUS="already_blocked"; REASON="Rule appeared concurrently"
    else
      STATUS="failed"; REASON="ufw command failed (permissions or syntax?)"
    fi
  fi
fi

[ "$UFW_ENABLED" = "false" ] && REASON="${REASON}; ufw inactive"

BeginNDJSON
AddRecord "$IP" "$STATUS" "$REASON"
CommitNDJSON

Duration=$(( $(date +%s) - RunStart ))
WriteLog "=== SCRIPT END : duration ${Duration}s ==="
