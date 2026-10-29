#!/bin/sh
# Read-only preflight for the *running* ARTEX process. Requires Linux cgroup v2.
set -eu
pid=${1:?Usage: sh scripts/check-resource-limits.sh ARTEX_PID}
case "$pid" in ''|*[!0-9]*) echo 'PID must be numeric' >&2; exit 2;; esac
[ -r "/proc/$pid/cgroup" ] || { echo 'Process/cgroup unavailable' >&2; exit 2; }
location=
while IFS=: read -r hierarchy controllers group; do
  if [ "$hierarchy" = 0 ] && [ -z "$controllers" ]; then location=$group; fi
done < "/proc/$pid/cgroup"
[ -n "$location" ] || { echo 'cgroup v2 is required for this preflight' >&2; exit 2; }
root=/sys/fs/cgroup
case "$location" in *'..'*) location=/;; esac
dir=$root$location
memory=0 cpu=0 pids=0
while :; do
  for controller in memory.max cpu.max pids.max; do
    if [ -r "$dir/$controller" ]; then
      value=$(cat "$dir/$controller")
      printf '%s = %s\n' "$dir/$controller" "$value"
      case "$value" in max*) :;; *)
        case "$controller" in memory.max) memory=1;; cpu.max) cpu=1;; pids.max) pids=1;; esac
      esac
    fi
  done
  [ "$dir" != "$root" ] || break
  dir=${dir%/}
  dir=${dir%/*}
  case "$dir" in "$root"|"$root"/*) :;; *) break;; esac
done
if [ "$memory$cpu$pids" != 111 ]; then
  echo 'FAIL: CPU, memory or PID hard ceiling is missing. Admission alone cannot contain running descendants.' >&2
  exit 1
fi
echo 'PASS: effective ancestor CPU/memory/PID ceilings found. Validate their values against the host budget.'
