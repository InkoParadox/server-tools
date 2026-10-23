#!/usr/bin/env bash
# Own launcher only; upstream IPRegion stays in Davoyan/ipregion.
set -uo pipefail
main() (
  local c missing=0 file; local -a elevate=()
  printf '\033[38;5;73m\n============================================================\nПРОВЕРКА IP НА СТРАНУ\n============================================================\033[0m\n'
  for c in curl jq column; do command -v "$c" >/dev/null || missing=1; done
  if ((missing)); then
    if [[ $(id -u) != 0 ]]; then command -v sudo >/dev/null || { printf '\033[31mСТОП: нужны root или sudo для зависимостей\033[0m\n'; return 1; }; elevate=(sudo); fi
    command -v apt-get >/dev/null || { printf '\033[31mСТОП: установите curl, jq и column\033[0m\n'; return 1; }
    "${elevate[@]}" env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get update </dev/null &&
      "${elevate[@]}" env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y curl jq util-linux bsdextrautils </dev/null || return 1
  fi
  umask 077; file=$(mktemp) || return 1
  trap 'rm -f -- "$file"' EXIT
  curl -fLSs --connect-timeout 10 --max-time 60 --retry 2 https://raw.githubusercontent.com/Davoyan/ipregion/e2c6c83bdc90010d13bc5f9c747e3b77fa660791/ipregion.sh -o "$file" || return 1
  printf '%s  %s\n' 17eb73e776f7ab292e30f12223a78c8f25a0ed6808e8204434d122f06e4b4b0e "$file" | sha256sum -c - || return 1
  bash -n "$file" || return 1
  bash "$file"
)
if [[ -z ${BASH_SOURCE[0]:-} || ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
