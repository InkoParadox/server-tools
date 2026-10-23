#!/usr/bin/env bash
# Own adapter, not a redistributed upstream benchmark. No upstream code is sourced.
set -uo pipefail
download() {
  local url=$1 expected=$2 file=$3
  curl -fLSs --connect-timeout 10 --max-time 90 --retry 2 "$url" -o "$file" || return 1
  printf '%s  %s\n' "$expected" "$file" | sha256sum -c - >/dev/null || return 1
}
prepare_iperf() {
  local folder=$1 arch asset digest
  command -v iperf3 >/dev/null && return 0
  arch=$(uname -m) || return 1
  case $arch in
    x86_64) asset=iperf3-amd64; digest=ef4c89f3fc01c56cf00d34b900024c74f68e540dab452eef4fd902544d9c1c64 ;;
    aarch64|arm64) asset=iperf3-arm64v8; digest=34364466812357fe021a8647cb433c8006b0360e3b690ecda470a979a2601031 ;;
    *) printf '\033[31mСТОП: нет закреплённого iperf3 для %s\033[0m\n' "$arch"; return 1 ;;
  esac
  mkdir -p "$folder/bin" || return 1
  download "https://github.com/userdocs/iperf3-static/releases/download/3.22/$asset" "$digest" "$folder/bin/iperf3" || return 1
  chmod 700 "$folder/bin/iperf3" || return 1
  export PATH="$folder/bin:$PATH"
}
main() (
  local folder c
  printf '\033[38;5;73m\n============================================================\nТЕСТ СКОРОСТИ ИНТЕРНЕТА #1\n============================================================\033[0m\n'
  for c in curl wget sha256sum; do command -v "$c" >/dev/null || { printf '\033[31mСТОП: нужен %s\033[0m\n' "$c"; return 1; }; done
  umask 077
  folder=$(mktemp -d) || return 1
  trap 'rm -rf -- "$folder"' EXIT
  download https://bench.tlab.pw/bench.sh a02ff383bdb96dea984cb4f2feea77caac383070d4bbd37b088f3ebd0ac38853 "$folder/bench.sh" || { printf '\033[31mСТОП: benchmark не скачан или изменился upstream; запуск отменён\033[0m\n'; return 1; }
  bash -n "$folder/bench.sh" || return 1
  prepare_iperf "$folder" || { printf '\033[31mСТОП: iperf3 не подготовлен\033[0m\n'; return 1; }
  # Upstream finds the verified binary in PATH and never enters its broken ARM URL fallback.
  bash "$folder/bench.sh"
)
if [[ -z ${BASH_SOURCE[0]:-} || ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
