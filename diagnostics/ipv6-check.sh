#!/usr/bin/env bash
# Runtime inspection only. The IPv6 2.3.1 transaction tool is unchanged.
set -uo pipefail
main() {
  local key value bad=0 global routes links
  printf '\033[38;5;73m\n============================================================\nПРОВЕРКА IPV6: RUNTIME\n============================================================\033[0m\n'
  for key in sysctl ip; do command -v "$key" >/dev/null || { printf '\033[31mСТОП: нет %s\033[0m\n' "$key"; return 1; }; done
  links=$(ip -o link show) || { printf '\033[31mСТОП: интерфейсы не прочитаны\033[0m\n'; return 1; }
  for key in all default lo $(printf '%s\n' "$links" | awk -F': ' '{print $2}' | cut -d@ -f1); do
    value=$(sysctl -n "net/ipv6/conf/${key}/disable_ipv6" 2>/dev/null) || value=unknown
    printf 'disable_ipv6[%s]=%s\n' "$key" "$value"
    [[ $value == 1 ]] || bad=$((bad+1))
  done
  if ! global=$(ip -6 -o addr show scope global); then printf '\033[31mСТОП: адреса IPv6 не прочитаны\033[0m\n'; return 1; fi
  if ! routes=$(ip -6 route show default); then printf '\033[31mСТОП: маршруты IPv6 не прочитаны\033[0m\n'; return 1; fi
  if [[ -n $global ]]; then printf '%s\n' "$global"; bad=$((bad+1)); fi
  if [[ -n $routes ]]; then printf '%s\n' "$routes"; bad=$((bad+1)); fi
  if ((bad)); then printf '\033[31mСТОП, ПРОВЕРИТЬ: %s\033[0m\n' "$bad"; return 1; fi
  printf '\033[1;92mВСЁ ОК, ДАЛЬШЕ: runtime IPv6 отключён\033[0m\n'
  printf '\033[33mСПРАВКА: постоянные настройки и сохранность после reboot проверяет ipv6.sh --check и отдельный smoke.\033[0m\n'
}
if [[ -z ${BASH_SOURCE[0]:-} || ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
