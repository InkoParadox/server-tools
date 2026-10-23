#!/usr/bin/env bash
# Read-only SSH inspection; socket activation does not require an sshd-owned listener.
set -uo pipefail
main() {
  local effective line port bad=0
  printf '\033[38;5;73m\n============================================================\nТЕСТ SSH\n============================================================\033[0m\n'
  for line in sshd ss systemctl; do command -v "$line" >/dev/null || { printf '\033[31mСТОП: нет %s\033[0m\n' "$line"; return 1; }; done
  if ! sshd -t; then printf '\033[31mСТОП: sshd -t не пройден (нужны права чтения ключей)\033[0m\n'; return 1; fi
  if ! effective=$(sshd -T); then printf '\033[31mСТОП: sshd -T не выполнен\033[0m\n'; return 1; fi
  printf '%s\n' "$effective" | grep -E '^(port|listenaddress|pubkeyauthentication|passwordauthentication|permitrootlogin) ' || true
  printf '\033[33mСПРАВКА: это глобальный sshd -T; Match-контекст и внешний вход не проверены.\033[0m\n'
  printf '\n=== ssh.service / ssh.socket ===\n'
  systemctl status ssh.service ssh.socket --no-pager 2>&1 || true
  printf '\n=== Эффективные порты и реальные listeners ===\n'
  while read -r port; do
    [[ $port =~ ^[0-9]+$ ]] || continue
    if ! line=$(ss -H -ltnp "sport = :${port}"); then bad=$((bad+1)); continue; fi
    if [[ -n $line ]]; then printf '\033[92mLISTEN %s\033[0m\n%s\n' "$port" "$line";
    elif systemctl is-active --quiet ssh.socket; then printf '\033[33mСПРАВКА: порт %s из sshd -T не слушает; проверьте Listen у активного ssh.socket.\033[0m\n' "$port";
    else printf '\033[31mСТОП: порт %s не слушает\033[0m\n' "$port"; bad=$((bad+1)); fi
  done < <(printf '%s\n' "$effective" | awk '$1=="port"{print $2}')
  systemctl show ssh.socket -p Listen --no-pager 2>/dev/null || true
  printf '\n=== Все TCP listeners (включая systemd) ===\n'; ss -ltnp || bad=$((bad+1))
  printf '\n=== Строки Port/Include ===\n'
  grep -nE '^[[:space:]]*(Port|Include)[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null || true
  printf '\n=== UFW / последние логи ===\n'
  if command -v ufw >/dev/null; then ufw status verbose 2>/dev/null || true; fi
  journalctl -u ssh.service -u ssh.socket --no-pager -n 20 2>/dev/null || true
  ((bad==0)) || return 1
  printf '\033[92mПроверка конфигурации завершена; внешний IPv4 SSH-вход здесь не проверен.\033[0m\n'
}
if [[ -z ${BASH_SOURCE[0]:-} || ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
