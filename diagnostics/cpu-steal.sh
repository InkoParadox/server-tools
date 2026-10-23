#!/usr/bin/env bash
GREEN='\033[1;92m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
TURQUOISE='\033[38;5;73m'
NC='\033[0m'

section() {
  echo -e "${TURQUOISE}============================================================${NC}"
  echo -e "${TURQUOISE}$1${NC}"
  echo -e "${TURQUOISE}============================================================${NC}"
}

section "CPU / STEAL TEST 60 СЕКУНД"

VCPU="$(nproc)"
case "$VCPU" in
  1) VCPU_RU="виртуальное ядро" ;;
  2|3|4) VCPU_RU="виртуальных ядра" ;;
  *) VCPU_RU="виртуальных ядер" ;;
esac

echo -e "${TURQUOISE}vCPU:${NC} ${VCPU} · ${VCPU_RU}"
echo -e "${TURQUOISE}CPU:${NC} $(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -n1)"
echo -e "${TURQUOISE}Виртуализация:${NC} $(systemd-detect-virt 2>/dev/null || true)"
echo -e "${TURQUOISE}Нагрузка до теста:${NC} $(cut -d' ' -f1-3 /proc/loadavg)"
echo
echo -e "${YELLOW}Замер 60 секунд...${NC}"

command -v vmstat >/dev/null || { echo -e "${RED}СТОП: vmstat не найден${NC}" >&2; exit 1; }
TMP="$(mktemp)" || exit 1
trap 'rm -f "$TMP"' EXIT
vmstat 1 61 > "$TMP" || { echo -e "${RED}СТОП: vmstat завершился ошибкой${NC}" >&2; exit 1; }

if ! awk -v G="$GREEN" -v Y="$YELLOW" -v R="$RED" -v T="$TURQUOISE" -v N="$NC" '
/^[[:space:]]*[0-9]+[[:space:]]+/ {
    if (first++ == 0) next
    n++
    us += $13
    sy += $14
    id += $15
    wa += $16
    st += $17
    if ($17 > maxst) maxst = $17
    if ($17 >= 5) s5++
    if ($17 >= 10) s10++
}
END {
    if (!n) {
        print R "СТОП: vmstat не дал данных" N
        exit 1
    }

    avg = st / n

    print ""
    print T "AVG_USER:       " N sprintf("%.1f%%", us/n) " · программы"
    print T "AVG_SYSTEM:     " N sprintf("%.1f%%", sy/n) " · система и сеть"
    print T "AVG_IDLE:       " N sprintf("%.1f%%", id/n) " · CPU свободен"
    print T "AVG_IOWAIT:     " N sprintf("%.1f%%", wa/n) " · ожидание диска"
    print T "AVG_STEAL:      " N sprintf("%.1f%%", avg) " · ожидание CPU у хостера"
    print T "MAX_STEAL:      " N sprintf("%.0f%%", maxst) " · худший скачок"
    print T "STEAL >= 5%:    " N (s5+0) " из " n " · повышенные скачки"
    print T "STEAL >= 10%:   " N (s10+0) " из " n " · серьёзные скачки"
    print ""

    if (avg >= 10 || s10 >= n/2)
        print R "ИТОГ: ПРОВЕРИТЬ ХОСТЕРА, высокий постоянный steal" N
    else if (avg >= 5 || s5 >= n/2)
        print Y "ИТОГ: НАБЛЮДАТЬ, steal заметный" N
    else
        print G "ИТОГ: НОРМА, CPU хостера сейчас выглядит нормально" N
}' "$TMP"; then exit 1; fi

echo -e "${TURQUOISE}Нагрузка после теста:${NC} $(cut -d' ' -f1-3 /proc/loadavg)"
echo -e "${TURQUOISE}============================================================${NC}"
