#!/usr/bin/env bash
geo_main() {
  local c
  for c in curl jq ip timeout awk grep sed; do command -v "$c" >/dev/null || { printf "\033[31mСТОП: нужен %s\033[0m\n" "$c" >&2; return 1; }; done
# Full picture (services + authority + observation) — устойчивые запросы
# Запуск без аргументов: проверяет все публичные IPv4 на сервере.
# Можно указать IP явно: ./geo_full_picture.sh 1.2.3.4 [5.6.7.8 ...]

UA1="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
UA2="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0"
UA3="curl/8.5.0"

TIMEOUT="${TIMEOUT:-60}"          # curl --max-time
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-6}"
ROW_TIMEOUT="${ROW_TIMEOUT:-10}"  # timeout(1) на один HTTP-запрос
RETRIES="${RETRIES:-2}"           # curl --retry
SLEEP="${SLEEP:-0.8}"             # базовая пауза между строками
JITTER_MS="${JITTER_MS:-300}"     # доп. случайная задержка 0..JITTER_MS мс

# IPs: аргументы или IPv4 интерфейсов, кроме RFC1918; это не NAT discovery.
if [ $# -gt 0 ]; then
  IPS="$@"
else
  IPS=$(ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 \
        | grep -Ev '^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\.' | sort -u)
fi

_sleep() {
  base="$SLEEP"
  jitter=$(( RANDOM % (JITTER_MS+1) ))
  jsec=$(awk -v m="$jitter" 'BEGIN{printf "%.3f", m/1000}')
  sleep "$(awk -v a="$base" -v b="$jsec" 'BEGIN{printf "%.3f", a+b}')"
}

# Универсальный body-wrapper: пробует HTTP/2 -> HTTP/1.1 и три UA
_req_body(){ # _req_body <ip> <curl_args...>
  local ip="$1"; shift
  local hv ua out
  for hv in "--http2" "--http1.1"; do
    for ua in "$UA1" "$UA2" "$UA3"; do
      out=$(timeout "${ROW_TIMEOUT}s" \
        curl -4 --interface "$ip" -m "$TIMEOUT" --connect-timeout "$CONNECT_TIMEOUT" -sS -L \
             $hv -H "User-Agent: $ua" \
             --retry "$RETRIES" --retry-delay 1 --retry-connrefused \
             "$@" 2>/dev/null) || true
      if [ -n "$out" ]; then echo "$out"; return 0; fi
    done
  done
  echo ""
  return 0
}

# Только заголовки (для Bing/Steam): тоже с hv/UA перебором
_req_head(){ # _req_head <ip> <url>
  local ip="$1" url="$2" hv ua hdrs
  for hv in "--http2" "--http1.1"; do
    for ua in "$UA1" "$UA2" "$UA3"; do
      hdrs=$(timeout "${ROW_TIMEOUT}s" \
        curl -4 --interface "$ip" -m "$TIMEOUT" --connect-timeout "$CONNECT_TIMEOUT" -sS -L \
             $hv -H "User-Agent: $ua" -D - -o /dev/null \
             "$url" 2>/dev/null) || true
      if [ -n "$hdrs" ]; then echo "$hdrs"; return 0; fi
    done
  done
  echo ""
  return 0
}

# Быстрый Speedtest (XML config, без jq)
_speedtest_cc(){
  local ip="$1" body cc
  body="$(_req_body "$ip" -H 'Referer: https://www.speedtest.net/' https://www.speedtest.net/speedtest-config.php)"
  cc="$(echo "$body" | sed -n 's/.*country="\([A-Z][A-Z]\)".*/\1/p' | head -1)"
  [ -n "$cc" ] && { echo "$cc"; return; }
  body="$(_req_body "$ip" https://c.speedtest.net/speedtest-config.php)"
  cc="$(echo "$body" | sed -n 's/.*country="\([A-Z][A-Z]\)".*/\1/p' | head -1)"
  [ -n "$cc" ] && { echo "$cc"; return; }
  echo "-"
}

_bing_cc(){
  local ip="$1" hdrs r
  hdrs="$(_req_head "$ip" 'https://www.bing.com/?setmkt=en-US&setlang=en')"
  r="$(echo "$hdrs" | grep -i '^set-cookie: _ss=' | grep -oE '\bR=[A-Z]{2}\b' | head -1 | cut -d= -f2)"
  [ -z "$r" ] && r="$(echo "$hdrs" | grep -io 'mkt=[a-z]{2}-[a-z]{2}' | head -1 | awk -F- '{print toupper($2)}')"
  [ -z "$r" ] && r="-"
  echo "$r"
}

_reddit_status(){
  local ip="$1" code
  code="$(_req_body "$ip" -o /dev/null -w '%{http_code}' https://www.reddit.com/)"
  [ "$code" = "200" ] && { echo "OK"; return; }
  code="$(_req_body "$ip" -o /dev/null -w '%{http_code}' https://old.reddit.com/)"
  [ "$code" = "200" ] && echo "OK" || echo "HTTP_$code"
}

# === Код -> Полное название страны (ISO-3166-1 alpha-2) ===
# Кэш популярных стран; остальное — через restcountries (быстро и без ключа)
declare -A NAME_CACHE=(
  [AE]="United Arab Emirates" [FI]="Finland" [RU]="Russia" [NL]="Netherlands"
  [SE]="Sweden" [TR]="Turkey" [DE]="Germany" [US]="United States"
  [GB]="United Kingdom" [FR]="France" [IT]="Italy" [ES]="Spain"
  [PL]="Poland" [UA]="Ukraine" [KZ]="Kazakhstan" [LT]="Lithuania"
  [LV]="Latvia" [EE]="Estonia" [CZ]="Czechia" [SK]="Slovakia"
)

_code_name(){ # _code_name <ip> <ISO2>
  local ip="$1" code="$2" name=""
  code="$(echo "$code" | tr '[:lower:]' '[:upper:]')"
  [[ -z "$code" ]] && { echo "$code"; return; }

  if [[ -n "${NAME_CACHE[$code]}" ]]; then
    echo "${NAME_CACHE[$code]}"; return
  fi

  name="$(_req_body "$ip" "https://restcountries.com/v3.1/alpha/$code?fields=name,cca2" \
         | jq -r '.[0].name.common // .name.common // empty' 2>/dev/null)"
  if [[ -z "$name" || "$name" == "null" ]]; then
    name="$(_req_body "$ip" "https://restcountries.com/v3.1/alpha/$code" \
           | jq -r '.[0].name.common // .name.common // empty' 2>/dev/null)"
  fi
  [[ -z "$name" || "$name" == "null" ]] && name="$code"
  NAME_CACHE[$code]="$name"
  echo "$name"
}

_add_code(){ local v="$1"; echo "$v" | grep -qE '^[A-Z]{2}$' && { CODES="$CODES $v"; TOTAL=$((TOTAL+1)); }; }
_row_keep(){ printf "%-24s %s\n" "$1" "$2"; _sleep; }
_row_count(){ printf "%-24s %s\n" "$1" "$2"; _add_code "$2"; _sleep; }

BAD=0
[ -n "$IPS" ] || { echo "СТОП: IPv4 интерфейсов не найдены" >&2; return 1; }
for IP in $IPS; do
  echo "=============================="
  echo "IP $IP"

  # ASN / ORG
  ORG="$(_req_body "$IP" https://ipinfo.io/json | jq -r '.org // empty')"
  ASN="$(_req_body "$IP" https://ipapi.co/json/ | jq -r '.asn // empty')"
  if [ -n "$ORG" ]; then echo "ASN: $ORG"
  elif [ -n "$ASN" ]; then echo "ASN: $ASN"
  else echo "ASN: -"; fi
  echo

  # ---------- SERVICE ----------
  echo "Service                 IPv4"
  YT_CC="$(_req_body "$IP" -H 'Accept-Language: en' 'https://www.youtube.com/premium?hl=en' \
           | grep -oE '"countryCode":"[A-Z]{2}"' | head -1 | awk -F'"' '{print $(NF-1)}')"
  _row_keep "Google"               "${YT_CC:-"-"}"

  if _req_body "$IP" -H 'Accept-Language: en' 'https://www.google.com/search?q=test' \
       | grep -qiE 'unusual traffic|/sorry/|verify you are a human|enter the characters'; then
    GC="Yes"; else GC="No"; fi
  _row_keep "Google Search Captcha" "$GC"

  _row_keep "YouTube"              "${YT_CC:-"-"}"
  _row_keep "YouTube Premium"      "$([ -n "$YT_CC" ] && echo Yes || echo No)"
  [ "$(_req_body "$IP" -o /dev/null -w '%{http_code}' https://music.youtube.com/)" = "200" ] && YTM="Yes" || YTM="No"
  _row_keep "YouTube Music"        "$YTM"

  _row_keep "Twitch"               "N/A"
  _row_keep "ChatGPT"              "N/A"
  _row_keep "Netflix"              "N/A"
  _row_keep "Spotify"              "N/A"
  _row_keep "Spotify Signup"       "No"
  _row_keep "Deezer"               "N/A"

  RSTAT="$(_reddit_status "$IP")"
  RCOUNTRY="$(_req_body "$IP" https://api.country.is | jq -r '.country // empty')"
  _row_keep "Reddit"               "${RCOUNTRY:-"-"}"
  _row_keep "Reddit (Guest Access)" "$([ "$RSTAT" = "OK" ] && echo Yes || echo No)"

  _row_keep "Amazon Prime"         "N/A"
  _row_keep "Apple"                "N/A"

  SH="$(_req_head "$IP" https://store.steampowered.com/)"
  STEAM_CC="$(echo "$SH" | grep -io 'steamCountry=[A-Z][A-Z]' | head -1 | cut -d= -f2)"
  [ -z "$STEAM_CC" ] && STEAM_CC="-"
  _row_keep "Steam"                "$STEAM_CC"

  _row_keep "PlayStation"          "N/A"
  _row_keep "Tiktok"               "N/A"

  _row_keep "Ookla Speedtest"      "$(_speedtest_cc "$IP")"
  _row_keep "JetBrains"            "N/A"
  _row_keep "Microsoft (Bing)"     "$(_bing_cc "$IP")"

  echo

  # ---------- Authority / Vendor ----------
  echo "Authority / Vendor         Country"
  TOTAL=0; CODES=""
  _row_count "rdap.db.ripe.net" "$(_req_body "$IP" https://rdap.db.ripe.net/ip/"$IP" | jq -r '.country // empty')"
  _row_count "ipinfo.io"        "$(_req_body "$IP" https://ipinfo.io/json          | jq -r '.country // empty')"
  _row_count "ipapi.co"         "$(_req_body "$IP" https://ipapi.co/json/          | jq -r '.country_code // empty')"
  _row_count "ipwho.is"         "$(_req_body "$IP" https://ipwho.is/               | jq -r '.country_code // empty')"
  _row_count "db-ip.com"        "$(_req_body "$IP" https://api.db-ip.com/v2/free/self | jq -r '.countryCode // empty')"
  _row_count "ip-api.com"       "$(_req_body "$IP" 'http://ip-api.com/json?fields=countryCode' | jq -r '.countryCode // empty')"

  echo

  # ---------- Observation / CDN ----------
  echo "Observation / CDN          Country"
  _row_count "cloudflare.com"   "$(_req_body "$IP" https://1.1.1.1/cdn-cgi/trace | sed -n 's/^loc=\([A-Z][A-Z]\)_.*/\1/p; t; s/^loc=\([A-Z][A-Z]\)$/\1/p' | head -1)"
  _row_count "geojs.io"         "$(_req_body "$IP" https://get.geojs.io/v1/ip/country.json | jq -r '.country // empty')"
  _row_count "ip.sb"            "$(_req_body "$IP" https://api.ip.sb/geoip | jq -r '.country_code // empty')"
  _row_count "ifconfig.co"      "$(_req_body "$IP" https://ifconfig.co/json | jq -r '.country_iso // empty')"
  _row_count "myip.com"         "$(_req_body "$IP" https://api.myip.com | jq -r '.cc // empty')"
  _row_count "country.is"       "$(_req_body "$IP" https://api.country.is | jq -r '.country // empty')"
  _row_count "YouTube (CC)"     "${YT_CC:-"-"}"

  echo
  echo "Legend"
  echo
  if [ "$TOTAL" -gt 0 ]; then
    printf "%-10s %-30s %s\n" "Code" "Country" "% IPv4"
    echo "$CODES" | tr ' ' '\n' | sed '/^$/d' \
      | awk '{cnt[$1]++} END{
          total='"$TOTAL"';
          for (k in cnt){ pct = cnt[k]*100.0/total; printf "%s %d %.6f\n", k, cnt[k], pct }
        }' \
      | sort -k3,3nr \
      | while read -r code count pct; do
          name="$(_code_name "$IP" "$code")"
          printf "%-10s %-30s %.0f%%\n" "$code" "$name" "$pct"
        done
  else
    echo "СТОП: нет данных геобаз"; BAD=1
  fi

  echo
done
((BAD==0))
}
if [[ -z ${BASH_SOURCE[0]:-} || ${BASH_SOURCE[0]} == "$0" ]]; then geo_main "$@"; fi
