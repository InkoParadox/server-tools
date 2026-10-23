#!/usr/bin/env python3
"""Build the single-file launcher deterministically; --check never writes."""
import argparse,hashlib,pathlib,sys
R=pathlib.Path(__file__).resolve().parents[1]
def build():
    source=(R/'src/engine.py').read_bytes().replace(b'\r\n',b'\n').rstrip(b'\n')+b'\n'
    engine=(R/'tools/engine-prefix.txt').read_bytes().replace(b'\r\n',b'\n')+source.replace(b'\n',b'\r\n')+b'MIST_PYTHON\n'
    digest=hashlib.sha256(engine).hexdigest();tag='MIST_ENGINE_EXACT_'+digest[:12].upper()
    head="""#!/usr/bin/env bash
set -euo pipefail
export PYTHONUTF8=1
[ "$(id -u)" -eq 0 ] || { printf '\\033[1;31mSTOP: root SSH required\\033[0m\\n' >&2; exit 1; }
command -v python3 >/dev/null || { printf '\\033[1;31mSTOP: python3 required\\033[0m\\n' >&2; exit 1; }
umask 077
mist_ipv6_ui_dir=$(mktemp -d /root/mist-ipv6-xshell-XXXXXXXX)
cat > "$mist_ipv6_ui_dir/mist_ipv6_off_fixed.sh" <<'"""+tag+"'\n"
    middle="\n"+tag+"\n"+"""printf '%s  %s\\n' '"""+digest+"' "+'"$mist_ipv6_ui_dir/mist_ipv6_off_fixed.sh"'+""" | sha256sum --check --status || { printf '\\033[1;31mSTOP: engine checksum mismatch\\033[0m\\n' >&2; exit 1; }
chmod 700 "$mist_ipv6_ui_dir/mist_ipv6_off_fixed.sh"
cat > "$mist_ipv6_ui_dir/display.py" <<'MIST_XSHELL_DISPLAY_EOF'
"""
    display=(R/'src/display.py').read_bytes().replace(b'\r\n',b'\n').rstrip(b'\n')+b'\n'
    tail="""MIST_XSHELL_DISPLAY_EOF
export MIST_IPV6_VERIFIED_SHA="""+digest+"\n"+"""export MIST_IPV6_SAVED_SOURCE="$mist_ipv6_ui_dir/mist_ipv6_off_fixed.sh"
[ "$#" -gt 0 ] || set -- --apply
bash "$mist_ipv6_ui_dir/mist_ipv6_off_fixed.sh" "$@" | python3 "$mist_ipv6_ui_dir/display.py"
"""
    return head.encode()+engine.rstrip(b'\n')+middle.encode()+display+tail.encode()
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--check',action='store_true');a=ap.parse_args();data=build();target=R/'ipv6.sh'
    if a.check:
        if target.read_bytes()!=data:raise SystemExit('STOP: ipv6.sh differs from deterministic build')
    else:target.write_bytes(data)
    print(hashlib.sha256(data).hexdigest()+'  ipv6.sh')
