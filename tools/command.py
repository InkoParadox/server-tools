#!/usr/bin/env python3
"""Print a short immutable-download command for Xshell Send String."""
import argparse,hashlib,pathlib,re
R=pathlib.Path(__file__).resolve().parents[1]
def command(ref):
    if not re.fullmatch('[0-9a-f]{40}',ref):raise ValueError('full Git commit SHA required')
    digest=hashlib.sha256((R/'ipv6.sh').read_bytes()).hexdigest()
    return "(set -eu; umask 077; trap 'r=$?;printf \"\\033[1;31mSTOP: download, checksum or tool failed\\033[0m\\n\" >&2;exit \"$r\"' ERR; f=$(mktemp /root/mist-ipv6-XXXXXXXX.sh); curl -fLSs --retry 2 --max-time 60 https://raw.githubusercontent.com/InkoParadox/server-tools/"+ref+"/ipv6.sh -o \"$f\"; printf '%s  %s\\n' '"+digest+"' \"$f\"|sha256sum --check --status; printf '\\033[32mOK: SHA-256 verified\\033[0m\\n' >&2; bash \"$f\")"
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--ref',required=True);ap.add_argument('--bash',action='store_true',help='print plain Bash, without Xshell escaping');ap.add_argument('--output',type=pathlib.Path);a=ap.parse_args();plain=command(a.ref);value=plain if a.bash else plain.replace('\\','\\\\').replace('$','\\$')+'\\r'
    if a.output:a.output.write_bytes(value.encode()+(b'\n' if a.bash else b''))
    else:print(value)
