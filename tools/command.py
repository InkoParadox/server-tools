#!/usr/bin/env python3
"""Generate main/immutable commands; Xshell ends with one literal backslash+r."""
import argparse,base64,hashlib,pathlib,re,zlib
R=pathlib.Path(__file__).resolve().parents[1]
XSHELL_SUFFIX=chr(92)+'r'
def command(ref,check=False):
    if not re.fullmatch('[0-9a-f]{40}',ref):raise ValueError('full Git commit SHA required')
    digest=hashlib.sha256((R/'ipv6.sh').read_bytes()).hexdigest()
    name='mist-ipv6-'+digest[:12]+'.sh'
    return "(umask 077 && cd /root && curl -fLSs --retry 2 --max-time 60 https://raw.githubusercontent.com/InkoParadox/server-tools/"+ref+"/ipv6.sh -o "+name+" && echo '"+digest+"  "+name+"' | sha256sum -c - && bash "+name+(" --check" if check else "")+")"

def latest_command(check=False):
    payload=base64.b64encode(zlib.compress((R/'tools/latest.py').read_bytes(),9)).decode('ascii')
    return "python3 -c 'import base64,zlib;exec(zlib.decompress(base64.b64decode(\""+payload+"\")))'"+(" --check" if check else "")
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--ref');ap.add_argument('--check',action='store_true',help='run only the compatibility check');ap.add_argument('--bash',action='store_true',help='print the same command without the literal Xshell suffix');ap.add_argument('--output',type=pathlib.Path);a=ap.parse_args();plain=command(a.ref,a.check) if a.ref else latest_command(a.check);value=plain if a.bash else plain+XSHELL_SUFFIX
    if a.output:a.output.write_bytes(value.encode()+(b'\n' if a.bash else b''))
    else:print(value)
