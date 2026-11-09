#!/usr/bin/env python3
"""Pinned-main downloader embedded in the permanent Xshell command; stdlib only."""
import hashlib,json,os,pathlib,re,subprocess,sys,tempfile,urllib.request

API='https://api.github.com/repos/InkoParadox/server-tools/commits/main'
RAW='https://raw.githubusercontent.com/InkoParadox/server-tools/'

def fetch(url,limit):
    request=urllib.request.Request(url,headers={'User-Agent':'server-tools-ipv6-loader','Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(request,timeout=25) as response:
        data=response.read(limit+1)
        if len(data)>limit:raise ValueError('download exceeds size limit')
        length=response.headers.get('Content-Length')
        if length is not None and int(length)!=len(data):raise ValueError('incomplete download')
        return data

def main(args=None):
    args=sys.argv[1:] if args is None else args
    if args not in ([],['--check']):raise ValueError('only --check or default apply supported')
    if os.geteuid()!=0:raise ValueError('root required')
    os.umask(0o077)
    folder=pathlib.Path(tempfile.mkdtemp(prefix='mist-ipv6-main-',dir='/root'))
    os.chmod(folder,0o700)
    commit=json.loads(fetch(API,1024*1024))['sha']
    if not isinstance(commit,str) or not re.fullmatch('[0-9a-f]{40}',commit):raise ValueError('invalid main commit SHA')
    script=fetch(RAW+commit+'/ipv6.sh',4*1024*1024)
    sums=fetch(RAW+commit+'/SHA256SUMS',1024*1024)
    for name,data in (('ipv6.sh',script),('SHA256SUMS',sums)):
        with (folder/name).open('xb') as out:out.write(data)
    matches=[]
    for line in sums.decode('utf-8').splitlines():
        match=re.fullmatch(r'([0-9a-fA-F]{64}) [ *]ipv6\.sh',line)
        if match:matches.append(match[1].lower())
    if len(matches)!=1:raise ValueError('expected one exact ipv6.sh checksum')
    digest=hashlib.sha256(script).hexdigest()
    if digest!=matches[0]:raise ValueError('ipv6.sh SHA-256 mismatch; nothing executed')
    versions=re.findall(rb"(?m)^VERSION='([^'\r\n]+)'\r?$",script)
    if len(versions)!=1:raise ValueError('cannot identify verified script version')
    version=versions[0].decode('ascii')
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)+',version):raise ValueError('invalid verified version')
    with (folder/'verified.json').open('x') as out:
        json.dump({'commit':commit,'version':version,'sha256':digest,'script':str(folder/'ipv6.sh')},out,sort_keys=True)
    print('\033[1;92mVERIFIED\033[0m version='+version+' commit='+commit+' SHA256='+digest+' file='+str(folder/'ipv6.sh'),flush=True)
    return subprocess.run(['bash',str(folder/'ipv6.sh'),*args],check=False).returncode

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('\033[0;31mSTOP\033[0m: '+str(error)+'; no fallback executed',file=sys.stderr,flush=True)
        raise SystemExit(1)
