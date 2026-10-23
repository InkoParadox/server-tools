#!/usr/bin/env python3
"""Apply through existing OpenSSH, then confirm through a separate TCP connection."""
import argparse,base64,hashlib,json,os,pathlib,re,shlex,subprocess,sys

def color(text,tone):
    print('\033['+tone+'m'+text+'\033[0m',file=sys.stderr,flush=True)

def main():
    for stream in (sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8')
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('host',help='existing root SSH alias')
    ap.add_argument('--source',type=pathlib.Path,default=pathlib.Path(__file__).with_name('ipv6.sh'))
    ap.add_argument('--rollback-seconds',type=int,default=600)
    ap.add_argument('--ssh',default='ssh');ap.add_argument('--ssh-config',type=pathlib.Path,help='optional existing/test OpenSSH config; never modified')
    g=ap.add_mutually_exclusive_group();g.add_argument('--check',action='store_true');g.add_argument('--status',action='store_true');g.add_argument('--restore',metavar='TRANSACTION')
    a=ap.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.@:-]+',a.host) or a.host.startswith('-'):ap.error('invalid SSH host/alias')
    if not 60<=a.rollback_seconds<=1800:ap.error('rollback seconds must be 60..1800')
    data=a.source.read_bytes();digest=hashlib.sha256(data).hexdigest()
    if not data.startswith(b'#!/usr/bin/env bash\n') or b'MIST_ENGINE_EXACT_' not in data:raise RuntimeError('source is not the full published launcher')
    ssh=[a.ssh]+(['-F',str(a.ssh_config)] if a.ssh_config else [])+['-T','-o','BatchMode=yes','-o','ConnectTimeout=15','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3','-o','StrictHostKeyChecking=yes','-o','ControlMaster=no','-o','ControlPath=none',a.host,'bash -s']
    def remote(script,render=False):
        proc=subprocess.Popen(ssh,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=None)
        try:out,_=proc.communicate(script.encode())
        except BaseException:
            proc.terminate()
            try:proc.wait(timeout=4)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
            raise
        sys.stdout.buffer.write(out);sys.stdout.buffer.flush()
        events=[]
        for line in out.decode('utf-8').splitlines():
            try:event=json.loads(line)
            except ValueError:continue
            if isinstance(event,dict):
                events.append(event)
                if render:
                    status=event.get('status','INFO');tone='1;31' if status=='STOP' else '1;32' if status in ('COMMITTED','NOOP','CHECK_OK') else '1;33'
                    color('['+status+'] '+str(event.get('reason',event.get('transaction',''))),tone)
        if proc.returncode:
            outcome='server reported ROLLED_BACK' if any(x.get('status')=='ROLLED_BACK' for x in events) else 'inspect transaction status; any armed watchdog remains responsible for recovery'
            raise RuntimeError('SSH/tool failed (exit '+str(proc.returncode)+'); '+outcome)
        return events
    # Decode into a unique retained root-only file; never execute a partial file.
    script="set -euo pipefail\numask 077\nf=$(mktemp /root/mist-ipv6-pc-XXXXXXXX.sh)\nbase64 -d > \"$f\" <<'MIST_UPLOAD'\n"+base64.b64encode(data).decode()+"\nMIST_UPLOAD\nprintf '%s  %s\\n' "+shlex.quote(digest)+" \"$f\" | sha256sum --check --status\nchmod 700 \"$f\"\nexport MIST_IPV6_UI=stderr TERM=xterm\nbash \"$f\" "
    if a.check:args=['--check']
    elif a.status:args=['--status']
    elif a.restore:args=['--restore',a.restore]
    else:args=['--apply','--rollback-seconds',str(a.rollback_seconds)]
    color('[...] Проверка и запуск исходника SHA-256 '+digest,'33')
    events=remote(script+shlex.join(args)+'\n')
    if a.check or a.status or a.restore:return
    last=next((x for x in reversed(events) if x.get('status') in ('AWAITING_CONFIRMATION','NOOP')),None)
    if not last:raise RuntimeError('apply did not return NOOP or AWAITING_CONFIRMATION')
    if last['status']=='NOOP':return
    tx=last['transaction'];tool=last['tool']
    if not re.fullmatch(r'/var/lib/mist-ipv6/tx-[A-Za-z0-9-]+',tx) or tool!=tx+'/tool.sh':raise RuntimeError('invalid returned transaction path; watchdog retained')
    # The first SSH process has ended. Reuse is disabled again for confirmation.
    color('[...] Новое внешнее SSH-подключение для подтверждения','33')
    events=remote('set -euo pipefail\nexport MIST_IPV6_UI=stderr TERM=xterm\nbash '+shlex.quote(tool)+' --confirm '+shlex.quote(tx)+'\n',render=True)
    if not any(x.get('status')=='COMMITTED' for x in events):raise RuntimeError('confirmation did not return COMMITTED; watchdog retained')
    color('[OK] Новый TCP проверен, операция подтверждена, страховка отменена.','1;32')

if __name__=='__main__':
    try:main()
    except KeyboardInterrupt:color('[СТОП] Прервано. Незавершённая операция остаётся под автооткатом.','1;31');sys.exit(130)
    except Exception as e:color('[СТОП] '+str(e),'1;31');sys.exit(1)
