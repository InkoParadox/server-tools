#!/usr/bin/env bash
set -euo pipefail
export PYTHONUTF8=1
[ "$(id -u)" -eq 0 ] || { printf '\033[1;31mSTOP: root required\033[0m\n' >&2; exit 1; }
command -v python3 >/dev/null || { printf '\033[1;31mSTOP: python3 required\033[0m\n' >&2; exit 1; }
umask 077
mist_ipv6_ui_dir=$(mktemp -d /root/mist-ipv6-xshell-XXXXXXXX)
cat > "$mist_ipv6_ui_dir/mist_ipv6_off_fixed.sh" <<'MIST_ENGINE_EXACT_1D230A3B6D64'
#!/usr/bin/env bash
set -eu
export PYTHONUTF8=1
export MIST_IPV6_SELF="$(readlink -f -- "${BASH_SOURCE[0]}")"
command -v python3 >/dev/null || { echo "STOP: python3 required" >&2; exit 1; }
exec python3 - "$@" <<'MIST_PYTHON'
#!/usr/bin/env python3
"""MIST IPv6 host transaction. Embedded in the distributed Bash file. Python >=3.8."""
import argparse,base64,copy,ctypes,errno,fcntl,socket,struct,collections,glob,hashlib,ipaddress,json,os,pathlib,re,shlex,shutil,signal,stat,subprocess,sys,tempfile,time,uuid
need_python = sys.version_info >= (3,8)
if not need_python:raise SystemExit('STOP: Python >=3.8 required; no package installed')
VERSION='2.3'
APPLY_DEADLINE=None
ROOT=pathlib.Path('/')
STATE='/var/lib/mist-ipv6'
POLICY='/etc/sysctl.d/99-zz-mist-ipv6-off.conf'
KNOBS=('disable_ipv6','accept_ra','autoconf','addr_gen_mode','use_tempaddr','proxy_ndp')
class Stop(Exception):pass
def need(ok,msg):
    if not ok:raise Stop(msg)
def p(path):return ROOT/path.lstrip('/')
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def run(args,check=True,timeout=60,stdin=None):
    if APPLY_DEADLINE is not None:
        left=APPLY_DEADLINE-time.monotonic()-25
        need(left>0,'apply deadline reached; reserving time for rollback')
        timeout=min(timeout,left)
    proc=subprocess.Popen(args,stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',errors='replace',start_new_session=True,env=dict(os.environ,LC_ALL='C'))
    try:out,err=proc.communicate(stdin,timeout=timeout)
    except BaseException:
        try:os.killpg(proc.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        try:proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            proc.wait(timeout=3)
        raise
    r=subprocess.CompletedProcess(args,proc.returncode,out,err)
    if check and r.returncode:raise Stop('command failed: '+shlex.join(args[:4])+' (exit '+str(r.returncode)+'): '+r.stderr[-700:])
    return r
def jr(*args):return json.loads(run(list(args)).stdout)
def active(unit):return run(['systemctl','is-active','--quiet',unit],False).returncode==0
def emit(**v):print(json.dumps(v,ensure_ascii=False),flush=True)
def xattrs(q):
    try:return {k:base64.b64encode(os.getxattr(q,k,follow_symlinks=False)).decode() for k in sorted(os.listxattr(q,follow_symlinks=False))}
    except OSError as error:
        if error.errno in (errno.ENOTSUP,errno.EOPNOTSUPP):return {}
        raise

def default_selinux_label(path,mode):
    if not p('/sys/fs/selinux/enforce').exists():return None
    # Official libselinux labeling API, no shell/helper/package installation.
    lib=ctypes.CDLL('libselinux.so.1',use_errno=True)
    lib.selabel_open.argtypes=[ctypes.c_uint,ctypes.c_void_p,ctypes.c_uint];lib.selabel_open.restype=ctypes.c_void_p
    lib.selabel_lookup_raw.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_char_p),ctypes.c_char_p,ctypes.c_int];lib.selabel_lookup_raw.restype=ctypes.c_int
    lib.selabel_close.argtypes=[ctypes.c_void_p];lib.freecon.argtypes=[ctypes.c_void_p]
    handle=lib.selabel_open(0,None,0);need(handle,'cannot open the active SELinux file-label policy')
    context=ctypes.c_char_p()
    try:
        need(lib.selabel_lookup_raw(handle,ctypes.byref(context),os.fsencode(path),mode)==0,'cannot determine SELinux label for '+str(path))
        need(context.value and context.value!=b'<<none>>','no safe SELinux label for '+str(path));return context.value+b'\0'
    finally:
        if context:lib.freecon(context)
        lib.selabel_close(handle)

def atomic(q,data,mode=0o600,owner=None,times=None,attrs=None,before_replace=None):
    missing=[];parent=q.parent
    while not parent.exists():missing.append(parent);parent=parent.parent
    q.parent.mkdir(parents=True,exist_ok=True)
    for parent in reversed(missing):
        label=default_selinux_label(parent,parent.stat().st_mode)
        if label is not None:os.setxattr(parent,'security.selinux',label,follow_symlinks=False)
    need(not q.is_symlink(),'symlink target: '+str(q))
    previous=xattrs(q) if q.exists() else None
    fd,tmp=tempfile.mkstemp(prefix='.mist-',dir=q.parent)
    try:
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        if owner:os.chown(tmp,*owner)
        wanted=attrs if attrs is not None else previous
        if wanted is not None:
            for key in os.listxattr(tmp):
                if key not in wanted:os.removexattr(tmp,key)
            for key,value in wanted.items():os.setxattr(tmp,key,base64.b64decode(value))
        elif (label:=default_selinux_label(q,stat.S_IFREG|mode)) is not None:os.setxattr(tmp,'security.selinux',label)
        # chmod updates the POSIX ACL mask using native filesystem semantics.
        os.chmod(tmp,mode)
        if times:os.utime(tmp,ns=times)
        fd=os.open(tmp,os.O_RDONLY);os.fsync(fd);os.close(fd)
        if before_replace:before_replace(pathlib.Path(tmp))
        os.replace(tmp,q)
        fd=os.open(q.parent,os.O_RDONLY);os.fsync(fd);os.close(fd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def file_record(path):
    q=p(path);need(not q.is_symlink(),'configuration symlink requires its owner to be identified: '+path)
    if not q.exists():return {'path':path,'exists':False,'sha':None}
    s=q.stat();need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_mode&0o022==0,'unsafe config permissions: '+path)
    b=read_noatime(q)
    return dict(path=path,exists=True,sha=sha(b),data=base64.b64encode(b).decode(),xattrs=xattrs(q),mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid,atime=s.st_atime_ns,mtime=s.st_mtime_ns)
def read_noatime(q):
    fd=os.open(q,os.O_RDONLY|getattr(os,'O_NOATIME',0)|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as f:return f.read()
def current_hash(path):
    q=p(path);need(not q.is_symlink(),'configuration became a symlink: '+path)
    return sha(read_noatime(q)) if q.exists() else None
def matches(path,record):
    if 'symlink' in record:
        q=p(path)
        if not q.is_symlink():return False
        st=q.lstat()
        return os.readlink(q)==record['symlink'] and st.st_uid==record['uid'] and st.st_gid==record['gid'] and st.st_mtime_ns==record['mtime']
    regenerated=record.get('owner_regeneration')
    new_boot=bool(regenerated and regenerated['boot']!=p('/proc/sys/kernel/random/boot_id').read_text().strip())
    actual_hash=current_hash(path)
    if actual_hash!=record.get('sha') and not (new_boot and actual_hash in regenerated['sha256']):return False
    q=p(path)
    if not q.exists():return not record.get('exists',False)
    st=q.stat();actual={'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'mtime':st.st_mtime_ns}
    if new_boot:actual.pop('mtime') # exact native output may be re-created by cloud-init at boot
    return all(actual[k]==record[k] for k in actual if k in record) and ('xattrs' not in record or xattrs(q)==record['xattrs'])

def yaml_load(text):
    try:import yaml
    except ImportError:raise Stop('PyYAML is required for Netplan/cloud-init; nothing installed automatically')
    class Loader(yaml.SafeLoader):pass
    def mapping(loader,node,deep=False):
        d={}
        for k,v in node.value:
            key=loader.construct_object(k,deep=deep);need(key not in d,'duplicate YAML key: '+str(key));d[key]=loader.construct_object(v,deep=deep)
        return d
    Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,mapping)
    try:return yaml.load(text,Loader=Loader)
    except yaml.YAMLError as error:
        mark=getattr(error,'problem_mark',None)
        raise Stop('YAML parse error'+(' at line '+str(mark.line+1)+', column '+str(mark.column+1) if mark else '')+'; configuration values omitted') from error
def cloud_network(text):
    # cloud-init vendors may have duplicate unrelated keys (e.g. sudo). Read
    # only the network subtree; retain strict duplicate checks inside that scope.
    try:import yaml
    except ImportError:raise Stop('PyYAML required for cloud-init; no package installed')
    try:node=yaml.compose(text)
    except yaml.YAMLError as error:raise Stop('cloud-init YAML parse error; configuration values omitted') from error
    if node is None:return {}
    need(isinstance(node,yaml.MappingNode),'cloud-init config is not a mapping')
    values=[v for k,v in node.value if isinstance(k,yaml.ScalarNode) and k.value=='network']
    need(len(values)<=1,'duplicate cloud-init network key')
    return {'network':yaml_load(yaml.serialize(values[0]))} if values else {}

def yaml_dump(v):
    import yaml
    return yaml.safe_dump(v,sort_keys=False,allow_unicode=True).encode()
def merge(a,b):
    if isinstance(a,dict) and isinstance(b,dict):
        d=copy.deepcopy(a)
        for k,v in b.items():d[k]=merge(d[k],v) if k in d else copy.deepcopy(v)
        return d
    if isinstance(a,list) and isinstance(b,list):return copy.deepcopy(a+b)
    return copy.deepcopy(b)
def is6(s):
    s=str(s).split('%')[0]
    try:return ipaddress.ip_interface(s).version==6
    except ValueError:return ':' in s

def strip_netplan(doc):
    d=copy.deepcopy(doc);n=d.get('network',{})
    for group,defs in n.items():
        if not isinstance(defs,dict) or group in ('openvswitch',):continue
        for name,e in defs.items():
            need(isinstance(e,dict),'invalid Netplan definition '+str(name))
            nm=e.get('networkmanager',{});pas=nm.get('passthrough',{})
            if pas or group=='nm-devices' or e.get('renderer',n.get('renderer'))=='NetworkManager':
                need(not any(k.startswith('ipv6.dns') and v for k,v in pas.items()),'IPv6 DNS in NM passthrough '+str(name))
                need(not any(k.endswith('.endpoint') and str(v).startswith('[') for k,v in pas.items()),'IPv6 VPN endpoint in NM passthrough '+str(name))
                e.setdefault('networkmanager',{})['passthrough']={**{k:v for k,v in pas.items() if not k.startswith('ipv6.')},'ipv6.method':'disabled'}
            if group=='nm-devices':continue
            if group=='tunnels':need(not any(is6(e.get(k,'')) for k in ('local','remote')),'IPv6 tunnel underlay: '+str(name))
            if 'addresses' in e:e['addresses']=[a for a in e['addresses'] if not is6(next(iter(a)) if isinstance(a,dict) else a)]
            if 'routes' in e:e['routes']=[r for r in e['routes'] if not is6(r.get('via','')) and not is6(r.get('to','')) and r.get('family') not in (6,'ipv6')]
            if 'routing-policy' in e:e['routing-policy']=[r for r in e['routing-policy'] if not any(is6(r.get(k,'')) for k in ('from','to'))]
            need(not any(is6(x) for x in e.get('nameservers',{}).get('addresses',[])),'IPv6 DNS in Netplan '+str(name)+'; DNS must be preserved')
            for k in ('gateway6','ipv6-address-generation','ipv6-address-token','ipv6-privacy','ipv6-mtu'):e.pop(k,None)
            e['dhcp6']=False;e['accept-ra']=False;e['link-local']=[x for x in e.get('link-local',[]) if x=='ipv4']
    return d

def unit_sections(text):
    out=[];name=None;lines=[]
    for line in text.splitlines(keepends=True):
        m=re.match(r'\s*\[([^]]+)\]',line)
        if m:
            if lines:out.append((name,lines))
            name=m[1];lines=[line]
        else:lines.append(line)
    if lines:out.append((name,lines))
    return out
def ini_pairs(lines):
    d={}
    for l in lines:
        m=re.match(r'\s*([^#;\s=]+)\s*=\s*(.*?)\s*(?:\n)?$',l)
        if m:d.setdefault(m[1],[]).append(m[2])
    return d
def strip_networkd(text):
    out=[]
    for section,lines in unit_sections(text):
        kv=ini_pairs(lines)
        if section=='RoutingPolicyRule' and kv.get('Family',[''])[-1]=='ipv6':continue
        if section in ('Address','Route','RoutingPolicyRule','IPv6AddressLabel','IPv6Prefix','IPv6RoutePrefix','IPv6PREF64Prefix'):
            if section.startswith('IPv6') or any(is6(v) for k,vs in kv.items() for v in vs if k in ('Address','Destination','Gateway','Source','From','To')):continue
        for l in lines:
            m=re.match(r'(\s*)([^#;\s=]+)\s*=\s*(.*?)\s*$',l)
            if not m:out.append(l);continue
            ws,k,v=m.groups()
            if section=='RoutingPolicyRule' and k=='Family' and v=='both':v='ipv4'
            if section=='Network':
                if k in ('IPv6SendRA','DHCPPrefixDelegation') and v.lower() in ('yes','true','1'):raise Stop('IPv6 router/prefix delegation is a real dependency')
                if k in ('DNS','NTP') and any(is6(x) for x in v.split()):raise Stop('IPv6 '+k+' dependency in networkd')
                if k in ('Address','Gateway') and is6(v):continue
                if k=='DHCP':v='ipv4' if v.lower() in ('yes','true','1','ipv4') else 'no'
                elif k=='LinkLocalAddressing':v='ipv4' if v.lower() in ('yes','true','1','ipv4') else 'no'
                elif k in ('IPv6AcceptRA','IPv6LinkLocalAddressGenerationMode','IPv6PrivacyExtensions','IPv6Token','IPv6MTUBytes'):continue
            out.append(ws+k+'='+v+'\n')
    return ''.join(out)
def strip_interfaces(text,inet4_names=None,ifup2=False,disable_attr=False,inline_policy=True):
    # Interface stanzas can be split across source files. IPv6-only links retain
    # a native manual stanza, including their MTU/L2 topology settings.
    if inet4_names is None:inet4_names=set(re.findall(r'^\s*iface\s+(\S+)\s+inet\s+',text,re.M))
    lines=text.splitlines(keepends=True);out=[];i=0
    directive=r'^\s*(?:iface|auto|allow-\S+|source|source-directory|mapping|rename)\s'
    def body_filter(body,ipv6=False):
        kept=[]
        for line in body:
            m=re.match(r'\s*(pre-up|up|post-up|pre-down|down|post-down)\s+(.*)',line)
            if m:
                cmd=m[2].strip()
                if re.match(r'^(?:/sbin/|/usr/sbin/|/bin/|/usr/bin/)?ip\s+-6\s+(?:addr(?:ess)?|route|rule)\s+',cmd) and not re.search(r'[;|&`$]',cmd):continue
                need(not ipv6,'IPv6 stanza has an arbitrary lifecycle hook: '+cmd[:120])
                need(not re.search(r'\b(?:ip\s+-6|dhclient\s+-6|disable_ipv6)\b',cmd),'custom IPv6 enable hook requires its owner: '+cmd[:120])
            m=re.match(r'(\s*)(address|gateway|dns-nameservers|netmask)\s+(.*)',line)
            if m:
                ws,k,v=m.groups();values=v.split()
                if k=='dns-nameservers':need(not any(is6(x) for x in values),'IPv6 DNS in interfaces; DNS must be preserved')
                if ipv6 and k in ('address','gateway','netmask'):continue
                if k in ('address','gateway') and any(is6(x) for x in values):
                    values=[x for x in values if not is6(x)]
                    if values:kept.append(ws+k+' '+' '.join(values)+'\n')
                    continue
            if ifup2 and re.match(r'\s*(?:ipv6-addrgen|disable-ipv6|disable-ip6)\s+',line):continue
            if ipv6 and re.match(r'\s*(?:accept_ra|autoconf|privext|dad-attempts|dad-interval)\s+',line):continue
            kept.append(line)
        return kept
    while i<len(lines):
        m=re.match(r'^(\s*)iface\s+(\S+)(?:\s+(inet6|inet)\s+(\S+))?',lines[i])
        if not m:out.append(lines[i]);i+=1;continue
        j=i+1
        while j<len(lines) and not re.match(directive,lines[j]):j+=1
        ws,name,family,method=m.groups();body=body_filter(lines[i+1:j],family=='inet6')
        meaningful=any(v.strip() and not v.lstrip().startswith('#') for v in body)
        if family!='inet6' or name not in inet4_names or meaningful:
            out.append(ws+'iface '+name+' inet6 manual\n' if family=='inet6' else lines[i])
            if ifup2 and inline_policy:
                out.append(ws+'    ipv6-addrgen off\n')
                if disable_attr:out.append(ws+'    disable-ipv6 yes\n')
            out.extend(body)
        i=j
    return ''.join(out)

def strip_nm_keyfile(text):
    out=[];found=False
    for sec,lines in unit_sections(text):
        if sec=='ipv6':
            need(not found,'duplicate ipv6 keyfile group');found=True
            kv=ini_pairs(lines)
            need(not any(is6(v) for line in kv.get('dns',[]) for v in line.split(';') if v),'IPv6 DNS in NetworkManager keyfile')
            out.append('[ipv6]\nmethod=disabled\n')
        else:out.extend(lines)
    # A standalone profile without an explicit IPv6 group defaults to auto.
    connection=next((ini_pairs(lines) for sec,lines in unit_sections(text) if sec=='connection'),{})
    port=any(connection.get(k) for k in ('master','slave-type','controller','port-type'))
    if not found and not port:
        if out and not out[-1].endswith('\n'):out[-1]+='\n'
        out.append('[ipv6]\nmethod=disabled\n')
    return ''.join(out)

def strip_ifcfg(text):
    out=[]
    for line in text.splitlines(keepends=True):
        m=re.match(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)',line)
        if not m:
            need(not line.strip() or line.lstrip().startswith('#'),'dynamic ifcfg script requires its provisioning owner')
            out.append(line);continue
        key,value=m.groups()
        if re.fullmatch(r'DNS[0-9]+',key):
            vals=shlex.split(value,comments=True);need(not any(is6(v) for v in vals),'IPv6 DNS in ifcfg')
        if key=='IPV6FORWARDING':need(not any(v.lower() in ('yes','true','1') for v in shlex.split(value,comments=True)),'ifcfg IPv6 forwarding dependency')
        if key.startswith(('IPV6','DHCPV6')):continue
        out.append(line)
    if out and not out[-1].endswith('\n'):out[-1]+='\n'
    return ''.join(out)+'IPV6_DISABLED=yes\nIPV6INIT=no\nIPV6_AUTOCONF=no\nDHCPV6C=no\n'

def nm_catalog():
    result={}
    for line in run(['nmcli','-t','-f','UUID,DBUS-PATH','connection','show']).stdout.splitlines():
        ident,obj=line.split(':',1)
        need(re.fullmatch(r'[0-9a-fA-F-]{36}',ident),'invalid NM UUID')
        need(obj.startswith('/org/freedesktop/NetworkManager/Settings/'),'invalid NM settings object')
        def prop(name):
            value=shlex.split(run(['busctl','--no-pager','get-property','org.freedesktop.NetworkManager',obj,'org.freedesktop.NetworkManager.Settings.Connection',name]).stdout)
            need(len(value)==2,'unexpected NM property '+name);return value[1]
        result[ident]={'path':prop('Filename'),'flags':int(prop('Flags')),'method':run(['nmcli','-g','ipv6.method','connection','show',ident],False).stdout.strip()}
    return result

def cloud_netplan_renderings(net):
    # Capture exact outputs of the installed provisioning renderer and native
    # Netplan writer. Arbitrary semantically equal YAML is NOT accepted.
    distro={}
    for line in p('/etc/os-release').read_text().splitlines():
        if '=' in line:
            k,v=line.split('=',1);distro[k]=v.strip('"')
    with tempfile.TemporaryDirectory(prefix='mist-cloud-') as folder:
        root=pathlib.Path(folder);source=root/'network.yaml';source.write_bytes(yaml_dump(net));out=root/'render'
        run(['cloud-init','devel','net-convert','--network-data',str(source),'--kind','yaml','--directory',str(out),'--distro',distro.get('ID',''),'--output-kind','netplan'])
        files=list((out/'etc/netplan').glob('*.yaml'))
        need(len(files)==1,'cloud-init offline renderer produced an unexpected Netplan file set')
        generated=files[0];content=generated.read_bytes()
        need(yaml_load(content.decode())=={'network':net},'cloud-init renderer changes settings beyond the planned network intent')
        hashes={sha(content)}
        run(['netplan','set','--root-dir',str(out),'--origin-hint',generated.stem,'network.version=2'])
        content=generated.read_bytes()
        need(yaml_load(content.decode())=={'network':net},'Netplan native writer changes the cloud-init network intent')
        hashes.add(sha(content))
        return sorted(hashes)

class Plan:
    def __init__(self):self.changes={};self.watched={};self.actions=[];self.owners={};self.nm_devices={};self.nm_paths={};self.netplan_before=None;self.nm_catalog={}
    def watch(self,path):
        if path not in self.watched:self.watched[path]=file_record(path)
        return self.watched[path]
    def put(self,path,data,mode=None):
        rec=self.watch(path);old=base64.b64decode(rec['data']) if rec['exists'] else None
        desired_mode=mode if mode is not None else rec.get('mode',0o600)
        if old==data and rec.get('mode')==desired_mode:self.changes.pop(path,None);return
        self.changes[path]={'data':base64.b64encode(data).decode(),'sha':sha(data),'mode':desired_mode,'uid':rec.get('uid',0),'gid':rec.get('gid',0),'mtime':time.time_ns(),'atime':time.time_ns()}
    def watch_globs(self):
        patterns=('/etc/netplan/*.yaml','/run/netplan/*.yaml','/lib/netplan/*.yaml','/etc/systemd/network/*.network','/run/systemd/network/*.network','/usr/lib/systemd/network/*.network','/etc/systemd/network/*.network.d/*.conf','/run/systemd/network/*.network.d/*.conf','/usr/lib/systemd/network/*.network.d/*.conf','/etc/NetworkManager/system-connections/*','/run/NetworkManager/system-connections/*','/etc/NetworkManager/NetworkManager.conf','/etc/NetworkManager/conf.d/*.conf','/usr/lib/NetworkManager/conf.d/*.conf','/run/NetworkManager/conf.d/*.conf','/etc/systemd/networkd.conf','/etc/systemd/networkd.conf.d/*.conf','/etc/network/if-up.d/*','/etc/network/ifupdown2/*.conf','/etc/network/interfaces','/etc/network/interfaces.d/*','/etc/cloud/cloud.cfg','/etc/cloud/cloud-init.disabled','/etc/cloud/cloud.cfg.d/*.cfg','/etc/sysctl.conf','/etc/sysctl.d/*.conf','/usr/lib/NetworkManager/system-connections/*','/etc/sysconfig/network-scripts/ifcfg-*','/etc/sysconfig/network-scripts/route6-*','/etc/sysconfig/network-scripts/rule6-*','/etc/sysconfig/network','/run/sysctl.d/*.conf','/usr/lib/sysctl.d/*.conf')
        paths=sorted({str(q.relative_to(ROOT)).replace(os.sep,'/') for pat in patterns for q in ROOT.glob(pat.lstrip('/')) if q.is_file() and not q.is_symlink()})
        paths=sorted(set(paths)|{x.lstrip('/') for x in self.watched if p(x).is_file()})
        return ['/'+x for x in paths if not (self.netplan_before is not None and (x.startswith('run/systemd/network/10-netplan-') or x.startswith('run/NetworkManager/system-connections/netplan-') or x=='run/NetworkManager/conf.d/10-globally-managed-devices.conf'))]
    def netplan(self):
        effective={}
        for folder in ('/lib/netplan','/etc/netplan','/run/netplan'):
            for q in p(folder).glob('*.yaml'):effective[q.name]='/'+str(q.relative_to(ROOT))
        merged={};after={}
        for name,path in sorted(effective.items()):
            rec=self.watch(path);doc=yaml_load(base64.b64decode(rec['data']).decode());need(isinstance(doc,dict),'invalid Netplan '+path)
            changed=strip_netplan(doc);merged=merge(merged,doc);after=merge(after,changed)
            if doc!=changed:
                need(not path.startswith('/run/'),'runtime Netplan source '+path+' has no durable identified writer')
                self.put('/etc/netplan/'+name,yaml_dump(changed))
        need(effective,'no Netplan source')
        need(after==strip_netplan(merged),'Netplan merge projection mismatch')
        self.netplan_before=merged
        self.actions.append({'type':'netplan','networkd_ifaces':[n for n,o in self.owners.items() if o=='netplan/networkd'],'nm_devices':self.nm_devices})
        return merged
    def networkd(self,path,iface):
        need(path.startswith(('/etc/systemd/network/','/usr/lib/systemd/network/','/lib/systemd/network/')),'generated networkd unit has unknown owner: '+path)
        name=pathlib.Path(path).name;files=[path];drop={}
        for folder in ('/usr/lib/systemd/network','/run/systemd/network','/etc/systemd/network'):
            for q in p(folder+'/'+name+'.d').glob('*.conf'):drop[q.name]='/'+str(q.relative_to(ROOT))
        files+= [v for k,v in sorted(drop.items())]
        ll=False;dhcp=False
        for src in files:
            rec=self.watch(src);text=base64.b64decode(rec['data']).decode()
            for sec,ls in unit_sections(text):
                if sec=='Network':
                    kv=ini_pairs(ls)
                    if 'DHCP' in kv:dhcp=kv['DHCP'][-1].lower() in ('yes','1','true','ipv4')
                    if 'LinkLocalAddressing' in kv:ll=kv['LinkLocalAddressing'][-1].lower() in ('yes','1','true','ipv4')
            new=strip_networkd(text)
            if text!=new:
                need(not src.startswith('/run/'),'runtime networkd drop-in has unknown writer: '+src)
                dst=src if src.startswith('/etc/') else '/etc/systemd/network/'+str(pathlib.Path(src).relative_to(pathlib.Path(src).parents[0]))
                if '.network.d/' in src:dst='/etc/systemd/network/'+name+'.d/'+pathlib.Path(src).name
                self.put(dst,new.encode())
        target='/etc/systemd/network/'+name+'.d/zzzz-mist-ipv6.conf'
        self.put(target,('[Network]\nIPv6AcceptRA=no\nLinkLocalAddressing='+('ipv4' if ll else 'no')+'\nDHCP='+('ipv4' if dhcp else 'no')+'\n').encode())
        if iface:self.actions.append({'type':'networkd','iface':iface,'source':name})
    def nm(self):
        paths={r['path'] for r in self.nm_catalog.values() if r['path']}
        for folder in ('/usr/lib/NetworkManager/system-connections','/etc/NetworkManager/system-connections'):
            paths.update('/'+str(q.relative_to(ROOT)) for q in p(folder).glob('*') if q.is_file() and not q.name.startswith('.') and not q.name.endswith(('~','.bak','.tmp','.swp')))
        for q in p('/etc/sysconfig/network-scripts').glob('ifcfg-*'):
            if q.is_file() and any(r['path']=='/'+str(q.relative_to(ROOT)) for r in self.nm_catalog.values()):paths.add('/'+str(q.relative_to(ROOT)))
        uuids=[];before_methods={}
        for path in sorted(paths):
            if pathlib.Path(path).name.startswith('netplan-'):continue
            if path.startswith('/run/'):
                # External observation profiles (e.g. Docker bridges) are not writers.
                records=[r for r in self.nm_catalog.values() if r['path']==path]
                if records and all(r['flags']&8 for r in records):continue
                raise Stop('runtime NM profile has no durable provisioning owner: '+path)
            rec=self.watch(path);text=base64.b64decode(rec['data']).decode()
            need(not re.search(r'^\s*(remote|endpoint)\s*=\s*\[?[0-9a-fA-F]*:',text,re.M),'IPv6 VPN endpoint in '+path)
            if path.startswith('/etc/sysconfig/network-scripts/ifcfg-'):
                changed=strip_ifcfg(text);dst=path
                for kind in ('route6-','rule6-'):
                    side=str(pathlib.PurePosixPath(path).with_name(kind+pathlib.PurePosixPath(path).name[6:]))
                    record=self.watch(side)
                    if record['exists']:self.put(side,b'# IPv6 disabled by MIST host policy.\n')
            else:
                if not any(sec=='connection' for sec,lines in unit_sections(text)):continue
                need(path.startswith(('/etc/NetworkManager/system-connections/','/usr/lib/NetworkManager/system-connections/')),'NM profile location has no supported durable writer: '+path)
                changed=strip_nm_keyfile(text);dst='/etc/NetworkManager/system-connections/'+pathlib.Path(path).name
            self.put(dst,changed.encode(),rec['mode'] if dst==path else 0o600)
            matches_uuid=[u for u,r in self.nm_catalog.items() if r['path']==path]
            for ident in matches_uuid:
                uuids.append(ident);self.nm_paths[ident]=dst;before_methods[ident]=self.nm_catalog[ident]['method']
        self.actions.append({'type':'nm','uuids':uuids,'before_methods':before_methods})
    def policy(self):
        effective={}
        for folder in ('/usr/lib/sysctl.d','/lib/sysctl.d','/run/sysctl.d','/etc/sysctl.d'):
            for q in p(folder).glob('*.conf'):effective[q.name]='/'+str(q.relative_to(ROOT))
        sources=list(sorted(effective.values()))
        if p('/etc/sysctl.conf').exists():sources.append('/etc/sysctl.conf')
        done=set()
        for source in sources:
            q=p(source);path=source
            if q.is_symlink():
                st=q.lstat();need(st.st_uid==0,'unsafe sysctl symlink')
                self.watched[source]=dict(path=source,exists=True,symlink=os.readlink(q),uid=st.st_uid,gid=st.st_gid,mtime=st.st_mtime_ns)
                target=q.resolve()
                if target==p('/dev/null'):continue
                need(target.is_relative_to(ROOT) if hasattr(target,'is_relative_to') else str(target).startswith(str(ROOT)),'sysctl symlink escapes root')
                path='/'+str(target.relative_to(ROOT))
                need(path.startswith('/etc/') and (path=='/etc/sysctl.conf' or path.startswith('/etc/sysctl.d/')),'sysctl symlink points to an unidentified writer: '+source)
            if path in done:continue
            done.add(path);r=self.watch(path);text=base64.b64decode(r['data']).decode();out=[]
            for line in text.splitlines(keepends=True):
                m=re.match(r'(\s*-?net[./]ipv6[./]conf[./].*[./]disable_ipv6\s*=\s*)([^#;\s]+)(.*?)(\n?)$',line)
                if m:
                    need(m[2] in ('0','1'),'invalid disable_ipv6 setting in '+source)
                    line=m[1]+'1'+m[3]+m[4]
                out.append(line)
            changed=''.join(out)
            if changed!=text:
                need(not path.startswith('/run/'),'runtime sysctl override has unknown durable writer: '+source)
                dst=path if path.startswith('/etc/') else '/etc/sysctl.d/'+pathlib.Path(source).name
                self.put(dst,changed.encode())
        policy='# MIST IPv6 host policy; explicit conflicting entries are sanitized at their owner.\nnet/ipv6/conf/all/disable_ipv6 = 1\nnet/ipv6/conf/default/disable_ipv6 = 1\nnet/ipv6/conf/*/disable_ipv6 = 1\n'
        self.put(POLICY,policy.encode(),self.watch(POLICY).get('mode',0o644))
    def interfaces(self):
        seen=set()
        def visit(path):
            if path in seen:return
            seen.add(path);rec=self.watch(path)
            if not rec['exists']:return
            text=base64.b64decode(rec['data']).decode()
            need(not re.search(r'^\s*(mapping|rename)\b',text,re.M),'ifupdown dynamic mapping/rename must be resolved before editing')
            for line in text.splitlines():
                fields=shlex.split(line,comments=True)
                if not fields or fields[0] not in ('source','source-directory'):continue
                for pattern in fields[1:]:
                    need(not any(x in pattern for x in ('$','`',';')),'shell-expanded interfaces include')
                    root=pathlib.Path(path).parent
                    pat=pattern if pattern.startswith('/') else str(root/pattern)
                    for q in sorted(ROOT.glob(pat.lstrip('/'))):
                        items=sorted(q.iterdir()) if fields[0]=='source-directory' and q.is_dir() else [q]
                        for item in items:
                            if item.is_file() and (fields[0]!='source-directory' or re.fullmatch('[A-Za-z0-9_-]+',item.name)):visit('/'+str(item.relative_to(ROOT)))
        visit('/etc/network/interfaces')
        texts={path:base64.b64decode(self.watched[path]['data']).decode() for path in seen if self.watched[path]['exists']}
        names={n for text in texts.values() for n in re.findall(r'^\s*iface\s+(\S+)\s+inet\s+',text,re.M)}
        module=p('/usr/share/ifupdown2/addons/address.py')
        ifup2=module.exists();disable_attr=ifup2 and 'disable-ipv6' in module.read_text()
        for path,text in texts.items():
            generated='cloud-init' in path or 'cloud-init' in text[:700].lower()
            # A provisioning renderer cannot carry ifupdown2-only attributes.
            # Its durable IPv6-free owner input + native post-up hook below
            # enforce the policy without re-editing its output after each boot.
            self.put(path,strip_interfaces(text,names,ifup2,disable_attr,not generated).encode())
        hook='/etc/network/if-up.d/zzzz-mist-ipv6'
        payload=b'#!/bin/sh\n# MIST IPv6 host policy; native ifupdown post-up hook.\nset -eu\ndev=${IFACE%%:*}\ncase "$dev" in all|default|.|..|*/*) exit 0;; esac\n[ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net)" ] || exit 0\nq=/proc/sys/net/ipv6/conf/$dev/disable_ipv6\n[ ! -f "$q" ] || printf 1 > "$q"\n'
        rec=self.watch(hook)
        need(not rec['exists'] or b'# MIST IPv6 host policy;' in base64.b64decode(rec['data']),'native IPv6 hook path belongs to another owner')
        self.put(hook,payload,rec.get('mode',0o755)|0o100)
        self.actions.append({'type':'ifupdown'})
    def cloud_other_regeneration(self,net):
        owners=set(self.owners.values());kinds=[]
        if 'ifupdown' in owners:kinds.append('eni')
        if 'networkd' in owners:kinds.append('networkd')
        if 'NetworkManager' in owners:kinds.append('network-manager')
        distro={}
        for line in p('/etc/os-release').read_text().splitlines():
            if '=' in line:
                k,v=line.split('=',1);distro[k]=v.strip('"')
        for kind in kinds:
            with tempfile.TemporaryDirectory(prefix='mist-cloud-') as folder:
                root=pathlib.Path(folder);source=root/'network.yaml';source.write_bytes(yaml_dump(net));out=root/'render'
                run(['cloud-init','devel','net-convert','--network-data',str(source),'--kind','yaml','--directory',str(out),'--distro',distro.get('ID',''),'--output-kind',kind])
                for q in out.rglob('*'):
                    if not q.is_file():continue
                    path='/'+str(q.relative_to(out));original=self.watched.get(path)
                    if original is None or not original['exists']:continue
                    if 'cloud-init' not in path and b'cloud-init' not in base64.b64decode(original['data'])[:700].lower():continue
                    self.changes.get(path,original)['owner_regeneration']={'boot':p('/proc/sys/kernel/random/boot_id').read_text().strip(),'sha256':[sha(q.read_bytes())]}

    def cloud(self):
        # Persist IPv6 intent at the provisioning owner; never disable cloud-init.
        if p('/etc/cloud/cloud-init.disabled').exists() or not shutil.which('cloud-init'):return
        sources=[p('/etc/cloud/cloud.cfg')]+sorted(p('/etc/cloud/cloud.cfg.d').glob('*.cfg'))
        cfg={}
        for q in sources:
            if q.exists():
                path='/'+str(q.relative_to(ROOT));self.watch(path);doc=cloud_network(q.read_text())
                cfg.update(doc)
        net=cfg.get('network',{})
        if net.get('config')=='disabled':return
        cmd=p('/proc/cmdline').read_text() if p('/proc/cmdline').exists() else ''
        if 'network-config=disabled' in cmd or 'cloud-init=disabled' in cmd:return
        need('network-config=' not in cmd or 'network-config=disabled' in cmd,'kernel network-config overrides cloud-init system config')
        cached=p('/var/lib/cloud/instance/network-config.json')
        if cached.exists() and net.get('version') not in (1,2):net=json.loads(cached.read_text())
        if self.netplan_before is not None:
            cloud_sources=[r for path,r in self.watched.items() if path.startswith(('/etc/netplan/','/lib/netplan/')) and r['exists'] and ('cloud-init' in pathlib.Path(path).name or 'cloud-init' in base64.b64decode(r['data']).decode(errors='replace')[:700].lower())]
            if len(cloud_sources)==1:
                # The live owner file is authoritative if IPv4 was deliberately
                # changed after boot; the old instance cache must not undo it.
                net=yaml_load(base64.b64decode(cloud_sources[0]['data']).decode())['network']
            elif len(cloud_sources)>1:raise Stop('multiple cloud-init Netplan owner files require their provisioning source to be resolved')
        if net.get('version')==2:
            desired=strip_netplan({'network':net})['network']
            target='/etc/cloud/cloud.cfg.d/zzzz-mist-ipv6.cfg';rec=self.watch(target)
            if not rec['exists'] or yaml_load(base64.b64decode(rec['data']).decode())!={'network':desired}:
                self.put(target,yaml_dump({'network':desired}))
            if self.netplan_before is not None and len(cloud_sources)==1:
                path=cloud_sources[0]['path']
                marker={'boot':p('/proc/sys/kernel/random/boot_id').read_text().strip(),'sha256':cloud_netplan_renderings(desired)}
                # The provisioning inputs remain strict read dependencies. Only
                # this known generated output may acquire an exact native form
                # and new mtime after a different boot; contents/mode/ACLs stay
                # protected and arbitrary edits still block restoration.
                self.changes.get(path,self.watched[path])['owner_regeneration']=marker
        elif net.get('version')==1:
            d=copy.deepcopy(net)
            for item in d.get('config',[]):
                if item.get('type')=='nameserver':need(not any(is6(x) for x in item.get('address',[])),'IPv6 DNS from cloud-init')
                if 'subnets' in item:item['subnets']=[x for x in item['subnets'] if x.get('type') not in ('ipv6_dhcpv6-stateful','ipv6_dhcpv6-stateless','ipv6_slaac') and not is6(x.get('address',''))]
            target='/etc/cloud/cloud.cfg.d/zzzz-mist-ipv6.cfg';rec=self.watch(target)
            if not rec['exists'] or yaml_load(base64.b64decode(rec['data']).decode())!={'network':d}:
                self.put(target,yaml_dump({'network':d}))
        elif p('/etc/cloud/cloud-init.disabled').exists():return
        else:
            # No active owner data: do not invent a DHCP provisioning config.
            need(not any('cloud-init' in base64.b64decode(r.get('data','')).decode(errors='replace').lower() for r in self.watched.values() if r['path'].startswith(('/etc/netplan/','/etc/network/'))),'cloud-init generated config exists but owner network data is missing')
        if self.netplan_before is None and net.get('version') in (1,2):self.cloud_other_regeneration(desired if net['version']==2 else d)

# Runtime and transactions follow below.
def nl_rule6(op=34,payload=None,family=socket.AF_INET6):
    # Linux rtnetlink UAPI: preserve every FIB selector, including port/UID rules.
    seq=int(time.monotonic()*1000000)&0xffffffff
    data=payload if payload is not None else struct.pack('=BBBBBBBBI',family,0,0,0,0,0,0,0,0)
    need(len(data)>=12 and data[0]==family,'invalid IP rule payload')
    flags=0x301 if op==34 else (0x605 if op==32 else 0x5)
    with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE) as sock:
        sock.bind((0,0));sock.settimeout(5);sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024*1024)
        sock.send(struct.pack('=IHHII',16+len(data),op,flags,seq,0)+data);out=[]
        while True:
            packet=sock.recv(1024*1024);offset=0
            while offset+16<=len(packet):
                size,kind,mflags,mseq,pid=struct.unpack_from('=IHHII',packet,offset)
                need(size>=16 and offset+size<=len(packet),'truncated IP rule reply')
                body=packet[offset+16:offset+size];offset+=(size+3)&~3
                if mseq!=seq:continue
                need(not mflags&0x10,'concurrent change interrupted IP rule dump')
                if kind==2:
                    need(len(body)>=4,'invalid netlink ACK');error=struct.unpack_from('=i',body)[0]
                    if error:raise OSError(-error,os.strerror(-error))
                    if op!=34:return []
                elif kind==3:return out
                elif kind==32:
                    need(body and body[0]==family,'unexpected family in IP rule dump');out.append(base64.b64encode(body).decode())
def rule_priority(encoded):
    body=base64.b64decode(encoded);need(len(body)>=12 and body[0] in (socket.AF_INET,socket.AF_INET6),'invalid backed-up IP rule')
    offset=12
    while offset+4<=len(body):
        size,kind=struct.unpack_from('=HH',body,offset);need(size>=4 and offset+size<=len(body),'invalid rule attribute')
        if kind&0x3fff==6:
            need(size>=8,'invalid rule priority');return struct.unpack_from('=I',body,offset+4)[0]
        offset+=(size+3)&~3
    return 0
def restore_rules6(want,family=socket.AF_INET6):
    have=nl_rule6(family=family);groups={}
    for v in want:groups.setdefault(rule_priority(v),[]).append(v)
    current={}
    for v in have:current.setdefault(rule_priority(v),[]).append(v)
    need(not (set(current)-set(groups)),'concurrent IP rule priorities; foreign rules retained')
    for priority,values in groups.items():
        got=current.get(priority,[])
        need(not (collections.Counter(got)-collections.Counter(values)),'concurrent IP rule modification at priority '+str(priority))
    for priority,values in groups.items():
        got=current.get(priority,[])
        if got==values:continue
        if got==values[:len(got)]:missing=values[len(got):]
        else:
            for v in got:nl_rule6(33,base64.b64decode(v),family)
            missing=values
        for v in missing:nl_rule6(32,base64.b64decode(v),family)
    need(nl_rule6(family=family)==want,'IP rule restoration differs; foreign rules retained')

def knobs():
    return {q.name:{k:int((q/k).read_text()) for k in KNOBS if (q/k).exists()} for q in sorted(p('/proc/sys/net/ipv6/conf').iterdir())}
def set_knob(name,key,value):
    need('/' not in name and name not in ('.','..'),'invalid interface name')
    q=p('/proc/sys/net/ipv6/conf')/name/key
    need(q.exists(),'interface disappeared: '+name)
    q.write_text(str(value))
def resolved_map(text):
    if isinstance(text,dict):return text
    out={}
    for line in text.splitlines():
        m=re.match(r'(?:Global|Link \d+ \((.*?)\)):\s*(.*)$',line.strip())
        need(m,'unrecognised resolvectl output: '+line)
        out[m[1] or 'global']=m[2].split()
    return out
def resolver_normalized(r):
    r=copy.deepcopy(r)
    for k in ('resolved_dns','resolved_domains'):
        if k in r:r[k]=resolved_map(r[k])
    return r
def resolver():
    q=p('/etc/resolv.conf');out={'link':os.readlink(q) if q.is_symlink() else None,'data':base64.b64encode(q.read_bytes()).decode()}
    if active('systemd-resolved'):
        out['resolved_dns']=resolved_map(run(['resolvectl','dns']).stdout.strip())
        out['resolved_domains']=resolved_map(run(['resolvectl','domain']).stdout.strip())
    return out
def runtime():
    return {'knobs':knobs(),'addr4':jr('ip','-j','-4','address','show'),'routes4':jr('ip','-j','-4','route','show','table','all'),
        'rules4':jr('ip','-j','-4','rule','show'),'rules4_raw':nl_rule6(family=socket.AF_INET),'addr6':jr('ip','-j','-6','address','show'),'routes6':jr('ip','-j','-6','route','show','table','all'),
        'rules6':jr('ip','-j','-6','rule','show'),'rules6_raw':nl_rule6(),'links':jr('ip','-j','-d','link','show'),'resolver':resolver(),
        'promote':{q.name:int((q/'promote_secondaries').read_text()) for q in p('/proc/sys/net/ipv4/conf').iterdir()}}
def addr_set(rows,family):
    return sorted((x['ifname'],a['local'],a['prefixlen'],a.get('scope'),a.get('broadcast'),a.get('label'),tuple(sorted(a.get('flags',[]))),tuple((k,a.get(k,False)) for k in ('dynamic','secondary','noprefixroute','mngtmpaddr','temporary')),a.get('metric')) for x in rows for a in x.get('addr_info',[]) if a['family']==family)
def route_set(rows):
    # Only lease/DHCP countdown fields are volatile; never ignore an address or route.
    return sorted(canonical(dict({k:v for k,v in r.items() if k not in ('expires','cache','used','age')},_has_expiry='expires' in r)).decode() for r in rows)
def link_set(rows,owners=None):return sorted((x['ifname'],x.get('mtu'),x.get('master'),x.get('linkinfo',{}).get('info_kind'),None if (owners or {}).get(x['ifname'],'').startswith('unmanaged ') else x.get('address')) for x in rows)
def verify4(before,now):
    need(addr_set(before['addr4'],'inet')==addr_set(now['addr4'],'inet'),'IPv4 address/prefix changed')
    need(route_set(before['routes4'])==route_set(now['routes4']),'IPv4 route changed or disappeared')
    need(before['rules4']==now['rules4'],'IPv4 policy rules changed')
    need(link_set(before['links'],before.get('owners'))==link_set(now['links'],before.get('owners')),'interface topology or MTU changed')
    need(resolver_normalized(before['resolver'])==resolver_normalized(now['resolver']),'DNS configuration or resolv.conf link changed')
    need(before['promote']==now['promote'],'IPv4 promote_secondaries changed')
def wait4(before,seconds=30):
    deadline=time.monotonic()+seconds;error=None
    while True:
        now=runtime()
        try:verify4(before,now);return now
        except Stop as e:error=e
        if time.monotonic()>=deadline:raise error
        time.sleep(0.5)
def verify_off(before):
    now=wait4(before)
    need(all(v.get('disable_ipv6')==1 for v in now['knobs'].values()),'manager re-enabled IPv6')
    need(not addr_set(now['addr6'],'inet6') and not now['routes6'],'IPv6 address/route remains')
    if before.get('dns_probe_ok',True):run(['getent','ahostsv4','example.com'],timeout=12)
    if before.get('chrony_ipv4_monitor'):chrony_ipv4_sources()
    return now
def transaction_error(code, message, **details):
    error = Stop(message)
    error.details = dict(error_code=code, **details)
    raise error


def tcp_peers(text):
    peers=[]
    for l in text.splitlines():
        f=l.split();need(len(f)==4,'unrecognised ss established format (expected Recv-Q Send-Q Local Peer)')
        a,port=f[3].rsplit(':',1);need(port.isdecimal(),'invalid TCP peer')
        ip=ipaddress.ip_address(a.strip('[]').split('%')[0])
        if ip.version==6 and ip.ipv4_mapped is None:peers.append(f[3])
    return peers
def udp_peers(text):
    peers=[]
    for line in text.splitlines():
        fields=line.split()
        if not fields or fields[0]!='ESTAB':continue
        need(len(fields)==5,'unrecognised ss UDP established format')
        host,port=fields[4].rsplit(':',1);need(port.isdecimal(),'invalid UDP peer')
        address=ipaddress.ip_address(host.strip('[]').split('%')[0])
        if address.version==6 and address.ipv4_mapped is None:peers.append(fields[4])
    return peers

def chrony_ipv4_sources():
    # Read-only monitoring over the exact IPv4 socket that will remain usable.
    need(shutil.which('chronyc'),'chronyc required to verify the chronyd IPv4 fallback')
    text=run(['chronyc','-n','-c','-h','127.0.0.1','sources'],timeout=8).stdout
    selected=False
    for line in text.splitlines():
        fields=line.split(',')
        need(len(fields)==10 and fields[0] in ('^','=','#') and fields[1] in ('*','+','-','?','x','~'),'unrecognised chronyc sources CSV format')
        if fields[0]=='#':continue
        try:address=ipaddress.ip_address(fields[2])
        except ValueError:raise Stop('chronyd time source has no verified IP address: '+fields[2])
        need(address.version==4,'chronyd has an IPv6 time source: '+fields[2])
        selected=selected or fields[1]=='*'
    need(selected,'chronyd has no selected IPv4 time source')

def chrony_loopback_pair(line,listeners4):
    # No generic loopback/port exemption: identify the daemon and its same-PID pair.
    fields=line.split()
    if fields[0]!='udp' or fields[4]!='[::1]:323':return False
    owners=set(re.findall(r'\("([^"]+)",pid=(\d+),fd=\d+\)',line))
    if len(owners)!=1:return False
    name,pid=next(iter(owners))
    if name!='chronyd':return False
    paired=any(len(v.split())>=6 and v.split()[0]=='udp' and v.split()[4]=='127.0.0.1:323' and set(re.findall(r'\("([^"]+)",pid=(\d+),fd=\d+\)',v))==owners for v in listeners4)
    if not paired:return False
    try:executable=os.readlink(p('/proc/'+pid+'/exe'))
    except OSError:raise Stop('cannot identify the executable of the chronyd loopback listener')
    return pathlib.Path(executable).name=='chronyd'

def dependencies(before):
    wireguard_ports=set()
    for link in before['links']:
        if link.get('linkinfo',{}).get('info_kind')!='wireguard':continue
        name=link['ifname'];need(shutil.which('wg'),'wg required to inspect the active WireGuard underlay on '+name)
        for line in run(['wg','show',name,'endpoints']).stdout.splitlines():
            fields=line.split();need(len(fields)==2,'unrecognised WireGuard endpoint format')
            need(not fields[1].startswith('['),'IPv6 WireGuard underlay on '+name)
        port=run(['wg','show',name,'listen-port']).stdout.strip()
        if port.isdecimal() and int(port):wireguard_ports.add(port)
    need(not tcp_peers(run(['ss','-6','-Htn','state','established']).stdout),'established IPv6 TCP connection is in use')
    need(not udp_peers(run(['ss','-6','-Huan']).stdout),'connected IPv6 UDP socket is in use')
    docker_ports=set()
    if shutil.which('docker') and active('docker'):
        ids=run(['docker','ps','-q']).stdout.split()
        if ids:
            for line in run(['docker','inspect','--format','{{json .NetworkSettings.Ports}}',*ids]).stdout.splitlines():
                for container_port,bindings in (json.loads(line) or {}).items():
                    binds=bindings or []
                    for binding in binds:
                        if binding.get('HostIp')=='::' and any(v.get('HostPort')==binding.get('HostPort') and v.get('HostIp') and not is6(v['HostIp']) for v in binds):docker_ports.add((container_port.split('/')[-1],binding['HostPort']))
    listeners=run(['ss','-6','-H','-lntu','-e','-p']).stdout
    listeners4=run(['ss','-4','-H','-lntu','-e','-p']).stdout.splitlines()
    for l in listeners.splitlines():
        f=l.split();need(len(f)>=6,'unrecognised ss listener format')
        local=f[4];host=local.rsplit(':',1)[0].strip('[]').split('%')[0]
        if local.rsplit(':',1)[1]=='546' and any(x in l for x in ('\"systemd-network\"','\"NetworkManager\"')):continue
        if host not in ('*','::'):
            address=ipaddress.ip_address(host)
            if address.version==6 and address.ipv4_mapped is not None:continue
            if chrony_loopback_pair(l,listeners4):
                chrony_ipv4_sources();before['chrony_ipv4_monitor']=True;continue
            raise Stop('explicit IPv6 listener dependency: '+local)
        if 'v6only:1' in l:
            port=local.rsplit(':',1)[1];pids=set(re.findall(r'pid=(\d+)',l))
            paired=any(len(v.split())>=6 and v.split()[0]==f[0] and v.split()[4].rsplit(':',1)[1]==port and pids.intersection(re.findall(r'pid=(\d+)',v)) for v in listeners4)
            paired=paired or (not pids and f[0]=='udp' and port in wireguard_ports and any(len(v.split())>=6 and v.split()[0]=='udp' and v.split()[4].rsplit(':',1)[1]==port for v in listeners4))
            paired=paired or ('"docker-proxy"' in l and (f[0],port) in docker_ports)
            need(paired,'IPv6-only listener has no IPv4 listener in the same process: '+local)
    for x in before['links']:
        data=x.get('linkinfo',{}).get('info_data',{})
        need(not any(is6(data.get(k,'')) for k in ('local','remote','group')),'IPv6 tunnel/overlay underlay on '+x['ifname'])
    if shutil.which('docker') and active('docker'):
        ids=run(['docker','network','ls','-q']).stdout.split()
        if ids:
            networks=jr('docker','network','inspect',*ids)
            need(not any(n.get('EnableIPv6') for n in networks),'Docker network explicitly enables IPv6; container configuration is outside scope')
    for q in p('/proc/sys/net/ipv6/conf').iterdir():
        if q.name in ('all','default'):continue
        if (q/'proxy_ndp').exists():need((q/'proxy_ndp').read_text().strip()=='0','IPv6 proxy NDP on '+q.name)
    text=base64.b64decode(before['resolver']['data']).decode()
    for l in text.splitlines():
        f=l.split()
        if len(f)>1 and f[0]=='nameserver':need(not is6(f[1]),'IPv6 resolver endpoint in resolv.conf')
    for values in resolved_map(before['resolver'].get('resolved_dns',{})).values():
        need(not any(is6(v) for v in values),'IPv6 upstream DNS in systemd-resolved')

def discover():
    for c in ('ip','ss','systemctl','getent'):need(shutil.which(c),'missing command: '+c)
    need(p('/run/systemd/system').is_dir(),'systemd is required for an SSH-independent and reboot-surviving rollback')
    need(os.stat('/proc/self/ns/net').st_ino==os.stat('/proc/1/ns/net').st_ino,'run in the host PID 1 network namespace; independent rollback uses that namespace')
    before=runtime();before['dns_probe_ok']=run(['getent','ahostsv4','example.com'],False,timeout=12).returncode==0;before['captured_at']=time.time();dependencies(before);pl=Plan();netplan=False;nm=False;eni=False
    eni_result=run(['ifquery','--list'],False) if shutil.which('ifquery') else None
    eni_names=set(eni_result.stdout.split()) if eni_result and not eni_result.returncode else set()
    if eni_result and eni_result.returncode and p('/etc/network/interfaces').exists():
        relevant=any(re.search(r'^\s*iface\s+(?!lo(?:\s|$))',q.read_text(),re.M) for q in [p('/etc/network/interfaces')]+list(p('/etc/network/interfaces.d').glob('*')) if q.is_file())
        need(not relevant,'ifquery failed on configured interfaces: '+eni_result.stderr[-300:])
    if shutil.which('nmcli') and active('NetworkManager'):
        need(shutil.which('busctl'),'busctl required to identify the actual NM settings owner')
        pl.nm_catalog=nm_catalog()
        v=run(['nmcli','--version']).stdout;parts=re.search(r'(\d+)\.(\d+)',v)
        need(parts and tuple(map(int,parts.groups()))>=(1,20),'NetworkManager >=1.20 required for native ipv6.method=disabled')
    eni_active=active('networking')
    primary={r.get('dev') for r in before['routes4'] if r.get('dst')=='default'}
    for x in before['links']:
        name=x['ifname']
        if name=='lo':continue
        nm_uuid='';nf=''
        if shutil.which('nmcli') and active('NetworkManager'):
            s=run(['nmcli','-g','GENERAL.CON-UUID','device','show',name],False).stdout.strip()
            if re.fullmatch('[0-9a-fA-F-]{36}',s):nm_uuid=s
        if active('systemd-networkd'):
            status=run(['networkctl','status','--no-pager',name],False).stdout
            m=re.search(r'Network File:\s+(\S+)',status)
            if m and m[1]!='n/a':nf=m[1]
        if nm_uuid and pl.nm_catalog.get(nm_uuid,{}).get('flags',0)&8:nm_uuid=''
        if (nf and nm_uuid) or (eni_active and name in eni_names and (nf or nm_uuid)):raise Stop('multiple enabled configuration owners claim '+name+'; resolve competing networkd/NM/ifupdown writers before IPv6 changes')
        if nf:
            if pathlib.Path(nf).name.startswith('10-netplan-'):netplan=True;pl.owners[name]='netplan/networkd'
            else:pl.networkd(nf,name);pl.owners[name]='networkd'
        elif nm_uuid:
            profile=pl.nm_catalog.get(nm_uuid);need(profile,'active NM UUID absent from settings catalog')
            filename=pathlib.Path(profile['path']).name
            need(profile['path'],'active NM profile is unsaved; no durable owner for '+name)
            if filename.startswith('netplan-'):netplan=True;pl.owners[name]='netplan/NetworkManager';pl.nm_devices[name]=nm_uuid
            else:nm=True;pl.owners[name]='NetworkManager'
        elif name in eni_names:eni=True;pl.owners[name]='ifupdown'
        else:
            need(name not in primary,'no persistent settings owner for SSH/default-route interface '+name)
            pl.owners[name]='unmanaged host link (kernel policy only)'
    if netplan:pl.netplan()
    processed={a['source'] for a in pl.actions if a['type']=='networkd'}
    for unit in p('/etc/systemd/network').glob('*.network'):
        if unit.name not in processed and not unit.name.startswith('10-netplan-'):pl.networkd('/'+str(unit.relative_to(ROOT)),None)
    if nm or pl.nm_catalog:pl.nm()
    if eni or (eni_result and not eni_result.returncode and eni_names-{'lo'}):pl.interfaces()
    pl.cloud()
    pl.policy()
    pl.inventory=pl.watch_globs()
    for path in pl.inventory:pl.watch(path)
    selected=[]
    for a in pl.actions:
        if a['type']=='netplan' and not any(x.startswith('/etc/netplan/') for x in pl.changes):continue
        if a['type']=='networkd' and not any(x=='/etc/systemd/network/'+a['source'] or x.startswith('/etc/systemd/network/'+a['source']+'.d/') for x in pl.changes):continue
        if a['type']=='nm':
            a['uuids']=[u for u in a['uuids'] if pl.nm_paths.get(u) in pl.changes]
            if not a['uuids']:continue
        if a['type']=='ifupdown' and not any(x.startswith('/etc/network/') for x in pl.changes):continue
        selected.append(a)
    pl.actions=selected
    before['owners']=pl.owners
    return pl,before

def apply_actions(actions):
    seen=set()
    for a in actions:
        key=canonical(a)
        if key in seen:continue
        seen.add(key);t=a['type']
        if t=='netplan':
            if 'networkd_ifaces' not in a:run(['netplan','apply'],timeout=60) # legacy backup adapter
            else:
                run(['netplan','generate'],timeout=30)
                if a['networkd_ifaces']:
                    run(['networkctl','reload']);run(['networkctl','reconfigure','--',*a['networkd_ifaces']],timeout=45)
                if a.get('nm_devices'):
                    run(['nmcli','connection','reload'])
                    for name in a['nm_devices']:run(['nmcli','device','reapply',name],timeout=35)
        elif t=='networkd':run(['networkctl','reload']);run(['networkctl','reconfigure',a['iface']],timeout=45)
        elif t=='nm':
            run(['nmcli','connection','reload'])
            for line in run(['nmcli','-t','-f','UUID,DEVICE','connection','show','--active']).stdout.splitlines():
                ident,name=line.split(':',1)
                if ident in a.get('uuids',[]) and name and name!='--':run(['nmcli','device','reapply',name],timeout=35)
        # ifupdown config changes are IPv6-only; sysctl applies them without cycling IPv4/DHCP.
        elif t=='ifupdown':run(['ifquery','--list'])

def verify_nm(actions,restoring=False):
    for action in actions:
        if action['type']!='nm':continue
        for ident in action.get('uuids',[]):
            expected=action.get('before_methods',{}).get(ident,'') if restoring else 'disabled'
            if expected:need(run(['nmcli','-g','ipv6.method','connection','show',ident]).stdout.strip()==expected,'NM did not load expected IPv6 method for '+ident)

def validate_plan(pl):
    if p('/sys/fs/selinux/enforce').exists():
        default_selinux_label(p(STATE),stat.S_IFDIR|0o700)
        for path,record in pl.changes.items():
            if not pl.watched[path]['exists']:default_selinux_label(p(path),stat.S_IFREG|record['mode'])
    if pl.netplan_before is not None and any(x.startswith('/etc/netplan/') for x in pl.changes):
        with tempfile.TemporaryDirectory(prefix='mist-netplan-') as tmp:
            root=pathlib.Path(tmp)
            for path,r in pl.watched.items():
                if '/netplan/' in path and path.endswith('.yaml') and r['exists']:
                    q=root/path.lstrip('/');q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(base64.b64decode(r['data']));q.chmod(0o600)
            for path,r in pl.changes.items():
                if '/netplan/' in path:
                    q=root/path.lstrip('/');q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(base64.b64decode(r['data']));q.chmod(0o600)
            run(['netplan','generate','--root-dir',tmp],timeout=30)

def read_status(d):
    valid=[]
    for name in ('status.json','status-mirror.json'):
        try:
            value=json.loads((d/name).read_text());digest=value.pop('digest',None)
            need(digest is None or sha(canonical(value))==digest,'status digest mismatch');need('status' in value,'missing status')
            valid.append(value)
        except (OSError,ValueError,Stop):pass
    return max(valid,key=lambda v:v.get('utc',0)) if valid else {'status':'unknown','reason':'status copies missing or invalid'}
def status_write(d,status,**kw):
    value=dict(status=status,utc=time.time(),**kw);value['digest']=sha(canonical(value));data=canonical(value)
    atomic(d/'status.json',data);atomic(d/'status-mirror.json',data)
def trusted_dir(d):
    base=p(STATE);need(not base.is_symlink(),'backup root is a symlink')
    st=base.stat();need(st.st_uid==0 and stat.S_ISDIR(st.st_mode) and st.st_mode&0o077==0,'unsafe backup root permissions')
    d=pathlib.Path(d);need(d.is_absolute() and not d.is_symlink() and d.resolve().parent==p(STATE).resolve(),'invalid transaction path')
    st=d.stat();need(st.st_uid==0 and st.st_mode&0o077==0,'unsafe transaction permissions')
    return d
def load(d):
    d=trusted_dir(d)
    errors=[]
    for name in ('backup','backup-mirror'):
        try:
            b=(d/(name+'.json')).read_bytes();expected=(d/(name+'.sha256')).read_text().strip();need(sha(b)==expected,'backup digest mismatch')
            s=json.loads(b);need(s['version'] in ('2.1','2.2',VERSION),'backup version mismatch')
            need(s['machine']==p('/etc/machine-id').read_text().strip(),'backup belongs to a different machine')
            need(sha((d/'tool.sh').read_bytes())==s['tool_sha'],'backup tool digest mismatch')
            for path,r in s['files'].items():
                need((path=='/etc/sysctl.conf' or path.startswith(('/etc/netplan/','/etc/systemd/network/','/etc/NetworkManager/system-connections/','/etc/network/','/etc/cloud/','/etc/sysctl.d/','/etc/sysconfig/network-scripts/'))) and '..' not in pathlib.Path(path).parts,'unsafe restore target')
                if r['exists']:need(sha(base64.b64decode(r['data']))==r['sha'],'backup file digest mismatch: '+path)
            return d,s
        except (OSError,ValueError,KeyError,Stop) as e:errors.append(str(e))
    raise Stop('both backup copies invalid: '+'; '.join(errors))
def save_backup(d,value):
    data=canonical(value)
    for name in ('backup','backup-mirror'):
        atomic(d/(name+'.json'),data);atomic(d/(name+'.sha256'),sha(data).encode())

def unit_paths(d):
    unit='mist-ipv6-'+d.name
    return unit,p('/etc/systemd/system/'+unit+'.service'),p('/etc/systemd/system/'+unit+'.timer')
def arm(d,seconds):
    unit,service,timer=unit_paths(d);link=timer.parent/'timers.target.wants'/timer.name
    need(not service.exists() and not timer.exists() and not link.exists() and not link.is_symlink(),'rollback unit collision; foreign unit left unchanged')
    service_data=('[Unit]\nDescription=MIST IPv6 transaction rollback\nAfter=network.target\n[Service]\nType=oneshot\nExecStart=/bin/bash '+str(d/'tool.sh')+' --automatic-restore '+str(d)+'\nRestart=on-failure\nRestartSec=15s\nTimeoutStartSec=180s\n').encode()
    timer_data=('[Unit]\nDescription=MIST IPv6 confirmation deadline and boot rollback\n[Timer]\nOnActiveSec='+str(seconds)+'s\nAccuracySec=1s\n[Install]\nWantedBy=timers.target\n').encode()
    owned={}
    try:
        for q,data in ((service,service_data),(timer,timer_data)):
            atomic(q,data,0o644);owned[q.name]=sha(data)
        atomic(d/'watchdog.json',canonical(owned))
        run(['systemctl','daemon-reload']);run(['systemctl','enable','--now',unit+'.timer'])
        need(active(unit+'.timer'),'independent rollback timer did not start')
        for folder in (timer.parent,link.parent):
            fd=os.open(folder,os.O_RDONLY);os.fsync(fd);os.close(fd)
    except BaseException:
        if (d/'watchdog.json').exists():disarm(d)
        else:
            for q in (service,timer):
                if q.name in owned and q.exists() and sha(read_noatime(q))==owned[q.name]:q.unlink()
        raise
def disarm(d):
    unit,service,timer=unit_paths(d);record=d/'watchdog.json'
    owned=json.loads(record.read_text()) if record.exists() else {}
    for q in (service,timer):
        if q.exists():need(not q.is_symlink() and q.stat().st_uid==0 and sha(read_noatime(q))==owned.get(q.name),'watchdog unit was changed externally; left unchanged: '+str(q))
    link=timer.parent/'timers.target.wants'/timer.name
    if link.exists() or link.is_symlink():need(link.is_symlink() and link.resolve()==timer.resolve(),'foreign rollback enable link; left unchanged')
    run(['systemctl','disable','--now',unit+'.timer'],False)
    # The running rollback service must not stop itself.
    for q in (service,timer):
        if q.exists():q.unlink()
    run(['systemctl','daemon-reload'],False)

def race_check(pl,expected=None):
    need(pl.watch_globs()==pl.inventory,'configuration file set changed concurrently')
    for path,r in pl.watched.items():need(matches(path,r),'concurrent config modification: '+path)
def route_command(verb,r,family='-6',elapsed=0):
    cmd=['ip',family,'route',verb]
    if r.get('type','unicast')!='unicast':cmd.append(r['type'])
    cmd.append(r.get('dst','default'))
    for key,opt in (('gateway','via'),('dev','dev'),('table','table'),('protocol','proto'),('scope','scope'),('prefsrc','src'),('metric','metric'),('pref','pref')):
        if key in r:cmd += [opt,str(r[key])]
    if 'onlink' in r.get('flags',[]):cmd.append('onlink')
    if family=='-6' and verb!='del' and 'expires' in r:
        remaining=int(r['expires'])-int(elapsed);need(remaining>0,'IPv6 route lease expired; waiting for its native owner')
        cmd += ['expires',str(remaining)]
    for metrics in r.get('metrics',[]):
        for key,value in metrics.items():cmd += [key,str(value)]
    for nh in r.get('nexthops',[]):
        cmd.append('nexthop')
        for key,opt in (('gateway','via'),('dev','dev'),('weight','weight')):
            if key in nh:cmd += [opt,str(nh[key])]
    return cmd
def route_slot(r):
    scoped=r.get('type') in ('multicast','broadcast','local') or (r.get('protocol')=='kernel' and r.get('scope')=='link')
    return (r.get('table','main'),r.get('dst','default'),r.get('metric',0),r.get('type','unicast'),r.get('dev') if scoped else None)

def restore_runtime(before):
    # Add before deleting; never flush the management link.
    now=runtime();elapsed=max(0,time.time()-before.get('captured_at',time.time()))
    for family,field in (('inet','addr4'),('inet6','addr6')):
        flag='-4' if family=='inet' else '-6'
        have={(x['ifname'],a['local'],a['prefixlen']):a for x in now[field] for a in x.get('addr_info',[]) if a['family']==family}
        for x in before[field]:
            for a in x.get('addr_info',[]):
                if a['family']!=family:continue
                existing=have.get((x['ifname'],a['local'],a['prefixlen']))
                if existing and addr_set([{'ifname':x['ifname'],'addr_info':[existing]}],family)==addr_set([{'ifname':x['ifname'],'addr_info':[a]}],family):continue
                cmd=['ip',flag,'address','change' if existing else 'replace',a['local']+'/'+str(a['prefixlen']),'dev',x['ifname'],'scope',a['scope']]
                for k in ('broadcast','label','metric'):
                    if k in a:cmd += [k,str(a[k])]
                for k in ('noprefixroute','mngtmpaddr','nodad'):
                    if a.get(k):cmd.append(k)
                for k,opt in (('valid_life_time','valid_lft'),('preferred_life_time','preferred_lft')):
                    if isinstance(a.get(k),int) and a[k]<4294967295:
                        value=max(0,int(a[k]-elapsed))
                        need(k!='valid_life_time' or value>0,'address lease expired; waiting for native DHCP owner')
                        cmd += [opt,str(value)]
                run(cmd)
        oldroutes=before['routes4' if family=='inet' else 'routes6'];newroutes=jr('ip','-j',flag,'route','show','table','all')
        for r in oldroutes:
            if route_set([r])[0] not in route_set(newroutes):run(route_command('replace',r,flag,elapsed))
        for r in newroutes:
            if r.get('dev') and r['dev'] not in {x['ifname'] for x in before['links']}:continue
            if route_slot(r) not in {route_slot(w) for w in oldroutes}:run(route_command('del',r,flag))
        wanted={(x['ifname'],a['local'],a['prefixlen']) for x in before[field] for a in x.get('addr_info',[]) if a['family']==family}
        for dev,addr,prefix in set(have)-wanted:
            if dev not in {x['ifname'] for x in before['links']}:continue
            run(['ip',flag,'address','del',addr+'/'+str(prefix),'dev',dev])

def restore(d,automatic=False):
    d,s=load(d);status=read_status(d)['status']
    need(not automatic or status!='unknown','status corrupt; automatic restore withheld to avoid undoing a committed transaction')
    if status=='rolled_back' or (automatic and status=='committed'):return emit(status='RESTORE_NOOP',transaction=str(d),previous=status)
    if not automatic and not active(unit_paths(d)[0]+'.timer'):arm(d,60)
    status_write(d,'restoring');errors=[]
    # Check ALL read inputs before any restore write. A stale snapshot must not
    # partially rewrite a host that has subsequently acquired new configuration.
    pl=Plan();pl.watched=s['watched'];pl.netplan_before={} if any(v.startswith('netplan/') for v in s['owners'].values()) else None
    have=set(pl.watch_globs());allowed=set(s['inventory'])|set(s['after'])
    if not have<=allowed or not set(s['inventory'])<=have:errors.append('configuration file set changed since transaction')
    for path,r in s['watched'].items():
        if path not in s['files'] and not matches(path,r):errors.append('restore read-input conflict: '+path)
    for path,r in s['files'].items():
        if not (matches(path,r) or matches(path,s['after'][path])):errors.append('restore target conflict: '+path)
    if errors:
        status_write(d,'restore_failed',errors=errors)
        raise Stop('restore withheld before writes; watchdog retained: '+'; '.join(errors))
    # A conflict is reported and retained; never overwrite a third party's new configuration.
    for path,r in s['files'].items():
        try:
            need(matches(path,r) or matches(path,s['after'][path]),'concurrent modification blocks restore: '+path)
            if r['exists']:
                if not matches(path,r):atomic(p(path),base64.b64decode(r['data']),r['mode'],(r['uid'],r['gid']),(r['atime'],r['mtime']),attrs=r.get('xattrs'))
            elif p(path).exists():p(path).unlink()
        except Exception as e:errors.append(str(e))
    try:
        need(not errors,'config conflict; manager reconfiguration withheld')
        for path in s.get('created_dirs',[]):
            need(path.startswith(('/etc/netplan','/etc/systemd/network','/etc/NetworkManager/system-connections','/etc/network','/etc/cloud','/etc/sysctl.d','/etc/sysconfig/network-scripts')) and '..' not in pathlib.Path(path).parts,'invalid created-directory record')
            directory=p(path)
            if directory.exists():
                need(not directory.is_symlink() and directory.stat().st_uid==0,'restore directory changed owner/type')
                directory.rmdir()
        for name in ('all','default'):
            for k,v in s['before']['knobs'][name].items():set_knob(name,k,v)
        apply_actions(s['actions']);verify_nm(s['actions'],True)
        current_links={v['ifname']:v for v in jr('ip','-j','-d','link','show')}
        for link in s['before']['links']:
            nowlink=current_links.get(link['ifname']);need(nowlink,'interface missing during restore: '+link['ifname'])
            if nowlink.get('mtu')!=link.get('mtu'):run(['ip','link','set','dev',link['ifname'],'mtu',str(link['mtu'])])
            if nowlink.get('address')!=link.get('address') and link.get('link_type')=='ether' and not s['owners'].get(link['ifname'],'').startswith('unmanaged '):run(['ip','link','set','dev',link['ifname'],'address',link['address']])
        for name,kv in s['before']['knobs'].items():
            if name in knobs():
                for k,v in kv.items():set_knob(name,k,v)
        time.sleep(3)
        # Reconstruct lost IPv4 objects before requiring them to be present.
        restore_runtime(s['before'])
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            time.sleep(1);now=runtime()
            if addr_set(now['addr6'],'inet6')==addr_set(s['before']['addr6'],'inet6') and route_set(now['routes6'])==route_set(s['before']['routes6']):break
            restore_runtime(s['before'])
        if 'rules4_raw' in s['before']:restore_rules6(s['before']['rules4_raw'],socket.AF_INET)
        if 'rules6_raw' in s['before']:restore_rules6(s['before']['rules6_raw'])
        now=wait4(s['before'])
        for path,r in s['files'].items():need(matches(path,r),'restored file/metadata differs: '+path)
        need(now['knobs']==s['before']['knobs'],'restored sysctls differ')
        need(addr_set(now['addr6'],'inet6')==addr_set(s['before']['addr6'],'inet6'),'IPv6 address restore incomplete')
        need(route_set(now['routes6'])==route_set(s['before']['routes6']),'IPv6 route restore incomplete')
        need(now['rules6']==s['before']['rules6'],'IP rules restore incomplete')
    except Exception as e:errors.append(str(e))
    if errors:status_write(d,'restore_failed',errors=errors);raise Stop('restore incomplete; watchdog retained: '+'; '.join(errors))
    status_write(d,'rolled_back');disarm(d);emit(status='ROLLED_BACK',transaction=str(d))

def pending():
    return [d for d in p(STATE).glob('tx-*') if d.is_dir() and read_status(d)['status'] not in ('committed','rolled_back','prepared_failed')]
def apply(seconds):
    global APPLY_DEADLINE
    need(not pending(),'unfinished transaction exists; use --status/--restore')
    pl,before=discover();validate_plan(pl)
    if not pl.changes and all(x.get('disable_ipv6')==1 for x in before['knobs'].values()) and not addr_set(before['addr6'],'inet6') and not before['routes6']:
        emit(status='NOOP',owners=pl.owners);return
    created_dirs=set()
    for path in pl.changes:
        parent=p(path).parent
        while not parent.exists():created_dirs.add('/'+str(parent.relative_to(ROOT)));parent=parent.parent
    tool=pathlib.Path(os.environ['MIST_IPV6_SELF']);st=tool.stat();need(st.st_uid==0 and not st.st_mode&0o022,'source script must be root-owned and not group/other writable');b=read_noatime(tool)
    base=p(STATE);need(not base.is_symlink(),'backup root is a symlink');base.mkdir(parents=True,exist_ok=True,mode=0o700)
    bst=base.stat();need(bst.st_uid==0 and bst.st_mode&0o077==0,'unsafe backup root permissions')
    d=p(STATE)/('tx-'+time.strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8]);d.mkdir(mode=0o700,parents=True)
    for parent in (base,base.parent):
        fd=os.open(parent,os.O_RDONLY);os.fsync(fd);os.close(fd)
    try:
        status_write(d,'prepared_failed') # no network writes until backup is complete and armed
        atomic(d/'tool.sh',b,0o700)
        s={'version':VERSION,'machine':p('/etc/machine-id').read_text().strip(),'boot':p('/proc/sys/kernel/random/boot_id').read_text().strip(),'before':before,
           'created_dirs':sorted(created_dirs,key=len,reverse=True),'files':{path:pl.watched[path] for path in pl.changes},'after':pl.changes,'actions':pl.actions,'watched':{path:{k:v for k,v in rec.items() if k!='data' or path in pl.changes} for path,rec in pl.watched.items()},'inventory':pl.inventory,'owners':pl.owners,'tool_sha':sha(b)}
        save_backup(d,s)
        load(d);status_write(d,'prepared')
    except BaseException:
        status_write(d,'prepared_failed');raise
    armed=False;mutated=False
    try:
        deadline=time.monotonic()+seconds
        arm(d,seconds);armed=True;race_check(pl);APPLY_DEADLINE=deadline
        status_write(d,'applying')
        for path,r in pl.changes.items():
            need(matches(path,pl.watched[path]),'concurrent modification before write: '+path)
            def staged(temporary):
                r['xattrs']=xattrs(temporary);save_backup(d,s);load(d)
                need(matches(path,pl.watched[path]),'concurrent modification before atomic replacement: '+path)
            mutated=True;atomic(p(path),base64.b64decode(r['data']),r['mode'],(r['uid'],r['gid']),(r['atime'],r['mtime']),attrs=pl.watched[path].get('xattrs'),before_replace=staged)
        apply_actions(pl.actions);verify_nm(pl.actions)
        restored_rules4=False
        if before.get('rules4_raw') is not None and nl_rule6(family=socket.AF_INET)!=before['rules4_raw']:
            # networkd reconfiguration may discard rules owned by another
            # host service. Restore the exact known selectors/order; never
            # remove a new foreign rule, and never ignore address/route loss.
            restore_rules6(before['rules4_raw'],socket.AF_INET);restored_rules4=True
            emit(status='IPV4_POLICY_REINSTATED',reason='native manager discarded existing IPv4 policy rules; exact snapshot reinstated')
        wait4(before)
        mutated=True # kernel-only transactions must also restore on error/signal
        for name in knobs():set_knob(name,'disable_ipv6',1)
        verify_off(before)
        # Recheck every read input and our writes, including newly created files.
        need(set(pl.watch_globs())==set(pl.inventory)|set(pl.changes),'configuration file set changed during apply')
        for path,r in pl.watched.items():need(matches(path,pl.changes.get(path,r)),'concurrent write during apply: '+path)
        APPLY_DEADLINE=None
        status_write(d,'awaiting_confirmation',deadline_monotonic=deadline,boot=s['boot'],ipv4_policy_reinstated=restored_rules4)
        emit(status='AWAITING_CONFIRMATION',transaction=str(d),tool=str(d/'tool.sh'),machine=s['machine'],owners=pl.owners,seconds=max(0,int(deadline-time.monotonic())),watchdog_active=True,ipv4_policy_reinstated=restored_rules4)
    except BaseException as original:
        APPLY_DEADLINE=None
        atomic(d/'apply-error.txt',str(original).encode())
        if mutated:
            try:restore(d)
            except Exception as recovery:raise Stop('apply failed: '+str(original)+'; '+str(recovery)) from original
        else:
            status_write(d,'prepared_failed')
            if armed:disarm(d)
        raise

def transaction_view(d):
    value=dict(transaction=str(d),**read_status(d))
    if value['status']=='awaiting_confirmation':
        boot=p('/proc/sys/kernel/random/boot_id').read_text().strip()
        value['same_boot']=value.get('boot')==boot
        value['remaining_seconds']=max(0,int(value.get('deadline_monotonic',0)-time.monotonic())) if value['same_boot'] else 0
        value['watchdog_active']=active(unit_paths(d)[0]+'.timer')
    return value

def confirmation_state(d,s):
    view=transaction_view(d)
    if view['status']!='awaiting_confirmation':
        transaction_error('not_awaiting_confirmation','transaction is '+view['status']+'; no confirmation performed',**view)
    if s['boot']!=p('/proc/sys/kernel/random/boot_id').read_text().strip():
        transaction_error('server_rebooted','server rebooted before confirmation; restore required',**view)
    if time.monotonic()>=view.get('deadline_monotonic',0):
        transaction_error('confirmation_expired','confirmation deadline elapsed; watchdog remains armed',**view)
    if not view['watchdog_active']:
        transaction_error('watchdog_inactive','rollback watchdog is not active; confirmation refused',**view)
    return view

def confirm(d):
    d,s=load(d);view=confirmation_state(d,s)
    verify_off(s['before'])
    pl=Plan();pl.watched=s['watched'];pl.netplan_before={} if any(v.startswith('netplan/') for v in s['owners'].values()) else None
    have=set(pl.watch_globs());want=set(s['inventory'])|set(s['after'])
    need(have==want,'configuration file set changed before confirmation; missing='+str(sorted(want-have))+' added='+str(sorted(have-want)))
    for path,r in s['watched'].items():need(matches(path,s['after'].get(path,r)),'configuration changed before confirmation: '+path)
    confirmation_state(d,s)
    status_write(d,'committed');disarm(d);emit(status='COMMITTED',transaction=str(d),watchdog_active=False)

def main():
    ap=argparse.ArgumentParser(description='Transactional host IPv6 disable. Default: read-only check.')
    g=ap.add_mutually_exclusive_group();g.add_argument('--check',action='store_true');g.add_argument('--apply',action='store_true');g.add_argument('--status',action='store_true');g.add_argument('--confirm');g.add_argument('--restore');g.add_argument('--automatic-restore')
    ap.add_argument('--rollback-seconds',type=int,default=600)
    a=ap.parse_args();need(os.geteuid()==0,'root required');need(60<=a.rollback_seconds<=1800,'rollback timeout must be 60..1800 seconds')
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,lambda n,f:(_ for _ in ()).throw(Stop('interrupted by signal '+str(n))))
    need(os.stat('/proc/self/ns/net').st_ino == os.stat('/proc/1/ns/net').st_ino, 'run in the host PID 1 network namespace')
    p('/run/lock').mkdir(exist_ok=True)
    fd=os.open(p('/run/lock/mist-ipv6.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
    st=os.fstat(fd);need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,'unsafe transaction lock file')
    with os.fdopen(fd,'a') as f:
        try:fcntl.flock(f,fcntl.LOCK_EX|(0 if a.automatic_restore else fcntl.LOCK_NB))
        except BlockingIOError:raise Stop('another IPv6 transaction is running')
        if a.restore or a.automatic_restore:restore(a.restore or a.automatic_restore,bool(a.automatic_restore))
        elif a.confirm:confirm(a.confirm)
        elif a.status:emit(status='STATUS',transactions=[transaction_view(d) for d in sorted(p(STATE).glob('tx-*')) if d.is_dir()])
        elif a.apply:apply(a.rollback_seconds)
        else:
            pl,before=discover();validate_plan(pl);emit(status='CHECK_OK',version=VERSION,owners=pl.owners,changes=sorted(pl.changes),actions=pl.actions,ipv6_disabled=all(x.get('disable_ipv6')==1 for x in before['knobs'].values()))
if __name__=='__main__':
    try:main()
    except Exception as e:emit(**dict(getattr(e,'details',{}),status='STOP',reason=str(e)));sys.exit(1)
MIST_PYTHON
MIST_ENGINE_EXACT_1D230A3B6D64
printf '%s  %s\n' '1d230a3b6d647fb798ecdda7d1b9f7663ee85bf8d56b961c3f3cf84331ecf0c1' "$mist_ipv6_ui_dir/mist_ipv6_off_fixed.sh" | sha256sum --check --status || { printf '\033[1;31mSTOP: engine checksum mismatch\033[0m\n' >&2; exit 1; }
chmod 700 "$mist_ipv6_ui_dir/mist_ipv6_off_fixed.sh"
cat > "$mist_ipv6_ui_dir/display.py" <<'MIST_XSHELL_DISPLAY_EOF'
#!/usr/bin/env python3
"""Presentation only: consume V2 JSON, preserve JSON for non-terminal callers."""
import json
import os
import shlex
import sys


def main():
    mirror = os.environ.get('MIST_IPV6_UI') == 'stderr'
    human = sys.stdout.isatty() or mirror
    output = sys.stderr if mirror else sys.stdout
    color = (mirror or output.isatty()) and 'NO_COLOR' not in os.environ and os.environ.get('TERM') != 'dumb'

    def say(text='', tone='0'):
        prefix = '\033[' + tone + 'm' if color else ''
        suffix = '\033[0m' if color else ''
        print(prefix + str(text) + suffix, file=output, flush=True)

    def owners(data):
        value = data.get('owners')
        if isinstance(value, dict) and value:
            say('  Сеть: ' + '; '.join(str(k) + ': ' + str(v) for k, v in value.items()), '36')

    if human:
        say('\nMIST | IPv6 V2.3', '1;36')
        if os.environ.get('MIST_IPV6_VERIFIED_SHA'):
            say('[OK] Контрольная сумма исходника проверена', '32')
        if os.environ.get('MIST_IPV6_SAVED_SOURCE'):
            say('  Скрипт: ' + os.environ['MIST_IPV6_SAVED_SOURCE'], '90')
        say('[...] Выполнение и проверка состояния сети...', '36')

    for raw in sys.stdin:
        if mirror or not human:
            sys.stdout.write(raw)
            sys.stdout.flush()
        if not human:
            continue
        try:
            item = json.loads(raw)
        except (ValueError, TypeError):
            say(raw.rstrip('\r\n'))
            continue
        if not isinstance(item, dict):
            say(raw.rstrip('\r\n'))
            continue
        status = item.get('status')
        say()
        if status == 'NOOP':
            say('[OK] IPv6 уже отключён. Изменения не требуются.', '1;32')
            owners(item)
        elif status == 'AWAITING_CONFIRMATION':
            say('[OK] IPv6 отключён. Локальные проверки пройдены.', '32')
            owners(item)
            say('[ЖДЁТ] Подтвердите результат до истечения страховки.', '1;33')
            seconds = item.get('seconds')
            if seconds is not None:
                say('  Страховка: ' + str(seconds) + ' с осталось до автоотката.', '33')
            transaction = item.get('transaction')
            tool = item.get('tool')
            if transaction:
                say('  Резервная копия: ' + str(transaction), '36')
            if isinstance(tool, str) and isinstance(transaction, str):
                say('  После проверки доступности выполните одну команду:', '33')
                confirm = ('bash ' + shlex.quote(tool) + ' --confirm ' + shlex.quote(transaction)
                           + ' | python3 ' + shlex.quote(os.path.abspath(__file__)))
                say('  bash -o pipefail -c ' + shlex.quote(confirm), '1;36')
            say('  Без подтверждения автоматический откат останется включён.', '33')
        elif status == 'COMMITTED':
            say('[OK] Результат подтверждён. Автооткат отменён.', '1;32')
            if item.get('transaction'):
                say('  Резервная копия сохранена: ' + str(item['transaction']), '36')
        elif status == 'ROLLED_BACK':
            say('[ВОЗВРАТ] Исходные настройки восстановлены.', '1;33')
            if item.get('transaction'):
                say('  Резервная копия: ' + str(item['transaction']), '36')
        elif status == 'RESTORE_NOOP':
            say('[OK] Повторное восстановление не требуется.', '32')
            say('  Состояние: ' + str(item.get('previous', 'unknown')), '90')
        elif status == 'IPV4_POLICY_REINSTATED':
            say('[ИНФО] Правила маршрутизации IPv4 восстановлены из снимка.', '33')
            say('  Итоговая проверка продолжается.', '36')
        elif status == 'CHECK_OK':
            say('[OK] Проверка завершена. Сеть не изменялась.', '1;32')
            owners(item)
            say('  IPv6 сейчас: ' + ('отключён' if item.get('ipv6_disabled') else 'ещё не полностью отключён'), '36')
        elif status == 'STOP':
            say('[СТОП] Операция остановлена.', '1;31')
            say('  Причина: ' + str(item.get('reason', 'не указана')), '31')
            if item.get('error_code'):
                say('  Код: ' + str(item['error_code']), '31')
            if item.get('same_boot') is False:
                say('  Сервер перезагружен: подтверждение закрыто; страховка: ' + str(item.get('watchdog_active')), '33')
            elif 'remaining_seconds' in item:
                say('  До автоотката: ' + str(item['remaining_seconds']) + ' с; страховка: ' + str(item.get('watchdog_active')), '33')
        elif status == 'STATUS':
            say('[ИНФО] Состояние сохранённых операций', '1;36')
            for tx in item.get('transactions', []):
                state = tx.get('status', 'unknown')
                tone = '32' if state == 'committed' else '31' if state == 'restore_failed' else '33'
                say('  ' + str(tx.get('transaction', '')) + ': ' + str(state), tone)
                if tx.get('same_boot') is False:
                    say('    Сервер перезагружен: подтверждение закрыто; страховка: ' + str(tx.get('watchdog_active')), '33')
                elif 'remaining_seconds' in tx:
                    say('    До автоотката: ' + str(tx['remaining_seconds']) + ' с; страховка: ' + str(tx.get('watchdog_active')), '33')
        else:
            say('[ИНФО] ' + json.dumps(item, ensure_ascii=False), '36')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
MIST_XSHELL_DISPLAY_EOF
export MIST_IPV6_VERIFIED_SHA=1d230a3b6d647fb798ecdda7d1b9f7663ee85bf8d56b961c3f3cf84331ecf0c1
export MIST_IPV6_SAVED_SOURCE="$mist_ipv6_ui_dir/mist_ipv6_off_fixed.sh"
[ "$#" -gt 0 ] || set -- --apply
bash "$mist_ipv6_ui_dir/mist_ipv6_off_fixed.sh" "$@" | python3 "$mist_ipv6_ui_dir/display.py"
