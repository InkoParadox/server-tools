import unittest,copy,pathlib,tempfile,json,base64,os
from embedded import new_engine
e=new_engine()
class Pure(unittest.TestCase):
 def test_ss_four(self):self.assertEqual(e.tcp_peers('0 0 [::1]:22 [2001:db8::1]:333\n'),['[2001:db8::1]:333'])
 def test_ss_mapped(self):self.assertEqual(e.tcp_peers('0 0 [::ffff:1.2.3.4]:22 [::ffff:5.6.7.8]:333'),[])
 def test_ss_loopback(self):self.assertEqual(e.tcp_peers('0 0 [::1]:22 [::1]:33'),['[::1]:33'])
 def test_ss_bad(self):
  with self.assertRaises(e.Stop):e.tcp_peers('ESTAB 0 0 a b')
 def test_netplan_merged(self):
  a={'network':{'version':2,'ethernets':{'ens3':{'dhcp4':True,'addresses':['10.2.0.2/24','2001:db8::2/64'],'link-local':['ipv4','ipv6']}}}}
  b={'network':{'ethernets':{'ens3':{'addresses':['10.3.0.2/24'],'routes':[{'to':'default','via':'10.2.0.1'},{'to':'::/0','via':'2001:db8::1'}]}}}}
  self.assertEqual(e.merge(e.strip_netplan(a),e.strip_netplan(b)),e.strip_netplan(e.merge(a,b)))
  self.assertEqual(e.strip_netplan(e.merge(a,b))['network']['ethernets']['ens3']['addresses'],['10.2.0.2/24','10.3.0.2/24'])
 def test_netplan_topologies(self):
  n={'network':{'version':2,**{t:{'x':{'addresses':['10.1.0.1/24','2001:db8::1/64'],'mtu':1400}} for t in ['bridges','bonds','vlans','ethernets','dummy-devices']}}}
  after=e.strip_netplan(n)
  for t in n['network']:
   if t!='version':self.assertEqual(after['network'][t]['x']['mtu'],1400);self.assertEqual(after['network'][t]['x']['addresses'],['10.1.0.1/24'])
 def test_address_map(self):
  n={'network':{'ethernets':{'x':{'addresses':[{'10.0.0.1/24':{'lifetime':0}},{'2001:db8::1/64':{}}]}}}}
  self.assertEqual(e.strip_netplan(n)['network']['ethernets']['x']['addresses'],[{'10.0.0.1/24':{'lifetime':0}}])
 def test_dns_dependency(self):
  with self.assertRaises(e.Stop):e.strip_netplan({'network':{'ethernets':{'x':{'nameservers':{'addresses':['::1']}}}}})
 def test_tunnel4(self):self.assertEqual(e.strip_netplan({'network':{'tunnels':{'x':{'local':'1.2.3.4','remote':'2.3.4.5','mode':'gre'}}}})['network']['tunnels']['x']['remote'],'2.3.4.5')
 def test_tunnel6_dependency(self):
  with self.assertRaises(e.Stop):e.strip_netplan({'network':{'tunnels':{'x':{'remote':'2001:db8::1'}}}})
 def test_yaml_duplicate(self):
  with self.assertRaises(e.Stop):e.yaml_load('a: 1\na: 2\n')
 def test_networkd(self):
  src='[Match]\nName=ens*\n[Network]\nDHCP=yes\nLinkLocalAddressing=yes\nDNS=1.1.1.1\nMTUBytes=1400\nAddress=10.0.0.2/24\nAddress=2001:db8::2/64\n[Route]\nDestination=::/0\nGateway=2001:db8::1\n[Route]\nGateway=10.0.0.1\nMetric=300\n'
  d=e.strip_networkd(src);self.assertIn('DHCP=ipv4',d);self.assertIn('LinkLocalAddressing=ipv4',d);self.assertIn('MTUBytes=1400',d);self.assertIn('Metric=300',d);self.assertNotIn('2001:',d)
 def test_networkd_router_dependency(self):
  with self.assertRaises(e.Stop):e.strip_networkd('[Network]\nIPv6SendRA=yes\n')
 def test_ifupdown(self):
  src='source /etc/network/interfaces.d/*\nauto eth0\niface eth0 inet dhcp\n mtu 1400\niface eth0 inet6 static\n address 2001:db8::2/64\n gateway 2001:db8::1\n'
  self.assertEqual(e.strip_interfaces(src),'source /etc/network/interfaces.d/*\nauto eth0\niface eth0 inet dhcp\n mtu 1400\n')
 def test_ifupdown2_mixed(self):self.assertEqual(e.strip_interfaces('iface br0\n address 10.0.0.1/24 2001:db8::1/64\n bridge-ports eth1\n'),'iface br0\n address 10.0.0.1/24\n bridge-ports eth1\n')
 def test_ifupdown_hooks_dependency(self):
  with self.assertRaises(e.Stop):e.strip_interfaces('iface x inet6 static\n up echo changed\n')
 def test_dhcp_lifetime(self):
  a=[{'dst':'default','dev':'x','protocol':'dhcp','expires':30}];b=copy.deepcopy(a);b[0]['expires']=25;self.assertEqual(e.route_set(a),e.route_set(b));b=[];self.assertNotEqual(e.route_set(a),e.route_set(b))
 def test_ipv4_lease_address(self):
  a=[{'ifname':'x','addr_info':[{'family':'inet','local':'10.0.0.2','prefixlen':24,'valid_life_time':40}]}];b=copy.deepcopy(a);b[0]['addr_info'][0]['valid_life_time']=30;self.assertEqual(e.addr_set(a,'inet'),e.addr_set(b,'inet'));b[0]['addr_info'][0]['local']='10.0.0.3';self.assertNotEqual(e.addr_set(a,'inet'),e.addr_set(b,'inet'))
 def test_route_metrics(self):self.assertIn('hoplimit',e.route_command('replace',{'dst':'::/0','metrics':[{'hoplimit':64}]}))
 def test_atomic_metadata(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'x';e.atomic(p,b'abc',0o640,(os.getuid(),os.getgid()),(1000000000,2000000000));self.assertEqual(p.read_bytes(),b'abc');self.assertEqual(p.stat().st_mode&0o777,0o640);self.assertEqual(p.stat().st_mtime_ns,2000000000)
 def test_ifupdown_only6_placeholder(self):
  self.assertEqual(e.strip_interfaces('auto eth1\niface eth1 inet6 static\n address 2001:db8::1/64\n mtu 1420\n'),'auto eth1\niface eth1 inet6 manual\n mtu 1420\n')
 def test_ifupdown_ipv6_route_hook(self):
  self.assertEqual(e.strip_interfaces('iface eth0 inet static\n address 10.0.0.1/24\n up ip -6 route add 2001:db8::/64 dev eth0\n'),'iface eth0 inet static\n address 10.0.0.1/24\n')
 def test_ifupdown2_native_policy(self):
  src='iface br0\n address 10.0.0.1/24\n ipv6-addrgen on\n bridge-ports eth1\n'
  want=e.strip_interfaces(src,ifup2=True)
  self.assertIn('ipv6-addrgen off',want);self.assertNotIn('ipv6-addrgen on',want);self.assertIn('bridge-ports eth1',want);self.assertEqual(e.strip_interfaces(want,ifup2=True),want)
 def test_nm_passthrough(self):
  src={'network':{'version':2,'nm-devices':{'x':{'networkmanager':{'passthrough':{'connection.type':'dummy','ipv4.address1':'10.0.0.2/24','ipv6.method':'manual','ipv6.address1':'2001:db8::1/64'}}}}}}
  v=e.strip_netplan(src);self.assertEqual(v['network']['nm-devices']['x']['networkmanager']['passthrough'],{'connection.type':'dummy','ipv4.address1':'10.0.0.2/24','ipv6.method':'disabled'});self.assertEqual(e.strip_netplan(v),v)
 def test_resolved_ifindex_normalization(self):
  a='Global:\nLink 8 (foo): 1.1.1.1 8.8.8.8\nLink 9 (bar):'
  b='Global:\nLink 9 (bar):\nLink 12 (foo): 1.1.1.1 8.8.8.8'
  self.assertEqual(e.resolved_map(a),e.resolved_map(b));self.assertNotEqual(e.resolved_map(a),e.resolved_map(b.replace('1.1.1.1','1.0.0.1')))
 def test_keyfile_preserves_ipv4_bytes(self):
  src='[connection]\nid=x\nuuid=00\n[ipv4]\nmethod=auto\nroute-metric=53\n[ipv6]\nmethod=manual\naddress1=2001:db8::1/64\n[ethernet]\nmtu=1430\n'
  v=e.strip_nm_keyfile(src);self.assertIn('[ipv4]\nmethod=auto\nroute-metric=53\n',v);self.assertIn('mtu=1430',v);self.assertNotIn('2001:',v);self.assertEqual(e.strip_nm_keyfile(v),v)
 def test_ifcfg_idempotent_preserves4(self):
  src='UUID=x\nIPADDR=10.0.0.1\nMTU=1420\nDNS1=1.1.1.1\nIPV6ADDR=2001:db8::1/64\nIPV6INIT=yes\n'
  v=e.strip_ifcfg(src);self.assertIn('IPADDR=10.0.0.1\nMTU=1420\nDNS1=1.1.1.1\n',v);self.assertIn('IPV6_DISABLED=yes',v);self.assertEqual(e.strip_ifcfg(v),v)
 def test_ifcfg_dns6_refused(self):
  with self.assertRaises(e.Stop):e.strip_ifcfg('DNS2="2001:db8::53"\n')
 def test_explicit_sysctl_and_symlink(self):
  old=e.ROOT
  try:
   with tempfile.TemporaryDirectory() as tmp:
    e.ROOT=pathlib.Path(tmp);e.p('/etc/sysctl.d').mkdir(parents=True);e.p('/etc/sysctl.conf').write_text('# Keep\nnet.ipv6.conf.eth0.disable_ipv6 = 0 # owner\nnet.ipv4.ip_forward=1\n');e.p('/etc/sysctl.d/99-sysctl.conf').symlink_to('../sysctl.conf')
    pl=e.Plan();pl.policy();v=base64.b64decode(pl.changes['/etc/sysctl.conf']['data']).decode();self.assertIn('= 1 # owner',v);self.assertIn('net.ipv4.ip_forward=1',v);self.assertIn('symlink',pl.watched['/etc/sysctl.d/99-sysctl.conf']);self.assertTrue(e.matches('/etc/sysctl.d/99-sysctl.conf',pl.watched['/etc/sysctl.d/99-sysctl.conf']))
  finally:e.ROOT=old
 def test_plan_cancel_intermediate_change(self):
  old=e.ROOT
  try:
   with tempfile.TemporaryDirectory() as tmp:
    e.ROOT=pathlib.Path(tmp);e.p('/etc').mkdir();e.p('/etc/test').write_bytes(b'before');pl=e.Plan();pl.put('/etc/test',b'after');pl.put('/etc/test',b'before');self.assertEqual(pl.changes,{})
  finally:e.ROOT=old
 def test_finite_route_presence_not_ignored(self):
  a={'dst':'::/0','expires':40};b={'dst':'::/0'};self.assertNotEqual(e.route_set([a]),e.route_set([b]))
 def test_cloud_ignores_unrelated_duplicates(self):
  self.assertEqual(e.cloud_network('users:\n - name: x\n   sudo: a\n   sudo: b\nnetwork: {config: disabled}\n'),{'network':{'config':'disabled'}})
 def test_cloud_rejects_ambiguous_network(self):
  with self.assertRaises(e.Stop):e.cloud_network('network: {version: 2, version: 1}\n')
 def test_keyfile_implicit_ipv6_default(self):
  self.assertIn('method=disabled',e.strip_nm_keyfile('[connection]\ntype=ethernet\n[ipv4]\nmethod=auto\n'))
  self.assertNotIn('[ipv6]',e.strip_nm_keyfile('[connection]\ntype=ethernet\nmaster=br0\nslave-type=bridge\n'))
 def test_multicast_slot_is_interface_scoped(self):
  a={'type':'multicast','dst':'ff00::/8','dev':'eth0','table':'local','metric':256};b=dict(a,dev='br0');self.assertNotEqual(e.route_slot(a),e.route_slot(b))
  a={'dst':'default','gateway':'10.0.0.1','dev':'a'};b=dict(a,dev='b');self.assertEqual(e.route_slot(a),e.route_slot(b))
 def test_udp_native6_peer(self):self.assertEqual(e.udp_peers('ESTAB 0 0 [::1]:123 [2001:db8::1]:444'),['[2001:db8::1]:444'])
 def test_udp_mapped_peer(self):self.assertEqual(e.udp_peers('ESTAB 0 0 [::ffff:127.0.0.1]:123 [::ffff:127.0.0.1]:444'),[])
 def test_atomic_preserves_user_xattr(self):
  with tempfile.TemporaryDirectory() as tmp:
   q=pathlib.Path(tmp)/'x';q.write_bytes(b'before');os.setxattr(q,'user.mist-test',b'preserve');e.atomic(q,b'after',0o600);self.assertEqual(os.getxattr(q,'user.mist-test'),b'preserve')
 def test_xattr_edit_is_detected(self):
  old=e.ROOT
  try:
   with tempfile.TemporaryDirectory() as tmp:
    e.ROOT=pathlib.Path(tmp);q=e.p('/x');q.write_bytes(b'data');r=e.file_record('/x');os.setxattr(q,'user.foreign',b'change');self.assertFalse(e.matches('/x',r))
  finally:e.ROOT=old
 def test_plan_mode_only_change(self):
  old=e.ROOT
  try:
   with tempfile.TemporaryDirectory() as tmp:
    e.ROOT=pathlib.Path(tmp);q=e.p('/x');q.write_bytes(b'data');q.chmod(0o600);pl=e.Plan();pl.put('/x',b'data',0o700);self.assertEqual(pl.changes['/x']['mode'],0o700)
  finally:e.ROOT=old
 def test_cloud_exact_native_regeneration_after_boot(self):
  old=e.ROOT
  try:
   with tempfile.TemporaryDirectory() as tmp:
    e.ROOT=pathlib.Path(tmp);e.p('/proc/sys/kernel/random').mkdir(parents=True);boot=e.p('/proc/sys/kernel/random/boot_id');boot.write_text('first');q=e.p('/generated');q.write_bytes(b'our initial yaml');q.chmod(0o600);r=e.file_record('/generated');r['owner_regeneration']={'boot':'first','sha256':[e.sha(b'exact native yaml')]}
    q.write_bytes(b'exact native yaml');self.assertFalse(e.matches('/generated',r));boot.write_text('second');self.assertTrue(e.matches('/generated',r))
    q.write_bytes(b'exact native yaml# foreign comment');self.assertFalse(e.matches('/generated',r));q.write_bytes(b'exact native yaml');q.chmod(0o640);self.assertFalse(e.matches('/generated',r));q.chmod(0o600);os.setxattr(q,'user.foreign',b'edit');self.assertFalse(e.matches('/generated',r))
  finally:e.ROOT=old
 def test_cloud_system_network_precedes_stale_cache(self):
  from unittest.mock import patch
  old=e.ROOT
  try:
   with tempfile.TemporaryDirectory() as tmp:
    e.ROOT=pathlib.Path(tmp)
    for directory in ('/etc/cloud/cloud.cfg.d','/var/lib/cloud/instance','/proc'):e.p(directory).mkdir(parents=True,exist_ok=True)
    e.p('/proc/cmdline').write_text('')
    e.p('/etc/cloud/cloud.cfg').write_text('network: {version: 1, config: []}\n')
    e.p('/var/lib/cloud/instance/network-config.json').write_text('{"version": 2, "ethernets": {"stale": {"dhcp4": true}}}')
    with patch.object(e.shutil,'which',return_value='/usr/bin/cloud-init'),patch.object(e.Plan,'cloud_other_regeneration'):
     pl=e.Plan();pl.cloud();v=e.yaml_load(e.base64.b64decode(pl.changes['/etc/cloud/cloud.cfg.d/zzzz-mist-ipv6.cfg']['data']).decode());self.assertEqual(v,{'network':{'version':1,'config':[]}})
  finally:e.ROOT=old
 def test_generated_eni_keeps_native_hook_policy_without_inline_churn(self):
  before='auto eth0\niface eth0 inet dhcp\n'
  self.assertEqual(e.strip_interfaces(before,{'eth0'},True,False,False),before)
  self.assertIn('ipv6-addrgen off',e.strip_interfaces(before,{'eth0'},True))
if __name__=='__main__':unittest.main(verbosity=2)
