"""Transaction failure injection with mocked manager/runtime/SSH/watchdog, real file IO and flock."""
import unittest,tempfile,pathlib,copy,os,json,contextlib,io,subprocess,fcntl,sys
from unittest.mock import patch
from embedded import new_engine
e=new_engine()
class Transaction(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.ps=[];self.armed=False
  self.patch('ROOT',self.root)
  for name in ('all','default','lo','eth.123'):
   for k in e.KNOBS:
    q=e.p('/proc/sys/net/ipv6/conf')/name/k;q.parent.mkdir(parents=True,exist_ok=True);q.write_text('0')
  for path,value in [('/etc/machine-id','machine'),('/proc/sys/kernel/random/boot_id','boot'),('/etc/netplan/test.yaml','before')]:
   q=e.p(path);q.parent.mkdir(parents=True,exist_ok=True);q.write_text(value);q.chmod(0o600)
  self.tool=self.root/'tool.sh';self.tool.write_text('# frozen fixture, not executed\n')
  self.env=patch.dict(os.environ,{'SSH_CONNECTION':'198.51.100.1 40000 192.0.2.2 22','MIST_IPV6_SELF':str(self.tool)});self.env.start()
  self.b={'knobs':e.knobs(),'addr4':[{'ifname':'eth.123','addr_info':[{'family':'inet','local':'192.0.2.2','prefixlen':24,'scope':'global'}]}],'routes4':[{'dst':'default','dev':'eth.123','gateway':'192.0.2.1','protocol':'dhcp','expires':100}],'rules4':[],'links':[{'ifname':'eth.123','mtu':1440}],'resolver':{'link':'../run/systemd/resolve/stub-resolv.conf','data':'fixture'},'promote':{},'addr6':[],'routes6':[],'rules6':[]}
  self.rt=copy.deepcopy(self.b)
  def runtime():
   r=copy.deepcopy(self.rt);r['knobs']=e.knobs();return r
  self.patch('runtime',runtime)
  self.patch_sleep=patch.object(e.time,'sleep',lambda _:None);self.patch_sleep.start();self.addCleanup(self.patch_sleep.stop)
  self.patch('jr',lambda *a:copy.deepcopy(self.rt['links']))
  def arm(d,seconds):
   self.armed=True
   for q in e.unit_paths(d)[1:]:e.atomic(q,b'watchdog')
  def disarm(d):
   self.armed=False
   for q in e.unit_paths(d)[1:]:
    if q.exists():q.unlink()
  self.patch('arm',arm);self.patch('disarm',disarm);self.patch('active',lambda u:self.armed)
  self.patch('run',lambda *a,**k:subprocess.CompletedProcess(a,0,'',''))
  self.patch('restore_runtime',lambda b:None)
  self.patch('apply_actions',lambda actions:None)
  def discover():
   pl=e.Plan();pl.put('/etc/netplan/test.yaml',b'after');pl.put(e.POLICY,b'policy',0o644);pl.inventory=pl.watch_globs()
   for path in pl.inventory:pl.watch(path)
   return pl,copy.deepcopy(self.b)
  self.patch('discover',discover)
 def patch(self,name,value):
  p=patch.object(e,name,value);p.start();self.ps.append(p)
 def tearDown(self):
  self.env.stop()
  for p in reversed(self.ps):p.stop()
  self.tmp.cleanup()
 def apply(self):
  with contextlib.redirect_stdout(io.StringIO()):e.apply(60)
  return next(e.p(e.STATE).glob('tx-*'))
 def test_commit_same_session(self):
  d=self.apply();self.assertTrue(self.armed)
  with contextlib.redirect_stdout(io.StringIO()):e.confirm(d)
  self.assertFalse(self.armed);self.assertEqual(e.read_status(d)['status'],'committed')
 def test_restore_exact_files_knobs(self):
  d=self.apply()
  with contextlib.redirect_stdout(io.StringIO()):e.restore(d)
  self.assertEqual(e.p('/etc/netplan/test.yaml').read_bytes(),b'before');self.assertFalse(e.p(e.POLICY).exists());self.assertEqual(e.knobs(),self.b['knobs']);self.assertFalse(self.armed)
 def test_apply_failure_rollback(self):
  count=[0]
  def actions(a):
   count[0]+=1
   if count[0]==1:raise e.Stop('injected apply failure')
  self.patch('apply_actions',actions)
  with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(e.Stop):e.apply(60)
  self.assertEqual(e.p('/etc/netplan/test.yaml').read_bytes(),b'before');self.assertFalse(self.armed)
 def test_rollback_failure_retry(self):
  self.patch('apply_actions',lambda a:(_ for _ in ()).throw(e.Stop('injected command failure')))
  with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(e.Stop):e.apply(60)
  d=next(e.p(e.STATE).glob('tx-*'));self.assertEqual(e.read_status(d)['status'],'restore_failed');self.assertTrue(self.armed)
  self.patch('apply_actions',lambda a:None)
  with contextlib.redirect_stdout(io.StringIO()):e.restore(d,True)
  self.assertEqual(e.read_status(d)['status'],'rolled_back');self.assertFalse(self.armed)
 def test_bad_primary_uses_mirror(self):
  d=self.apply();(d/'backup.json').write_bytes(b'CORRUPT')
  with contextlib.redirect_stdout(io.StringIO()):e.restore(d)
  self.assertEqual(e.p('/etc/netplan/test.yaml').read_bytes(),b'before')
 def test_both_bad_no_writes(self):
  d=self.apply()
  for name in ('backup.json','backup-mirror.json'):(d/name).write_bytes(b'CORRUPT')
  with self.assertRaises(e.Stop):e.restore(d)
  self.assertEqual(e.p('/etc/netplan/test.yaml').read_bytes(),b'after');self.assertTrue(self.armed)
 def test_foreign_edit_retained(self):
  d=self.apply();e.p('/etc/netplan/test.yaml').write_bytes(b'FOREIGN')
  with self.assertRaises(e.Stop):e.restore(d)
  self.assertEqual(e.p('/etc/netplan/test.yaml').read_bytes(),b'FOREIGN');self.assertTrue(self.armed)
 def test_stale_or_missing_ssh_environment_accepted(self):
  d=self.apply();os.environ.pop('SSH_CONNECTION',None)
  with contextlib.redirect_stdout(io.StringIO()):e.confirm(d)
  self.assertEqual(e.read_status(d)['status'],'committed');self.assertFalse(self.armed)
 def test_rolled_back_cannot_commit(self):
  d=self.apply()
  with contextlib.redirect_stdout(io.StringIO()):e.restore(d)
  with self.assertRaises(e.Stop):e.confirm(d)
  self.assertEqual(e.read_status(d)['status'],'rolled_back');self.assertFalse(self.armed)
 def test_reboot_confirm_refused(self):
  d=self.apply();e.p('/proc/sys/kernel/random/boot_id').write_text('newboot');os.environ['SSH_CONNECTION']='198.51.100.1 40001 192.0.2.2 22'
  with self.assertRaises(e.Stop):e.confirm(d)
  self.assertTrue(self.armed)
 def test_config_added_during_apply(self):
  def actions(a):e.atomic(e.p('/etc/netplan/new.yaml'),b'network: {}')
  self.patch('apply_actions',actions)
  with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(e.Stop):e.apply(60)
  self.assertTrue(e.p('/etc/netplan/new.yaml').exists())
 def test_lease_countdown_accepted(self):
  d=self.apply();self.rt['routes4'][0]['expires']=80
  e.verify_off(self.b)
 def test_address_loss_detected(self):
  d=self.apply();self.rt['addr4']=[]
  with self.assertRaises(e.Stop):e.verify4(self.b,e.runtime())
 def test_route_loss_detected(self):
  d=self.apply();self.rt['routes4']=[]
  with self.assertRaises(e.Stop):e.verify4(self.b,e.runtime())
 def test_watchdog_arm_failure_no_config_write(self):
  self.patch('arm',lambda d,s:(_ for _ in ()).throw(e.Stop('arm failed')))
  with self.assertRaises(e.Stop):e.apply(60)
  self.assertEqual(e.p('/etc/netplan/test.yaml').read_bytes(),b'before');self.assertFalse(e.p(e.POLICY).exists())
 def test_real_flock_concurrent_stop(self):
  e.p('/run/lock').mkdir(parents=True,exist_ok=True)
  with e.p('/run/lock/mist-ipv6.lock').open('a') as f,patch.object(sys,'argv',['tool','--status']):
   fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
   with self.assertRaises(e.Stop):e.main()
 def test_put_cancels_intermediate_change(self):
  pl=e.Plan();pl.put('/etc/netplan/test.yaml',b'intermediate');self.assertIn('/etc/netplan/test.yaml',pl.changes);pl.put('/etc/netplan/test.yaml',b'before');self.assertNotIn('/etc/netplan/test.yaml',pl.changes)
 def test_foreign_metadata_retained(self):
  d=self.apply();q=e.p('/etc/netplan/test.yaml');q.chmod(0o640)
  with self.assertRaises(e.Stop):e.restore(d)
  self.assertEqual(q.stat().st_mode&0o777,0o640);self.assertEqual(q.read_bytes(),b'after');self.assertTrue(self.armed)
 def test_foreign_input_prevents_any_restore_write(self):
  d=self.apply();q=e.p('/etc/netplan/new.yaml');e.atomic(q,b'foreign')
  with self.assertRaises(e.Stop):e.restore(d)
  self.assertEqual(e.p('/etc/netplan/test.yaml').read_bytes(),b'after');self.assertEqual(q.read_bytes(),b'foreign')
 def test_expired_confirm(self):
  d=self.apply();e.status_write(d,'awaiting_confirmation',deadline_monotonic=0);os.environ['SSH_CONNECTION']='198.51.100.1 40001 192.0.2.2 22'
  with self.assertRaises(e.Stop):e.confirm(d)
  self.assertTrue(self.armed)
 def test_corrupt_status_primary_uses_mirror(self):
  d=self.apply();(d/'status.json').write_bytes(b'bad');self.assertEqual(e.read_status(d)['status'],'awaiting_confirmation')
 def test_source_not_owned_no_pending(self):
  self.tool.chmod(0o666)
  with self.assertRaises(e.Stop):self.apply()
  self.assertFalse(e.pending());self.assertFalse(self.armed)
 def test_unsafe_state_directory_refused(self):
  e.p(e.STATE).mkdir(parents=True,mode=0o755)
  with self.assertRaises(e.Stop):self.apply()
  self.assertEqual(e.p('/etc/netplan/test.yaml').read_text(),'before')
 def test_created_parent_removed_on_restore(self):
  d=self.apply();_,data=e.load(d);self.assertIn('/etc/sysctl.d',data['created_dirs'])
  with contextlib.redirect_stdout(io.StringIO()):e.restore(d)
  self.assertFalse(e.p('/etc/sysctl.d').exists())
 def test_kernel_only_failure_restores_knobs(self):
  def only_kernel():
   pl=e.Plan();pl.inventory=pl.watch_globs()
   for path in pl.inventory:pl.watch(path)
   return pl,copy.deepcopy(self.b)
  self.patch('discover',only_kernel);self.patch('verify_off',lambda b:(_ for _ in ()).throw(e.Stop('injected postcheck failure')))
  with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(e.Stop):e.apply(60)
  d=next(e.p(e.STATE).glob('tx-*'));self.assertEqual(e.read_status(d)['status'],'rolled_back');self.assertEqual(e.knobs(),self.b['knobs']);self.assertFalse(self.armed)
 def test_xattr_exact_restore(self):
  q=e.p('/etc/netplan/test.yaml');os.setxattr(q,'user.original',b'keep');d=self.apply()
  self.assertEqual(os.getxattr(q,'user.original'),b'keep')
  with contextlib.redirect_stdout(io.StringIO()):e.restore(d)
  self.assertEqual(e.xattrs(q),{'user.original':e.base64.b64encode(b'keep').decode()})
 def test_xattr_foreign_restore_refused(self):
  d=self.apply();q=e.p('/etc/netplan/test.yaml');os.setxattr(q,'user.foreign',b'keep-new')
  with self.assertRaises(e.Stop):e.restore(d)
  self.assertEqual(os.getxattr(q,'user.foreign'),b'keep-new');self.assertTrue(self.armed)
if __name__=='__main__':unittest.main(verbosity=2)
