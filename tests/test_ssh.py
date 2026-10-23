"""Unit tests use deliberate substitutes; native evidence is separate."""
import copy,io,json,os,subprocess,sys,unittest
from unittest.mock import patch
from test_chrony import load_engine,SCRIPT

class SSHTests(unittest.TestCase):
    def setUp(self):
        self.launcher,self.engine,self.a=load_engine()
        self.a['connection_live']=lambda proof:True
        self.old={'tuple':['198.51.100.1','44000','203.0.113.2','22'],'inode':'100','sshd_start_ticks':10,'boot_id':'boot'}
        self.s={'ssh':self.old['tuple'],'transport':self.old}
        self.view={'confirmation_ready_ticks':100,'remaining_seconds':120,'watchdog_active':True,'status':'awaiting_confirmation'}
        self.new=dict(self.old,tuple=['198.51.100.1','44001','203.0.113.2','22'],inode='101',sshd_start_ticks=101)
    def reject(self,code,proof=None):
        with self.assertRaises(self.a['Stop']) as cm:self.a['validate_confirmation_transport'](self.s,self.view,proof or self.new)
        self.assertEqual(cm.exception.details['error_code'],code)
    def test_new_tcp_after_ready_accepted(self):self.a['validate_confirmation_transport'](self.s,self.view,self.new)
    def test_same_transport_rejected(self):self.reject('ssh_same_transport',self.old)
    def test_tuple_reuse_rejected(self):self.reject('ssh_same_transport',dict(self.new,tuple=self.old['tuple']))
    def test_inode_reuse_rejected(self):self.reject('ssh_same_transport',dict(self.new,inode=self.old['inode']))
    def test_endpoint_port_rejected(self):self.reject('ssh_endpoint_changed',dict(self.new,tuple=self.new['tuple'][:3]+['2222']))
    def test_endpoint_address_rejected(self):self.reject('ssh_endpoint_changed',dict(self.new,tuple=self.new['tuple'][:2]+['203.0.113.3','22']))
    def test_preexisting_different_connection_rejected(self):self.reject('ssh_transport_predates_apply',dict(self.new,sshd_start_ticks=99))
    def test_ready_tick_boundary_rejected(self):self.reject('ssh_transport_predates_apply',dict(self.new,sshd_start_ticks=100))
    def test_legacy_unproven_rejected(self):self.s.pop('transport');self.reject('legacy_transport_unproven')
    def test_ready_proof_required(self):self.view.pop('confirmation_ready_ticks');self.reject('legacy_transport_unproven')
    def test_connection_lost_rejected(self):self.a['connection_live']=lambda proof:False;self.reject('ssh_transport_lost')
    def test_proc_ipv4_endpoint(self):self.assertEqual(self.a['proc_endpoint']('0F02000A:0016',2),('10.0.2.15','22'))
    def test_proc_mapped_ipv6_endpoint(self):self.assertEqual(self.a['proc_endpoint']('0000000000000000FFFF00000F02000A:0016',10),('10.0.2.15','22'))
    def test_ambiguous_sockets_never_choose_foreign(self):
        a=self.a;a['tcp_sockets']=lambda:{'1':{'state':'01','tuple':self.old['tuple']},'2':{'state':'01','tuple':self.new['tuple']}}
        a['socket_inodes']=lambda pid:{'1','2'}
        with self.assertRaises(a['Stop']) as cm:a['sshd_connection']([dict(pid=5,exe='sshd',uid=0,mode=0o755,start_ticks=1)])
        self.assertEqual(cm.exception.details['error_code'],'ssh_transport_unverified')
    def test_status_json_and_color_stderr(self):
        display=SCRIPT.parents[0]/'src/display.py'
        raw=json.dumps(dict(status='STOP',error_code='ssh_same_transport',reason='same',remaining_seconds=42,watchdog_active=True))+'\n'
        env=dict(os.environ,MIST_IPV6_UI='stderr',TERM='xterm');env.pop('NO_COLOR',None)
        p=subprocess.run([sys.executable,str(display)],input=raw,text=True,capture_output=True,env=env)
        self.assertEqual(p.stdout,raw);self.assertIn('\033[1;31m',p.stderr);self.assertIn('42',p.stderr);self.assertIn('ssh_same_transport',p.stderr)
    def test_reboot_status_does_not_mislabel_confirmation_window(self):
        raw=json.dumps(dict(status='STATUS',transactions=[dict(status='awaiting_confirmation',same_boot=False,remaining_seconds=0,watchdog_active=True)]))+'\n'
        p=subprocess.run([sys.executable,str(SCRIPT.parent/'src/display.py')],input=raw,text=True,encoding='utf-8',capture_output=True,env=dict(os.environ,MIST_IPV6_UI='stderr',TERM='xterm'))
        self.assertEqual(p.stdout,raw);self.assertIn('подтверждение закрыто',p.stderr);self.assertNotIn('До автоотката: 0',p.stderr)
    def test_generated_engine_matches_readable_source(self):
        code=self.engine.split(b"<<'MIST_PYTHON'\n",1)[1].rsplit(b'\nMIST_PYTHON',1)[0]
        self.assertEqual(code.replace(b'\r\n',b'\n').rstrip(),(SCRIPT.parent/'src/engine.py').read_bytes().rstrip())
    def test_builder_is_reproducible(self):
        subprocess.run([sys.executable,str(SCRIPT.parent/'tools/build.py'),'--check'],check=True,capture_output=True)

if __name__=='__main__':unittest.main(verbosity=2)
