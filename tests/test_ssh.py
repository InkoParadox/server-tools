"""Unit tests use deliberate substitutes; native evidence is separate."""
import copy,io,json,os,subprocess,sys,unittest
from unittest.mock import patch
from pathlib import Path
from test_chrony import load_engine,SCRIPT

class InterfaceTests(unittest.TestCase):
    def setUp(self):self.launcher,self.engine,self.a=load_engine()
    def test_host_context_rejects_container_and_accepts_full_vm(self):
        a=self.a
        with patch.object(a['shutil'],'which',return_value='/usr/bin/systemd-detect-virt'):
            for code,name in ((0,'docker'),(0,'lxc'),(2,'')):
                a['run']=lambda *args,**kw:subprocess.CompletedProcess(args,code,name,'')
                with self.subTest(name=name),self.assertRaises(a['Stop']):a['host_context']()
            a['run']=lambda *args,**kw:subprocess.CompletedProcess(args,1,'none\n','')
            a['host_context']()
    def test_status_json_and_color_stderr(self):
        display=SCRIPT.parents[0]/'src/display.py'
        raw=json.dumps(dict(status='STOP',error_code='confirmation_expired',reason='same',remaining_seconds=42,watchdog_active=True))+'\n'
        env=dict(os.environ,MIST_IPV6_UI='stderr',TERM='xterm');env.pop('NO_COLOR',None)
        p=subprocess.run([sys.executable,str(display)],input=raw,text=True,capture_output=True,env=env)
        self.assertEqual(p.stdout,raw);self.assertIn('\033[1;31m',p.stderr);self.assertIn('42',p.stderr);self.assertIn('confirmation_expired',p.stderr)
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
