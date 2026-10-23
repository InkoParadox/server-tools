"""Unit tests use deliberate substitutes; native evidence is separate."""
import copy,io,json,os,subprocess,sys,unittest
from unittest.mock import patch
from pathlib import Path
from test_chrony import load_engine,SCRIPT

class InterfaceTests(unittest.TestCase):
    def setUp(self):self.launcher,self.engine,self.a=load_engine()
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
    def test_xshell_string_roundtrip_preserves_shell_escapes(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('command',SCRIPT.parent/'tools/command.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        plain=module.command('7'*40)
        macro=subprocess.check_output([sys.executable,str(SCRIPT.parent/'tools/command.py'),'--ref','7'*40],text=True).rstrip('\n')
        decoded=[];i=0
        escapes={'\\':'\\','$':'$','r':'\r','n':'\n','t':'\t','a':'\a','b':'\b'}
        while i<len(macro):
            if macro[i]=='\\':
                i+=1;self.assertIn(macro[i],escapes);decoded.append(escapes[macro[i]])
            else:decoded.append(macro[i])
            i+=1
        self.assertEqual(''.join(decoded),plain+'\r');self.assertLess(len(macro),30000)
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            field=Path(folder)/'Xshell.txt'
            subprocess.run([sys.executable,str(SCRIPT.parent/'tools/command.py'),'--ref','7'*40,'--output',str(field)],check=True)
            self.assertEqual(field.read_bytes(),macro.encode())
        bash=subprocess.check_output([sys.executable,str(SCRIPT.parent/'tools/command.py'),'--ref','7'*40,'--bash'],text=True).rstrip('\n');self.assertEqual(bash,plain)
        subprocess.run(['bash','-n'],input=(''.join(decoded)[:-1]+'\n').encode(),check=True)
    def test_builder_is_reproducible(self):
        subprocess.run([sys.executable,str(SCRIPT.parent/'tools/build.py'),'--check'],check=True,capture_output=True)

if __name__=='__main__':unittest.main(verbosity=2)
