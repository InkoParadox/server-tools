"""Launcher regression tests; local HTTP fixtures are not Xshell UI evidence."""
import hashlib,http.server,importlib.util,json,os,pathlib,shutil,subprocess,sys,tempfile,threading,unittest
from unittest.mock import patch

R=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('command',R/'tools/command.py')
command=importlib.util.module_from_spec(spec);spec.loader.exec_module(command)
BASH=os.environ.get('MIST_TEST_BASH') or shutil.which('bash')
REF='7'*40

class CommandTests(unittest.TestCase):
    def test_literal_field_and_terminal_command(self):
        plain=command.command(REF)
        self.assertNotIn('$',plain);self.assertNotIn('\\',plain)
        digest=hashlib.sha256((R/'ipv6.sh').read_bytes()).hexdigest()
        self.assertIn(digest,plain);self.assertIn('/'+REF+'/ipv6.sh',plain)
        for ref in ('main','7'*39,REF+';id'):
            with self.subTest(ref=ref),self.assertRaises(ValueError):command.command(ref)
        with tempfile.TemporaryDirectory() as folder:
            field=pathlib.Path(folder)/'Xshell.txt';terminal=pathlib.Path(folder)/'Bash.txt'
            for target,flags in ((field,[]),(terminal,['--bash'])):
                subprocess.run([sys.executable,str(R/'tools/command.py'),'--ref',REF,'--output',str(target),*flags],check=True)
            self.assertEqual(field.read_bytes(),plain.encode()+b'\\r')
            self.assertEqual(terminal.read_bytes(),plain.encode()+b'\n')
            self.assertLess(len(field.read_bytes()),1000)

    @unittest.skipUnless(BASH,'Bash unavailable')
    def test_bash_syntax(self):
        subprocess.run([BASH,'--noprofile','--norc','-n'],input=command.command(REF).encode(),check=True)

    @unittest.skipUnless(BASH,'Bash unavailable')
    def test_download_checksum_execution_guard(self):
        payload=b"#!/usr/bin/env bash\nprintf 'FIXTURE_EXECUTED\\n'\n"
        class Handler(http.server.BaseHTTPRequestHandler):
            scenario='valid'
            def do_GET(self):
                if self.scenario=='download_error':self.send_error(404);return
                if self.path=='/redirect':
                    self.send_response(302);self.send_header('Location','/payload');self.end_headers();return
                body=payload if self.scenario=='valid' else payload+b'# corruption\n'
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*args):pass
        records=[]
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);(root/'ipv6.sh').write_bytes(payload)
            unixroot=subprocess.check_output([BASH,'--noprofile','--norc','-c','pwd -P'],cwd=root,text=True).strip()
            with http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler) as server:
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                try:
                    with patch.object(command,'R',root):original=command.command(REF)
                    url='https://raw.githubusercontent.com/InkoParadox/server-tools/'+REF+'/ipv6.sh'
                    tested=original.replace('cd /root',"cd '"+unixroot+"'").replace(url,'http://127.0.0.1:'+str(server.server_port)+'/redirect')
                    for scenario in ('valid','checksum_error','download_error'):
                        Handler.scenario=scenario
                        p=subprocess.run([BASH,'--noprofile','--norc','-c',tested],capture_output=True,text=True,timeout=30)
                        downloaded=root/('mist-ipv6-'+hashlib.sha256(payload).hexdigest()[:12]+'.sh')
                        record=dict(scenario=scenario,command=tested,returncode=p.returncode,stdout=p.stdout,stderr=p.stderr,expected_sha256=hashlib.sha256(payload).hexdigest(),downloaded_sha256=hashlib.sha256(downloaded.read_bytes()).hexdigest() if downloaded.exists() else None)
                        records.append(record)
                        if os.environ.get('MIST_COMMAND_EVIDENCE'):
                            pathlib.Path(os.environ['MIST_COMMAND_EVIDENCE']).write_text(json.dumps(records,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
                        with self.subTest(scenario=scenario):
                            if scenario=='valid':
                                self.assertEqual(p.returncode,0,p.stderr);self.assertIn('FIXTURE_EXECUTED',p.stdout)
                                self.assertEqual(record['downloaded_sha256'],record['expected_sha256'])
                            else:self.assertNotEqual(p.returncode,0);self.assertNotIn('FIXTURE_EXECUTED',p.stdout)
                finally:server.shutdown();thread.join()

if __name__=='__main__':unittest.main(verbosity=2)
