"""Local HTTP stand: moving main, real downloads, truncation and guarded Bash."""
import hashlib,importlib.util,json,pathlib,shlex,subprocess,tempfile,threading,unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[1]

class LatestHTTP(unittest.TestCase):
    def test_real_http_main_updates_race_and_failure_guards(self):
        spec=importlib.util.spec_from_file_location('latest_http_test',ROOT/'tools/latest.py')
        loader=importlib.util.module_from_spec(spec);spec.loader.exec_module(loader)
        old_umask=loader.os.umask(0o077);loader.os.umask(old_umask)
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);marker=root/'executed';state={'main':'a'*40,'move':False,'mode':'ok'};requests=[]
            def script(version):
                return ("#!/usr/bin/env bash\nVERSION='"+version+"'\nprintf '%s\\n' '"+version+"' >> "+shlex.quote(str(marker))+"\n").encode()
            scripts={'a'*40:script('9.0.1'),'b'*40:script('9.0.2')}
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def do_GET(self):
                    requests.append(self.path)
                    if self.path=='/main':
                        data=json.dumps({'sha':state['main']}).encode()
                        if state['move']:state['main']='b'*40
                    else:
                        parts=self.path.strip('/').split('/');commit,name=parts
                        data=scripts[commit] if name=='ipv6.sh' else (hashlib.sha256(scripts[commit]).hexdigest()+'  ipv6.sh\n').encode()
                        if state['mode']=='unavailable':self.send_error(503);return
                        if state['mode']=='bad-sha' and name=='SHA256SUMS':data=b'0'*64+b'  ipv6.sh\n'
                    self.send_response(200)
                    self.send_header('Content-Length',str(len(data)+(10 if state['mode']=='partial' and self.path.endswith('ipv6.sh') else 0)))
                    self.end_headers();self.wfile.write(data)
            server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            url='http://127.0.0.1:'+str(server.server_port)
            original_mkdtemp=tempfile.mkdtemp
            def private(**kwargs):return original_mkdtemp(prefix=kwargs['prefix'],dir=root)
            try:
                with patch.object(loader,'API',url+'/main'),patch.object(loader,'RAW',url+'/'),patch.object(loader.os,'geteuid',return_value=0,create=True),patch.object(loader.tempfile,'mkdtemp',side_effect=private):
                    self.assertEqual(loader.main(['--check']),0)
                    state['main']='b'*40
                    self.assertEqual(loader.main(['--check']),0)
                    self.assertEqual(marker.read_text().splitlines(),['9.0.1','9.0.2'])
                    marker.unlink();requests.clear();state.update(main='a'*40,move=True)
                    self.assertEqual(loader.main(['--check']),0)
                    self.assertEqual(marker.read_text().splitlines(),['9.0.1'])
                    self.assertEqual(requests,['/main','/'+'a'*40+'/ipv6.sh','/'+'a'*40+'/SHA256SUMS'])
                    for mode in ('bad-sha','unavailable','partial'):
                        marker.unlink(missing_ok=True);state.update(mode=mode,move=False)
                        with self.assertRaises(Exception):loader.main(['--check'])
                        self.assertFalse(marker.exists(),mode+' executed unverified script')
            finally:server.shutdown();server.server_close();thread.join();loader.os.umask(old_umask)

if __name__=='__main__':unittest.main()
