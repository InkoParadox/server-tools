"""Virtual-duration SSH regression; this does not substitute for native manager tests."""
import contextlib,importlib.util,io,json,pathlib,subprocess,sys,unittest
from unittest.mock import patch
R=pathlib.Path(__file__).resolve().parents[1]
class Process:
    def __init__(self,duration,events,exit_code=0):
        self.duration=duration;self.payload=''.join(json.dumps(x)+'\n' for x in events).encode();self.returncode=exit_code;self.finished=False;self.terminated=False;self.timeouts=[]
    def communicate(self,data,timeout=None):
        self.timeouts.append(timeout)
        if timeout is not None and timeout<self.duration:raise subprocess.TimeoutExpired('ssh',timeout)
        self.finished=True;return self.payload,None
    def terminate(self):self.terminated=True
    def kill(self):self.terminated=True
    def wait(self,timeout=None):return self.returncode
class WrapperTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('ipv6_client',R/'ipv6_ssh.py');self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.tx='/var/lib/mist-ipv6/tx-test-1234';self.calls=[]
    @contextlib.contextmanager
    def execution(self,processes,*extra):
        stream=io.TextIOWrapper(io.BytesIO(),encoding='utf-8');err=io.StringIO();queue=iter(processes)
        def spawn(argv,**kw):self.calls.append(argv);return next(queue)
        with patch.object(sys,'argv',['ipv6_ssh.py','test-host','--source',str(R/'ipv6.sh'),*extra]),patch.object(sys,'stdout',stream),patch.object(sys,'stderr',err),patch.object(self.m.subprocess,'Popen',spawn):
            yield stream,err
    def test_slow_rollback_is_allowed_to_finish(self):
        process=Process(650,[dict(status='ROLLED_BACK',transaction=self.tx),dict(status='STOP',reason='apply failed after delayed preflight')],1)
        with self.execution([process],'--rollback-seconds','600') as (out,err):
            with self.assertRaisesRegex(RuntimeError,'server reported ROLLED_BACK'):self.m.main()
            self.assertIn(b'ROLLED_BACK',out.buffer.getvalue())
        self.assertTrue(process.finished);self.assertFalse(process.terminated);self.assertEqual(process.timeouts,[None]);self.assertEqual(len(self.calls),1)
    def test_long_preflight_and_confirmation_cleanup_keep_fresh_tcp(self):
        apply=Process(700,[dict(status='AWAITING_CONFIRMATION',transaction=self.tx,tool=self.tx+'/tool.sh',seconds=240)])
        confirm=Process(260,[dict(status='COMMITTED',transaction=self.tx)])
        with self.execution([apply,confirm]):self.m.main()
        self.assertEqual(len(self.calls),2)
        for argv in self.calls:
            for option in ('ControlMaster=no','ControlPath=none','StrictHostKeyChecking=yes','ServerAliveInterval=15','ServerAliveCountMax=3'):self.assertIn(option,argv)
        self.assertTrue(apply.finished and confirm.finished);self.assertFalse(apply.terminated or confirm.terminated);self.assertEqual(apply.timeouts+confirm.timeouts,[None,None])
    def test_real_transport_error_does_not_attempt_confirmation(self):
        process=Process(45,[],255)
        with self.execution([process]):
            with self.assertRaisesRegex(RuntimeError,'exit 255'):self.m.main()
        self.assertEqual(len(self.calls),1);self.assertFalse(process.terminated)
if __name__=='__main__':unittest.main(verbosity=2)
