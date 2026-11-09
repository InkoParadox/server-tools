"""Permanent loader guards; all HTTP and script execution are mocked."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import zlib
from unittest.mock import patch

R = pathlib.Path(__file__).resolve().parents[1]

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

latest = module('latest_under_test', R / 'tools/latest.py')
command = module('command_under_test', R / 'tools/command.py')
SHA1, SHA2 = 'a' * 40, 'b' * 40

class Response(io.BytesIO):
    def __init__(self, body, length=None):
        super().__init__(body)
        self.headers = {'Content-Length': str(len(body) if length is None else length)}

class LatestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.head = SHA1
        self.responses = {}
        self.lengths = {}
        self.requests = []
        self.executions = []
        self.folders = []
        self.api_body = None
        self.move_after_api = None
        self.publish(SHA1, '2.3.4')
        self.old_umask = os.umask(0o077)
        os.umask(self.old_umask)
        real_mkdtemp = tempfile.mkdtemp
        def make_folder(**kwargs):
            self.assertEqual(kwargs['dir'], '/root')
            folder = pathlib.Path(real_mkdtemp(prefix=kwargs['prefix'], dir=self.root))
            self.folders.append(folder)
            return str(folder)
        def execute(args, **kwargs):
            self.assertEqual(kwargs, {'check': False})
            self.executions.append(args)
            return subprocess.CompletedProcess(args, 0)
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(patch.object(latest.os, 'geteuid', return_value=0, create=True))
        self.stack.enter_context(patch.object(latest.tempfile, 'mkdtemp', side_effect=make_folder))
        self.stack.enter_context(patch.object(latest.urllib.request, 'urlopen', side_effect=self.urlopen))
        self.stack.enter_context(patch.object(latest.subprocess, 'run', side_effect=execute))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def tearDown(self):
        self.stack.close()
        os.umask(self.old_umask)
        self.tmp.cleanup()

    def publish(self, sha, version):
        script = ("#!/usr/bin/env bash\r\nVERSION='" + version + "'\r\n").encode()
        self.responses[latest.RAW + sha + '/ipv6.sh'] = script
        self.responses[latest.RAW + sha + '/SHA256SUMS'] = (
            hashlib.sha256(script).hexdigest() + '  ipv6.sh\r\n' + '0' * 64 + '  other.txt\r\n').encode()

    def urlopen(self, request, timeout):
        self.assertEqual(timeout, 25)
        url = request.full_url
        self.requests.append(url)
        if url == latest.API:
            body = self.api_body if self.api_body is not None else json.dumps({'sha': self.head}).encode()
            if self.move_after_api is not None:
                self.head = self.move_after_api
        else:
            if url not in self.responses:
                raise urllib.error.HTTPError(url, 404, 'missing fixture', {}, None)
            body = self.responses[url]
        if isinstance(body, Exception):
            raise body
        return Response(body, self.lengths.get(url))

    def rejected(self, args=None):
        with self.assertRaises((ValueError, KeyError, urllib.error.HTTPError, FileExistsError)):
            latest.main([] if args is None else args)
        self.assertEqual(self.executions, [])

    def test_success_crlf_receipt_and_private_saved_files(self):
        self.assertEqual(latest.main([]), 0)
        folder = self.folders[0]
        receipt = json.loads((folder / 'verified.json').read_text())
        self.assertEqual(receipt['commit'], SHA1)
        self.assertEqual(receipt['version'], '2.3.4')
        self.assertEqual(receipt['sha256'], hashlib.sha256((folder / 'ipv6.sh').read_bytes()).hexdigest())
        self.assertEqual(self.executions, [['bash', str(folder / 'ipv6.sh')]])
        if os.name == 'posix':
            self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
            for name in ('ipv6.sh', 'SHA256SUMS', 'verified.json'):
                self.assertEqual((folder / name).stat().st_mode & 0o777, 0o600)

    def test_check_forwarded(self):
        latest.main(['--check'])
        self.assertEqual(self.executions[0][-1], '--check')

    def test_corrupt_checksum_never_executes(self):
        self.responses[latest.RAW + SHA1 + '/ipv6.sh'] += b'# corrupted\n'
        self.rejected()

    def test_missing_exact_checksum_never_executes(self):
        self.responses[latest.RAW + SHA1 + '/SHA256SUMS'] = ('0' * 64 + '  other.txt\n').encode()
        self.rejected()

    def test_duplicate_checksum_never_executes(self):
        value = self.responses[latest.RAW + SHA1 + '/SHA256SUMS']
        self.responses[latest.RAW + SHA1 + '/SHA256SUMS'] = value + value
        self.rejected()

    def test_missing_source_http_error_has_no_fallback(self):
        del self.responses[latest.RAW + SHA1 + '/ipv6.sh']
        self.rejected()
        self.assertEqual(self.requests, [latest.API, latest.RAW + SHA1 + '/ipv6.sh'])

    def test_api_http_error_has_no_fallback(self):
        self.api_body = urllib.error.HTTPError(latest.API, 503, 'unavailable', {}, None)
        self.rejected()
        self.assertEqual(self.requests, [latest.API])

    def test_incomplete_response_never_executes(self):
        url = latest.RAW + SHA1 + '/ipv6.sh'
        self.lengths[url] = len(self.responses[url]) + 1
        self.rejected()

    def test_main_moves_after_api_both_files_remain_pinned(self):
        self.publish(SHA2, '2.4.0')
        self.move_after_api = SHA2
        latest.main([])
        self.assertEqual(self.requests, [latest.API, latest.RAW + SHA1 + '/ipv6.sh', latest.RAW + SHA1 + '/SHA256SUMS'])
        receipt = json.loads((self.folders[0] / 'verified.json').read_text())
        self.assertEqual(receipt['commit'], SHA1)

    def test_unchanged_command_resolves_new_main_each_invocation(self):
        permanent = command.latest_command()
        latest.main([])
        self.publish(SHA2, '2.4.0')
        self.head = SHA2
        latest.main([])
        self.assertEqual(command.latest_command(), permanent)
        receipts = [json.loads((folder / 'verified.json').read_text()) for folder in self.folders]
        self.assertEqual([(x['commit'], x['version']) for x in receipts], [(SHA1, '2.3.4'), (SHA2, '2.4.0')])
        self.assertNotEqual(self.folders[0], self.folders[1])
        self.assertEqual(self.requests.count(latest.API), 2)

    def test_malformed_sha_and_json_never_execute(self):
        for body in (b'{', b'{}', json.dumps({'sha': 'main'}).encode(), json.dumps({'sha': 'a' * 39}).encode(), json.dumps({'sha': 'A' * 40}).encode(), json.dumps({'sha': None}).encode()):
            with self.subTest(body=body):
                self.api_body = body
                self.rejected()

    def test_exclusive_file_creation_preserves_existing_file(self):
        folder = self.root / 'existing'
        folder.mkdir()
        target = folder / 'ipv6.sh'
        target.write_bytes(b'EXISTING_BYTES')
        with patch.object(latest.tempfile, 'mkdtemp', return_value=str(folder)):
            self.rejected()
        self.assertEqual(target.read_bytes(), b'EXISTING_BYTES')

    def test_invalid_arguments_never_download_or_execute(self):
        self.rejected(['--restore', '/tmp/anything'])
        self.assertEqual(self.requests, [])

class PermanentCommandTests(unittest.TestCase):
    def test_embedded_payload_is_exact_bootstrap_and_no_dollar(self):
        plain = command.latest_command()
        self.assertNotIn('$', plain)
        match = re.search(r'base64.b64decode\("([A-Za-z0-9+/=]+)"\)', plain)
        self.assertIsNotNone(match)
        payload = zlib.decompress(base64.b64decode(match[1]))
        self.assertEqual(payload, (R / 'tools/latest.py').read_bytes())
        compile(payload, 'embedded-latest.py', 'exec')
        self.assertEqual(command.latest_command(check=True), plain + ' --check')

    def test_cli_default_literal_xshell_suffix_and_bash_output(self):
        with tempfile.TemporaryDirectory() as folder:
            target = pathlib.Path(folder) / 'Xshell.txt'
            subprocess.run([sys.executable, str(R / 'tools/command.py'), '--output', str(target)], check=True)
            self.assertEqual(target.read_bytes(), command.latest_command().encode() + b'\\r')
            terminal = pathlib.Path(folder) / 'Bash.txt'
            subprocess.run([sys.executable, str(R / 'tools/command.py'), '--check', '--bash', '--output', str(terminal)], check=True)
            self.assertEqual(terminal.read_bytes(), command.latest_command(check=True).encode() + b'\n')

if __name__ == '__main__':
    unittest.main(verbosity=2)
