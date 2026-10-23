"""Generated-file race checks; real filesystem metadata, no native manager claim."""
import os
import pathlib
import tempfile
import unittest
from embedded import new_engine


class GeneratedConfig(unittest.TestCase):
    def setUp(self):
        self.e = new_engine()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.e.ROOT = pathlib.Path(self.temp.name)
        self.path = '/run/systemd/network/10-netplan-enp1s0.network'
        self.q = self.e.p(self.path)
        self.q.parent.mkdir(parents=True)
        self.q.write_bytes(b'[Match]\nName=enp1s0\n[Network]\nDHCP=ipv4\n')
        self.q.chmod(0o600)
        self.record = self.e.file_record(self.path)

    def test_identical_generator_replacement_passes_race_check(self):
        plan = self.e.Plan()
        plan.watch(self.path)
        plan.inventory = plan.watch_globs()
        replacement = self.q.with_name('replacement')
        replacement.write_bytes(self.q.read_bytes())
        replacement.chmod(self.record['mode'])
        os.utime(replacement, ns=(self.record['atime'], self.record['mtime'] + 1000000000))
        os.replace(replacement, self.q)
        self.assertNotEqual(self.q.stat().st_mtime_ns, self.record['mtime'])
        self.e.race_check(plan)

    def test_real_generated_file_conflicts_still_stop(self):
        original = self.q.read_bytes()
        for kind in ('content', 'mode', 'uid', 'gid', 'xattr'):
            with self.subTest(kind=kind):
                self.e.atomic(self.q, original, self.record['mode'],
                              (self.record['uid'], self.record['gid']),
                              (self.record['atime'], self.record['mtime']), attrs={})
                if kind == 'content':
                    self.q.write_bytes(original + b'# foreign change\n')
                    os.utime(self.q, ns=(self.record['atime'], self.record['mtime']))
                elif kind == 'mode':
                    self.q.chmod(0o640)
                elif kind == 'uid':
                    os.chown(self.q, 1, -1)
                elif kind == 'gid':
                    os.chown(self.q, -1, 1)
                else:
                    os.setxattr(self.q, 'user.foreign', b'change')
                plan = self.e.Plan()
                plan.watched[self.path] = self.record
                plan.inventory = plan.watch_globs()
                with self.assertRaisesRegex(self.e.Stop, 'concurrent config modification'):
                    self.e.race_check(plan)

    def test_other_configuration_timestamps_remain_strict(self):
        for path in ('/etc/netplan/50-cloud-init.yaml', '/run/systemd/network/other.network'):
            with self.subTest(path=path):
                q = self.e.p(path)
                q.parent.mkdir(parents=True, exist_ok=True)
                q.write_bytes(b'unchanged')
                q.chmod(0o600)
                record = self.e.file_record(path)
                os.utime(q, ns=(record['atime'], record['mtime'] + 1000000000))
                self.assertFalse(self.e.matches(path, record))
