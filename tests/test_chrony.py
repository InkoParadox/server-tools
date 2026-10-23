"""Regression tests for the embedded engine; no host network/sysctl writes."""
import base64
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'ipv6.sh'


def load_engine():
    launcher = SCRIPT.read_bytes()
    tag = re.search(rb"<<'(MIST_ENGINE_EXACT_[A-F0-9]+)'\n", launcher)
    engine = launcher[tag.end():].split(b'\n' + tag[1] + b'\n', 1)[0] + b'\n'
    code = engine.split(b"<<'MIST_PYTHON'\n", 1)[1].rsplit(b'\nMIST_PYTHON', 1)[0]
    api = {'__name__': 'mist_engine_test'}
    exec(compile(code, str(SCRIPT), 'exec'), api)
    return launcher, engine, api


def listener(address, port=323, pid=849, name='chronyd', proto='udp', extra=''):
    peer = '[::]:*' if ':' in address else '0.0.0.0:*'
    users = '' if pid is None else f'users:(("{name}",pid={pid},fd=5))'
    return f'{proto} UNCONN 0 0 {address}:{port} {peer} {users} {extra}\n'


def source(address='203.0.113.8', state='*', mode='^'):
    return f'{mode},{state},{address},2,10,377,471,-0.000084,-0.000151,0.007392\n'


class ChronyTests(unittest.TestCase):
    def setUp(self):
        self.launcher, self.engine, self.api = load_engine()
        self.tmp = tempfile.TemporaryDirectory(prefix='mist-chrony-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.api['ROOT'] = self.root
        proc = self.root / 'proc/849'
        proc.mkdir(parents=True)
        binary = self.root / 'bin/chronyd'
        binary.parent.mkdir()
        binary.touch()
        (proc / 'exe').symlink_to(binary)
        self.ndp = self.root / 'proc/sys/net/ipv6/conf/lo/proxy_ndp'
        self.ndp.parent.mkdir(parents=True)
        self.ndp.write_text('0')
        self.before = {'links': [], 'resolver': {'data': base64.b64encode(b'nameserver 1.1.1.1\n').decode()}}
        self.ss6 = listener('[::1]')
        self.ss4 = listener('127.0.0.1')
        self.tcp6 = ''
        self.udp6 = ''
        self.csv = source()
        self.has_chronyc = True
        self.monitor_error = None
        self.calls = []
        self.api['run'] = self.run_command
        self.api['active'] = lambda unit: False
        which = patch.object(self.api['shutil'], 'which', self.which)
        which.start()
        self.addCleanup(which.stop)

    def which(self, name):
        return '/usr/bin/chronyc' if name == 'chronyc' and self.has_chronyc else None

    def run_command(self, args, check=True, timeout=60, stdin=None):
        self.calls.append(tuple(args))
        if args == ['ss', '-6', '-Htn', 'state', 'established']:
            out = self.tcp6
        elif args == ['ss', '-6', '-Huan']:
            out = self.udp6
        elif args == ['ss', '-6', '-H', '-lntu', '-e', '-p']:
            out = self.ss6
        elif args == ['ss', '-4', '-H', '-lntu', '-e', '-p']:
            out = self.ss4
        elif args == ['chronyc', '-n', '-c', '-h', '127.0.0.1', 'sources']:
            self.assertEqual(timeout, 8)
            if self.monitor_error:
                raise self.monitor_error
            out = self.csv
        else:
            self.fail('unexpected command: ' + repr(args))
        return subprocess.CompletedProcess(args, 0, out, '')

    def dependencies(self):
        self.api['dependencies'](self.before)

    def rejects(self, reason):
        with self.assertRaisesRegex(self.api['Stop'], reason):
            self.dependencies()

    def test_same_chronyd_pid_ipv4_monitor_and_selected_ipv4_source(self):
        self.csv = source('203.0.113.7', '-') + source()
        self.dependencies()
        self.assertTrue(self.before['chrony_ipv4_monitor'])

    def test_no_generic_exception_for_port_or_process_name(self):
        cases = [
            (listener('[::1]', name='other'), listener('127.0.0.1', name='other')),
            (listener('[::1]', proto='tcp'), listener('127.0.0.1', proto='tcp')),
            (listener('[::1]', port=123), listener('127.0.0.1', port=123)),
            (listener('[2001:db8::1]'), self.ss4),
            (listener('[fe80::1%eth0]'), self.ss4),
            (listener('[::1]', pid=None), self.ss4),
        ]
        for ipv6, ipv4 in cases:
            with self.subTest(ipv6=ipv6):
                self.ss6, self.ss4 = ipv6, ipv4
                self.rejects('explicit IPv6 listener dependency')

    def test_missing_ipv4_pair_stops(self):
        self.ss4 = ''
        self.rejects('explicit IPv6 listener dependency')

    def test_pair_from_another_process_stops(self):
        self.ss4 = listener('127.0.0.1', pid=850)
        self.rejects('explicit IPv6 listener dependency')

    def test_ipv4_wildcard_is_not_the_verified_loopback_pair(self):
        self.ss4 = listener('0.0.0.0')
        self.rejects('explicit IPv6 listener dependency')

    def test_second_process_cannot_share_the_exception(self):
        self.ss6 += listener('[::1]', port=8080, name='other')
        self.rejects('explicit IPv6 listener dependency')

    def test_process_name_without_matching_executable_stops(self):
        exe = self.root / 'proc/849/exe'
        exe.unlink()
        exe.symlink_to(self.root / 'bin/other')
        self.rejects('explicit IPv6 listener dependency')

    def test_disappeared_process_stops(self):
        (self.root / 'proc/849/exe').unlink()
        self.rejects('cannot identify the executable')

    def test_selected_or_backup_ipv6_time_source_stops(self):
        for state in ('*', '-', '?'):
            with self.subTest(state=state):
                self.csv = source() + source('2001:db8::8', state)
                self.rejects('chronyd has an IPv6 time source')

    def test_no_selected_ipv4_time_source_stops(self):
        for data in ('', source(state='-'), source('GPS', mode='#')):
            with self.subTest(data=data):
                self.csv = data
                self.rejects('chronyd has no selected IPv4 time source')

    def test_reference_clock_is_allowed_alongside_selected_ipv4(self):
        self.csv = source() + source('GPS', '-', '#')
        self.dependencies()

    def test_malformed_csv_is_not_treated_as_a_verified_source(self):
        for data in ('^,*,203.0.113.8\n', 'MS Name/IP address\n', source(mode='!'), source(state='!')):
            with self.subTest(data=data):
                self.csv = data
                self.rejects('unrecognised chronyc sources CSV format')

    def test_hostname_is_not_accepted_as_a_proven_ipv4_address(self):
        self.csv = source('ntp.example.invalid')
        self.rejects('no verified IP address')

    def test_missing_chronyc_stops_without_installing(self):
        self.has_chronyc = False
        self.rejects('chronyc required')

    def test_monitor_failure_or_timeout_stops(self):
        for error in (self.api['Stop']('monitor unavailable'), subprocess.TimeoutExpired('chronyc', 8)):
            with self.subTest(error=error):
                self.monitor_error = error
                with self.assertRaises(type(error)):
                    self.dependencies()

    def test_established_ipv6_tcp_still_stops(self):
        self.tcp6 = '0 0 [2001:db8::1]:80 [2001:db8::2]:12345\n'
        self.rejects('established IPv6 TCP connection')

    def test_connected_ipv6_udp_still_stops(self):
        self.udp6 = 'ESTAB 0 0 [::1]:6000 [::1]:323\n'
        self.rejects('connected IPv6 UDP socket')

    def test_ipv6_dns_still_stops(self):
        self.before['resolver']['data'] = base64.b64encode(b'nameserver 2001:db8::53\n').decode()
        self.rejects('IPv6 resolver endpoint')

    def test_proxy_ndp_still_stops(self):
        self.ndp.write_text('1')
        self.rejects('IPv6 proxy NDP')

    def test_ipv6_only_wildcard_without_pair_still_stops(self):
        self.ss6 = listener('[::]', port=443, proto='tcp', name='sshd', extra='v6only:1')
        self.ss4 = ''
        self.rejects('IPv6-only listener has no IPv4 listener')

    def test_existing_dual_stack_and_paired_wildcard_behaviour(self):
        self.ss6 = listener('[::]', port=443, proto='tcp', name='sshd', extra='v6only:0')
        self.ss4 = ''
        self.dependencies()
        self.ss6 = self.ss6.replace('v6only:0', 'v6only:1')
        self.ss4 = listener('0.0.0.0', port=443, proto='tcp', name='sshd')
        self.dependencies()
        self.assertNotIn('chrony_ipv4_monitor', self.before)

    def prepare_postcheck(self):
        self.before.update(dns_probe_ok=False, chrony_ipv4_monitor=True)
        self.api['wait4'] = lambda before: {'knobs': {'all': {'disable_ipv6': 1}}, 'addr6': [], 'routes6': []}

    def test_postcheck_revalidates_chrony_over_ipv4(self):
        self.prepare_postcheck()
        self.api['verify_off'](self.before)
        self.assertEqual(len(self.calls), 1)

    def test_lost_monitor_or_time_source_fails_postcheck(self):
        self.prepare_postcheck()
        for error, data in ((self.api['Stop']('monitor lost'), source()), (None, source(state='?')), (None, source() + source('2001:db8::8'))):
            with self.subTest(error=error, data=data):
                self.monitor_error, self.csv = error, data
                with self.assertRaises(self.api['Stop']):
                    self.api['verify_off'](self.before)

    def test_hosts_without_exception_do_not_gain_a_chronyc_dependency(self):
        self.prepare_postcheck()
        self.before.pop('chrony_ipv4_monitor')
        self.has_chronyc = False
        self.api['verify_off'](self.before)
        self.assertFalse(self.calls)

    def test_launcher_hashes_and_embedded_syntax(self):
        digest = hashlib.sha256(self.engine).hexdigest().encode()
        self.assertEqual(self.launcher.count(digest), 2)
        subprocess.run(['bash', '-n'], input=self.launcher, check=True)
        self.assertEqual(self.api['VERSION'], '2.3')

    def test_noop_repeated_run_still_requires_no_network_writes(self):
        self.before.update(knobs={'lo': {'disable_ipv6': 1}}, addr6=[], routes6=[])
        plan = type('PlanFixture', (), {'changes': {}, 'owners': {'eth0': 'netplan/networkd'}})()
        events = []
        self.api.update(ssh_session=lambda **kw: {'tuple':['203.0.113.1', '50000', '203.0.113.2', '22']}, connection_live=lambda proof: True,
                        pending=lambda: [], discover=lambda: (plan, self.before), validate_plan=lambda plan: None,
                        emit=lambda **event: events.append(event))
        self.dependencies()
        self.api['apply'](240)
        self.assertEqual(events, [{'status': 'NOOP', 'owners': plan.owners}])
        self.assertFalse((self.root / 'var/lib/mist-ipv6').exists())

    def test_monitor_failure_after_apply_enters_existing_restore_path(self):
        self.dependencies()
        self.before.update(knobs={'lo': {'disable_ipv6': 0}}, addr6=[], routes6=[],
                           links=[{'ifname':'eth0','flags':['UP'],'operstate':'UP'}], addr4=[{'ifname':'eth0','addr_info': [{'family':'inet','local': '203.0.113.2'}]}], routes4=[{'dst':'default','dev':'eth0'}], dns_probe_ok=False)
        for name, value in (('etc/machine-id', 'test-machine'), ('proc/sys/kernel/random/boot_id', 'test-boot')):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
        tool = self.root / 'engine.sh'
        tool.write_bytes(self.engine)
        tool.chmod(0o700)
        plan = type('PlanFixture', (), {'changes': {}, 'owners': {}, 'watched': {}, 'actions': [], 'inventory': []})()
        restored, armed, events, writes = [], [], [], []

        def apply_actions(actions):
            self.monitor_error = self.api['Stop']('monitor lost after apply')

        self.api.update(ssh_session=lambda **kw: {'tuple':['203.0.113.1', '50000', '203.0.113.2', '22']}, connection_live=lambda proof: True,
                        pending=lambda: [], discover=lambda: (plan, self.before), validate_plan=lambda plan: None,
                        arm=lambda d, seconds: armed.append(d), race_check=lambda plan: None,
                        apply_actions=apply_actions, verify_nm=lambda actions: None,
                        wait4=lambda before: {'knobs': {'lo': {'disable_ipv6': 1}}, 'addr6': [], 'routes6': []},
                        knobs=lambda: {'lo': {}}, set_knob=lambda *args: writes.append(args),
                        restore=lambda d: restored.append(d), emit=lambda **event: events.append(event))
        with patch.dict(os.environ, MIST_IPV6_SELF=str(tool)):
            with self.assertRaisesRegex(self.api['Stop'], 'monitor lost after apply'):
                self.api['apply'](240)
        self.assertEqual(restored, armed)
        self.assertEqual(len(restored), 1)
        self.assertEqual(writes, [('lo', 'disable_ipv6', 1)])
        self.assertFalse(events)
        self.assertEqual((restored[0] / 'apply-error.txt').read_text(), 'monitor lost after apply')
        _, backup = self.api['load'](restored[0])
        self.assertTrue(backup['before']['chrony_ipv4_monitor'])

    def test_failed_chrony_confirmation_keeps_watchdog_armed(self):
        boot = self.root / 'proc/sys/kernel/random/boot_id'
        boot.parent.mkdir(parents=True)
        boot.write_text('test-boot')
        self.prepare_postcheck()
        self.before.update(links=[{'ifname':'eth0','flags':['UP'],'operstate':'UP'}],addr4=[{'ifname':'eth0','addr_info':[{'family':'inet','local':'203.0.113.2'}]}],routes4=[{'dst':'default','dev':'eth0'}])
        self.csv = source(state='?')
        disarmed, states = [], []
        self.api.update(load=lambda d: (Path(d), {'ssh': ['203.0.113.1', '50000', '203.0.113.2', '22'],
                                                'transport': {'tuple': [], 'boot_id':'test-boot', 'inode':'1'}, 'boot': 'test-boot', 'before': self.before}),
                        read_status=lambda d: {'status': 'awaiting_confirmation', 'deadline_monotonic': 10**20, 'boot':'test-boot', 'confirmation_ready_ticks':1},
                        ssh_session=lambda **kw: {'tuple':['203.0.113.1', '50001', '203.0.113.2', '22'], 'boot_id':'test-boot','inode':'2','sshd_start_ticks':2}, connection_live=lambda proof: True,
                        active=lambda unit: True, disarm=lambda d: disarmed.append(d),
                        status_write=lambda *args, **kwargs: states.append(args))
        with self.assertRaisesRegex(self.api['Stop'], 'no selected IPv4 time source'):
            self.api['confirm']('/var/lib/mist-ipv6/tx-test')
        self.assertFalse(disarmed)
        self.assertFalse(states)


if __name__ == '__main__':
    unittest.main(verbosity=2)
