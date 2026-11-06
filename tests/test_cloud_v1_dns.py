"""Regression for cloud-init v1 IPv6 nameservers on an IPv4-only VPS."""
import base64
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from embedded import new_engine


class CloudV1DNS(unittest.TestCase):
    def setUp(self):
        self.e = new_engine()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.e.ROOT = pathlib.Path(self.tmp.name)
        for name in ('/var/lib/cloud/instance', '/etc/cloud/cloud.cfg.d', '/proc'):
            self.e.p(name).mkdir(parents=True, exist_ok=True)
        self.e.p('/proc/cmdline').write_text('')

    def run_plan(self, config):
        cache = self.e.p('/var/lib/cloud/instance/network-config.json')
        original = json.dumps({'version': 1, 'config': config})
        cache.write_text(original)
        with patch.object(self.e.shutil, 'which', return_value='/usr/bin/cloud-init'), patch.object(
            self.e.Plan, 'cloud_other_regeneration'
        ) as render:
            plan = self.e.Plan()
            plan.cloud()
        render.assert_called_once()
        self.assertEqual(cache.read_text(), original)
        encoded = plan.changes['/etc/cloud/cloud.cfg.d/zzzz-mist-ipv6.cfg']['data']
        return self.e.yaml_load(base64.b64decode(encoded).decode())['network']['config']

    def test_mixed_ipv4_ipv6_preserves_ipv4_and_search(self):
        base = [{'type':'nameserver','address':['1.1.1.1','2001:4860:4860::8888','8.8.8.8'],'search':['example.com']},
                {'type':'physical','name':'eth0','subnets':[{'type':'dhcp4'}]}]
        want = [{'type':'nameserver','address':['1.1.1.1','8.8.8.8'],'search':['example.com']},
                {'type':'physical','name':'eth0','subnets':[{'type':'dhcp4'}]}]
        self.assertEqual(self.run_plan(base), want)

    def test_only_ipv6_nameserver_removed(self):
        self.assertEqual(self.run_plan([{'type':'nameserver','address':['2001:4860:4860::8888']}]), [])

    def test_only_ipv6_dns_with_search_keeps_search(self):
        self.assertEqual(self.run_plan([{'type':'nameserver','address':['2001:4860:4860::8888'],'search':['example.com']}]),
                         [{'type':'nameserver','address':[],'search':['example.com']}])

    def test_ipv4_only_is_unchanged(self):
        config=[{'type':'nameserver','address':['1.1.1.1','8.8.8.8']}]
        self.assertEqual(self.run_plan(config), config)

    def test_ipv6_string_removed(self):
        self.assertEqual(self.run_plan([{'type':'nameserver','address':'2001:4860:4860::8888'}]), [])

    def test_ipv4_string_kept(self):
        config=[{'type':'nameserver','address':'1.1.1.1'}]
        self.assertEqual(self.run_plan(config), config)

    def test_bad_types_fail_closed(self):
        for value in (42, ['1.1.1.1',42], {'address':'1.1.1.1'}):
            with self.subTest(value=value):
                with self.assertRaises(self.e.Stop):
                    self.run_plan([{'type':'nameserver','address':value}])

    def test_ipv4_dhcp_dns_mtu_and_routes_survive(self):
        route = {'destination': '192.0.2.0/24', 'gateway': '198.51.100.1', 'metric': 90}
        subnet = {
            'type': 'dhcp4',
            'dns_nameservers': ['1.1.1.1', '2001:db8::53'],
            'dns_search': ['example.com'],
            'routes': [route, {'network': '2001:db8::', 'prefix': 32}],
        }
        interface = {'type': 'physical', 'name': 'eth0', 'mtu': 1420, 'accept-ra': True,
                     'subnets': [subnet, {'type': 'dhcp6'}, {'type': 'static6', 'ip_address': '2001:db8::2/64'}]}
        top_route = {'type': 'route', 'destination': 'default', 'gateway': '2001:db8::1'}
        expected = dict(interface, **{'accept-ra': False}, subnets=[dict(subnet, dns_nameservers=['1.1.1.1'], routes=[route])])
        self.assertEqual(self.run_plan([interface, top_route]), [expected])
        self.assertEqual(self.run_plan([expected]), [expected])

    def test_ipv6_subnet_with_ipv4_resolver_fails_closed(self):
        interface = {'type': 'physical', 'name': 'eth0', 'subnets': [
            {'type': 'static6', 'address': '2001:db8::2/64', 'dns_nameservers': ['1.1.1.1']}
        ]}
        with self.assertRaisesRegex(self.e.Stop, 'IPv6 subnet carries IPv4'):
            self.run_plan([interface])

    def test_changed_cache_stops_plan(self):
        cache = self.e.p('/var/lib/cloud/instance/network-config.json')
        cache.write_text('{"version":1,"config":[]}')
        with patch.object(self.e.shutil, 'which', return_value='/usr/bin/cloud-init'), patch.object(
            self.e.Plan, 'cloud_other_regeneration', side_effect=lambda _: cache.write_text('{"version":2}')
        ), self.assertRaisesRegex(self.e.Stop, 'network cache changed'):
            self.e.Plan().cloud()

    def test_networkd_boot_render_must_preserve_ipv4(self):
        engine = self.e
        path = '/etc/systemd/network/10-cloud-init-eth0.network'
        engine.p(path).parent.mkdir(parents=True)
        engine.p('/etc/os-release').write_text('ID=ubuntu\n')
        engine.p('/proc/sys/kernel/random').mkdir(parents=True)
        engine.p('/proc/sys/kernel/random/boot_id').write_text('boot')
        original = '[Match]\nName=eth0\n[Network]\nDHCP=ipv4\nDNS=1.1.1.1\n'
        engine.p(path).write_text(original)

        def run_render(args):
            root = pathlib.Path(args[args.index('--directory') + 1])
            target = root / path.lstrip('/')
            target.parent.mkdir(parents=True)
            target.write_bytes(rendered.encode())

        for rendered in (original + 'IPv6AcceptRA=no\n', original.replace('1.1.1.1', '8.8.8.8')):
            plan = engine.Plan()
            plan.owners['eth0'] = 'networkd'
            record = plan.watch(path)
            with patch.object(engine, 'run', side_effect=run_render):
                if '8.8.8.8' in rendered:
                    with self.assertRaisesRegex(engine.Stop, 'would change non-IPv6 settings'):
                        plan.cloud_other_regeneration({'version': 1, 'config': []})
                else:
                    plan.cloud_other_regeneration({'version': 1, 'config': []})
                    self.assertEqual(record['owner_regeneration']['sha256'], [engine.sha(rendered.encode())])

    def test_cloud_v2_overlay_refuses_reinherited_gateway6(self):
        self.e.p('/etc/cloud/cloud.cfg').write_text(
            'network: {version: 2, ethernets: {eth0: {dhcp4: true, gateway6: "2001:db8::1"}}}\n'
        )
        with patch.object(self.e.shutil, 'which', return_value='/usr/bin/cloud-init'), self.assertRaisesRegex(
            self.e.Stop, 'system merge would retain or override network settings'
        ):
            self.e.Plan().cloud()

    def test_cloud_v2_netplan_source_preserves_merged_ipv4(self):
        engine = self.e
        network = {'version': 2, 'ethernets': {'eth0': {'dhcp4': True, 'mtu': 1420, 'dhcp6': True}}}
        engine.p('/etc/cloud/cloud.cfg').write_text('network: {version: 2, ethernets: {eth0: {dhcp4: true}}}\n')
        engine.p('/etc/cloud/cloud.cfg.d/90-mtu.cfg').write_text('network: {ethernets: {eth0: {mtu: 1420}}}\n')
        path = '/etc/netplan/50-cloud-init.yaml'
        engine.p(path).parent.mkdir(parents=True)
        engine.p(path).write_bytes(engine.yaml_dump({'network': network}))
        engine.p('/proc/sys/kernel/random').mkdir(parents=True)
        engine.p('/proc/sys/kernel/random/boot_id').write_text('boot')
        plan = engine.Plan()
        plan.netplan_before = {'network': network}
        plan.watch(path)
        with patch.object(engine.shutil, 'which', return_value='/usr/bin/cloud-init'), patch.object(
            engine, 'cloud_netplan_renderings', return_value=['example-hash']
        ) as render:
            plan.cloud()
        expected = engine.strip_netplan({'network': network})
        render.assert_called_once_with(expected['network'])
        owner = plan.changes['/etc/cloud/cloud.cfg.d/zzzz-mist-ipv6.cfg']
        self.assertEqual(engine.yaml_load(base64.b64decode(owner['data']).decode()), expected)


if __name__=='__main__':
    unittest.main()
