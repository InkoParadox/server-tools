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


if __name__=='__main__':
    unittest.main()
