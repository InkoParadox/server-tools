"""DNS ownership, permitted deltas and symmetric recovery; no host writes."""
import base64
import copy
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from embedded import new_engine


class ResolverDNS(unittest.TestCase):
    def setUp(self):
        self.e=new_engine()
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.e.ROOT=pathlib.Path(self.tmp.name)
        self.source='/etc/systemd/network/10-test.network'
        self.write(self.source,'[Match]\nName=eth0\n[Network]\nDNS=1.1.1.1\nDNS=2001:db8::53\nDNS=8.8.8.8\nDomains=corp.test ~internal.test\n')
        self.before={'links':[{'ifname':'eth0','ifindex':2}], 'resolver':{
            'link':'/run/systemd/resolve/stub-resolv.conf','data':base64.b64encode(b'nameserver 127.0.0.53\n').decode(),
            'resolved_dns':{'global':[],'eth0':['1.1.1.1','2001:db8::53','8.8.8.8']},
            'resolved_domains':{'global':[],'eth0':['corp.test','~internal.test']},
            'resolved_default_route':{'eth0':['no']},'resolved_dnsovertls':{'global':['no'],'eth0':['no']}}}

    def write(self,path,text):
        q=self.e.p(path);q.parent.mkdir(parents=True,exist_ok=True);q.write_text(text);q.chmod(0o600)

    def plan(self):
        pl=self.e.Plan();pl.owners['eth0']='networkd';pl.dns_sources['eth0']=self.source
        with patch.object(self.e,'dns4_probe') as probe, patch.object(self.e,'run',return_value=subprocess.CompletedProcess([],0,'','')):
            self.e.plan_dns(pl,self.before)
        return pl,probe

    def test_mixed_scope_preserves_order_domains_and_original(self):
        original=copy.deepcopy(self.before['resolver'])
        _,probe=self.plan();after=self.e.resolver_after(self.before)
        self.assertEqual(after['resolved_dns']['eth0'],['1.1.1.1','8.8.8.8'])
        self.assertEqual(after['resolved_domains'],original['resolved_domains'])
        self.assertEqual(after['resolved_default_route'],original['resolved_default_route'])
        self.assertEqual(self.before['resolver'],original)
        self.assertEqual(probe.call_count,4)

    def test_ipv6_only_scope_refuses_even_with_global_ipv4(self):
        self.before['resolver']['resolved_dns']={'global':['9.9.9.9'],'eth0':['2001:db8::53']}
        with self.assertRaisesRegex(self.e.Stop,'eth0 source .*10-test.network.*2001:db8::53.*no IPv4'):
            self.plan()
        self.assertFalse(self.e.p('/var/lib/mist-ipv6').exists())

    def test_unknown_runtime_override_refused(self):
        self.before['resolver']['resolved_dns']['eth0'].append('2001:db8::99')
        with self.assertRaisesRegex(self.e.Stop,'not attributable'):self.plan()

    def test_unknown_ra_domains_refused(self):
        self.before['resolver']['resolved_domains']['eth0'].append('~ra-only.test')
        with self.assertRaisesRegex(self.e.Stop,'DHCPv6/RA'):self.plan()

    def test_dhcpv4_native_dns_and_domains_supported(self):
        self.write(self.source,'[Match]\nName=eth0\n[Network]\nDHCP=yes\nDNS=2001:db8::53\n')
        details=self.details('DHCPv4')
        details['SearchDomains']=[{'Domain':'corp.test','ConfigSource':'DHCPv4'}]
        details['RouteDomains']=[{'Domain':'internal.test','ConfigSource':'DHCPv4'}]
        with patch.object(self.e,'run',side_effect=self.native_run(details)),patch.object(self.e,'dns4_probe'):
            self.e.plan_dns(self.make_plan(),self.before)
        self.assertTrue(self.before['dns_delta'])

    def test_failed_retained_ipv4_probe_refuses_before_write(self):
        with patch.object(self.e,'dns4_probe',side_effect=OSError('timeout')), patch.object(self.e,'run',return_value=subprocess.CompletedProcess([],0,'','')):
            with self.assertRaisesRegex(self.e.Stop,'retained IPv4 DNS 1.1.1.1 unreachable'):
                pl=self.e.Plan();pl.owners['eth0']='networkd';pl.dns_sources['eth0']=self.source;self.e.plan_dns(pl,self.before)

    def test_tls_scope_is_concretely_unsupported(self):
        self.before['resolver']['resolved_dnsovertls']['eth0']=['yes']
        with self.assertRaisesRegex(self.e.Stop,'DNS-over-TLS'):self.plan()

    def test_unknown_owner_refused(self):
        pl=self.e.Plan()
        with self.assertRaisesRegex(self.e.Stop,'eth0 source unknown.*2001:db8::53'):
            self.e.plan_dns(pl,self.before)

    def test_global_persistent_dns_and_fallback_filtered_transactionally(self):
        self.write('/etc/systemd/resolved.conf','[Resolve]\nDNS=1.1.1.1 2001:db8::53\nFallbackDNS=8.8.8.8 2001:db8::54\nDomains=~.\n')
        self.before['resolver']['resolved_dns']['global']=['1.1.1.1','2001:db8::53']
        pl,_=self.plan()
        text=base64.b64decode(pl.changes['/etc/systemd/resolved.conf']['data']).decode()
        self.assertEqual(text,'[Resolve]\nDNS=1.1.1.1\nFallbackDNS=8.8.8.8\nDomains=~.\n')
        self.assertIn({'type':'resolved-restart'},pl.actions)
        self.assertIn('2001:db8::53',self.e.p('/etc/systemd/resolved.conf').read_text())

    def test_runtime_global_override_refused(self):
        self.before['resolver']['resolved_dns']['global']=['1.1.1.1','2001:db8::53']
        with self.assertRaisesRegex(self.e.Stop,'global.*unknown owner'):self.plan()

    def test_global_runtime_writer_refused(self):
        self.write('/run/systemd/resolved.conf.d/provider.conf','[Resolve]\nDNS=1.1.1.1 2001:db8::53\n')
        with self.assertRaisesRegex(self.e.Stop,'unknown runtime resolved writer'):self.plan()

    def test_dns_only6_line_does_not_reset_previous_ipv4(self):
        self.assertEqual(self.e.strip_networkd('[Network]\nDNS=1.1.1.1\nDNS=2001:db8::53\nDNS=8.8.8.8\n'),
                         '[Network]\nDNS=1.1.1.1\nDNS=8.8.8.8\n')
        self.assertIn('DNS=\n',self.e.strip_networkd('[Network]\nDNS=\nDNS=1.1.1.1\n'))

    def test_all_static_adapters_filter_dns_and_preserve_ipv4_order(self):
        e=self.e
        text='iface eth0 inet static\n dns-nameservers 1.1.1.1 2001:db8::53 8.8.8.8\n dns-search corp.test\n'
        self.assertIn('dns-nameservers 1.1.1.1 8.8.8.8',e.strip_interfaces(text))
        self.assertIn('dns-search corp.test',e.strip_interfaces(text))
        key='[connection]\nid=a\n[ipv4]\ndns=1.1.1.1;8.8.8.8;\n[ipv6]\ndns=2001:db8::53;\n'
        self.assertIn('dns=1.1.1.1;8.8.8.8;',e.strip_nm_keyfile(key))
        self.assertNotIn('2001:',e.strip_nm_keyfile(key))
        text='DNS1=1.1.1.1\nDNS2="2001:db8::53"\nDNS3=8.8.8.8\n'
        self.assertIn('DNS1=1.1.1.1\nDNS3=8.8.8.8\n',e.strip_ifcfg(text))

    def test_ipv6_nm_selection_policy_not_discarded(self):
        with self.assertRaisesRegex(self.e.Stop,'selection policy'):
            self.e.strip_nm_keyfile('[ipv6]\ndns=2001:db8::53;\ndns-search=corp.test;\n')

    def test_dns_endpoint_family(self):
        for value in ('1.1.1.1','1.1.1.1:5353','1.1.1.1#name.test'):
            self.assertFalse(self.e.dns_is6(value))
        for value in ('2001:db8::53','fe80::1%eth0','[2001:db8::53]:5353#name.test'):
            self.assertTrue(self.e.dns_is6(value))

    def test_dns_delta_does_not_allow_ipv4_reorder_or_domain_loss(self):
        self.plan();after=self.e.resolver_after(self.before)
        bad=copy.deepcopy(after);bad['resolved_dns']['eth0'].reverse()
        self.assertNotEqual(self.e.resolver_normalized(after),self.e.resolver_normalized(bad))
        bad=copy.deepcopy(after);bad['resolved_domains']['eth0']=[]
        self.assertNotEqual(self.e.resolver_normalized(after),self.e.resolver_normalized(bad))

    def test_runtime_recovery_restores_original_dns_and_selection(self):
        self.plan();calls=[]
        def fake(args,*a,**kw):
            calls.append(args)
            return subprocess.CompletedProcess(args,0,'Link 2 (eth0): 1.1.1.1 8.8.8.8\n' if args[1:]==['dns','eth0'] else '','')
        with patch.object(self.e,'run',side_effect=fake):self.e.restore_resolver(self.before)
        self.assertIn(['resolvectl','dns','eth0','1.1.1.1','2001:db8::53','8.8.8.8'],calls)
        self.assertIn(['resolvectl','domain','eth0','corp.test','~internal.test'],calls)
        self.assertIn(['resolvectl','default-route','eth0','no'],calls)

    def test_equal_selection_does_not_freeze_automatic_default_route(self):
        self.plan();calls=[]
        def fake(args,*a,**kw):
            calls.append(args)
            field={'dns':'resolved_dns','domain':'resolved_domains','default-route':'resolved_default_route','dnsovertls':'resolved_dnsovertls'}[args[1]]
            values=self.before['resolver'][field]['eth0']
            return subprocess.CompletedProcess(args,0,'Link 2 (eth0): '+' '.join(values)+'\n','')
        with patch.object(self.e,'run',side_effect=fake):self.e.restore_resolver(self.before)
        self.assertTrue(all(len(args)==3 for args in calls))

    def test_second_dns_plan_is_noop(self):
        self.plan();self.before['resolver']=self.e.resolver_after(self.before);self.before.pop('dns_delta')
        pl,probe=self.plan()
        self.assertFalse(pl.changes);self.assertFalse(pl.actions);self.assertEqual(probe.call_count,4)

    def test_ifupdown_dns_from_other_interface_is_not_owner_proof(self):
        path='/etc/network/interfaces'
        self.write(path,'iface eth0 inet static\n dns-nameservers 1.1.1.1 8.8.8.8\n dns-search corp.test ~internal.test\niface eth1 inet static\n dns-nameservers 2001:db8::53\n')
        pl=self.e.Plan();pl.owners['eth0']='ifupdown';pl.dns_sources['eth0']=path;pl.watch(path)
        with self.assertRaisesRegex(self.e.Stop,'not attributable'):self.e.plan_dns(pl,self.before)

    def test_ifupdown_sourced_fragment_scoped_to_interface(self):
        path='/etc/network/interfaces';extra='/etc/network/interfaces.d/eth0'
        self.write(path,'source /etc/network/interfaces.d/*\n')
        self.write(extra,'iface eth0 inet static\n dns-nameservers 1.1.1.1 2001:db8::53 8.8.8.8\n dns-search corp.test ~internal.test\n')
        pl=self.e.Plan();pl.owners['eth0']='ifupdown';pl.dns_sources['eth0']=path;pl.watch(path);pl.watch(extra)
        with patch.object(self.e,'dns4_probe'),patch.object(self.e,'run',return_value=subprocess.CompletedProcess([],0,'','')):
            self.e.plan_dns(pl,self.before)
        self.assertTrue(self.before['dns_delta'])

    def test_managed_uplink_comments_are_not_dns_semantics(self):
        before={'link':'/run/systemd/resolve/resolv.conf','data':base64.b64encode(b'# Too many DNS servers configured\nnameserver 1.1.1.1\nsearch corp.test\n').decode()}
        after=dict(before,data=base64.b64encode(b'nameserver 1.1.1.1\nsearch corp.test\n').decode())
        self.assertEqual(self.e.resolver_normalized(before),self.e.resolver_normalized(after))
        before['link']=after['link']=None
        self.assertNotEqual(self.e.resolver_normalized(before),self.e.resolver_normalized(after))

    def test_positive_internal_soa_is_required_even_without_apex_a(self):
        pl=self.e.Plan();pl.owners['eth0']='networkd';pl.dns_sources['eth0']=self.source
        calls=[]
        def fake(args,*a,**kw):
            calls.append(args)
            return subprocess.CompletedProcess(args,0 if args[0]=='resolvectl' else 2,'','')
        with patch.object(self.e,'run',side_effect=fake),patch.object(self.e,'dns4_probe') as probe:
            self.e.plan_dns(pl,self.before)
        self.assertIn('corp.test',self.before['dns_zone_probes'])
        self.assertIn(unittest.mock.call('1.1.1.1','corp.test',positive=True,qtype=6,iface='eth0'),probe.call_args_list)
        self.assertIn(['resolvectl','query','--type=SOA','--legend=no','corp.test'],calls)

    def test_uncertain_internal_zone_refuses_before_write(self):
        with patch.object(self.e,'run',return_value=subprocess.CompletedProcess([],1,'','timeout')):
            with self.assertRaisesRegex(self.e.Stop,'cannot validate routed zone'):
                self.e.plan_dns(self.make_plan(),self.before)

    def test_ipv4_only_dns_does_not_hide_ipv6_learned_domain_loss(self):
        self.before['resolver']['resolved_dns']['eth0']=['1.1.1.1','8.8.8.8']
        self.before['resolver']['resolved_domains']['eth0'].append('~dhcp6-only.test')
        with self.assertRaisesRegex(self.e.Stop,'DHCPv6/RA'):self.plan()

    def make_plan(self):
        pl=self.e.Plan();pl.owners['eth0']='networkd';pl.dns_sources['eth0']=self.source
        return pl

    def details(self,origin='static'):
        return {'Name':'eth0','Index':2,'NetworkFile':self.source,'DNS':[
            {'Address':[1,1,1,1],'ConfigSource':origin},
            {'Address':[8,8,8,8],'ConfigSource':origin}], 'SearchDomains':[], 'RouteDomains':[]}

    def native_run(self,details):
        def fake(args,*a,**kw):
            return subprocess.CompletedProcess(args,0,json.dumps(details) if args[0]=='networkctl' else '','')
        return fake

    def test_networkd_ndisc_dns_removed_with_proven_retained_domains(self):
        self.write(self.source,'[Network]\nDHCP=yes\nIPv6AcceptRA=yes\nDNS=1.1.1.1 8.8.8.8\nDomains=corp.test ~internal.test\n')
        details=self.details();details['DNS'].append({'Address':list(self.e.ipaddress.ip_address('2001:db8::53').packed),'ConfigSource':'NDisc'})
        with patch.object(self.e,'run',side_effect=self.native_run(details)),patch.object(self.e,'dns4_probe'):
            self.e.plan_dns(self.make_plan(),self.before)
        self.assertEqual(self.e.resolver_after(self.before)['resolved_dns']['eth0'],['1.1.1.1','8.8.8.8'])

    def test_networkd_runtime_override_is_not_persistent_provenance(self):
        with patch.object(self.e,'run',side_effect=self.native_run(self.details('runtime'))):
            with self.assertRaisesRegex(self.e.Stop,'unsupported networkd DNS writer runtime'):
                self.e.plan_dns(self.make_plan(),self.before)

    def test_networkd_runtime_domain_is_not_proven_by_equal_static_text(self):
        details=self.details();details['SearchDomains']=[{'Domain':'corp.test','ConfigSource':'runtime'}]
        with patch.object(self.e,'run',side_effect=self.native_run(details)):
            with self.assertRaisesRegex(self.e.Stop,'unsupported networkd domain writer runtime'):
                self.e.plan_dns(self.make_plan(),self.before)

    def test_networkd_convergence_never_sets_runtime_override(self):
        self.before['owners']={'eth0':'networkd'}
        calls=[]
        def fake(args,*a,**kw):
            calls.append(args)
            key={'dns':'resolved_dns','domain':'resolved_domains','default-route':'resolved_default_route','dnsovertls':'resolved_dnsovertls'}[args[1]]
            return subprocess.CompletedProcess(args,0,'Link 2 (eth0): '+' '.join(self.before['resolver'][key]['eth0'])+'\n','')
        with patch.object(self.e,'run',side_effect=fake):self.e.restore_resolver(self.before)
        self.assertTrue(calls);self.assertTrue(all(len(args)==3 for args in calls))

    def test_getent_timeout_does_not_hide_concrete_dns_refusal(self):
        with patch.object(self.e,'run',side_effect=self.e.subprocess.TimeoutExpired(['getent'],12)):
            self.assertFalse(self.e.getent4_ok('example.com'))

    def test_real_dns_probe_rejects_public_nxdomain(self):
        class Sock:
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def settimeout(self,*a):pass
            def connect(self,*a):pass
            def send(self,packet):self.packet=packet
            def recv(self,*a):return self.packet[:2]+b'\x81\x83'+b'\0\1'+b'\0'*6+self.packet[12:]
        with patch.object(self.e.socket,'socket',return_value=Sock()):
            with self.assertRaisesRegex(self.e.Stop,'IPv4 DNS query failed'):self.e.dns4_probe('192.0.2.53')
            self.e.dns4_probe('192.0.2.53','absent.test',positive=False,qtype=6)


if __name__=='__main__':unittest.main()
