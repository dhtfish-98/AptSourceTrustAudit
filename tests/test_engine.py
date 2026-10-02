import unittest
from apt_source_trust_audit import analyze
from apt_source_trust_audit.common import InputError

class AptTests(unittest.TestCase):
    def good(self):return {'files':{'/etc/apt/sources.list':'deb [signed-by=/etc/apt/keyrings/vendor.gpg] https://packages.example.invalid stable main'},'global_options':{},'global_options_complete':True}
    def test_one_line_positive(self):self.assertEqual(analyze(self.good())['status'],'PASS')
    def test_deb822_multivalue(self):
        s=self.good();s['files']={'/etc/apt/sources.list.d/vendor.sources':'Types: deb deb-src\nURIs: https://one.example.invalid https://two.example.invalid\nSuites: stable testing\nComponents: main contrib\nSigned-By: /etc/apt/keyrings/a.gpg\n /usr/share/keyrings/b.gpg\n'};self.assertEqual(analyze(s)['status'],'PASS')
    def test_disabled_does_not_parse_active_fields(self):
        s=self.good();s['files']['/etc/apt/sources.list.d/off.sources']='Enabled: no\nTypes: deb\nURIs: http://disabled.example.invalid\nSuites: stable\nComponents: main\nTrusted: yes\n';self.assertEqual(analyze(s)['status'],'PASS')
    def test_auth_bypass(self):
        s=self.good();s['files']['/etc/apt/sources.list']=s['files']['/etc/apt/sources.list'].replace('signed-by=','trusted=yes signed-by=');self.assertEqual(analyze(s)['status'],'FAIL')
    def test_expiry_override(self):
        s=self.good();s['global_options']['Acquire::Check-Valid-Until']=False;self.assertEqual(analyze(s)['status'],'FAIL')
    def test_global_missing(self):
        s=self.good();s.pop('global_options_complete');self.assertEqual(analyze(s)['status'],'OPEN')
    def test_relative_keyring(self):
        s=self.good();s['files']['/etc/apt/sources.list']=s['files']['/etc/apt/sources.list'].replace('/etc/apt/keyrings/vendor.gpg','vendor.gpg');self.assertEqual(analyze(s)['status'],'FAIL')
    def test_declared_signed_by_not_verified(self):
        r=analyze(self.good());self.assertTrue(any('authenticity' in x for x in r['limitations']))
    def test_duplicate_source(self):
        s=self.good();s['files']['/etc/apt/sources.list.d/duplicate.list']=s['files']['/etc/apt/sources.list'];self.assertEqual(analyze(s)['status'],'FAIL')
    def test_duplicate_deb822_field(self):
        s=self.good();s['files']={'a.sources':'Types: deb\nTypes: deb-src'}
        with self.assertRaises(InputError):analyze(s)
    def test_unknown_option(self):
        s=self.good();s['files']['/etc/apt/sources.list']=s['files']['/etc/apt/sources.list'].replace('signed-by=','future=yes signed-by=');self.assertEqual(analyze(s)['status'],'OPEN')
    def test_exact_path_forbids_components(self):
        s=self.good();s['files']['/etc/apt/sources.list']=s['files']['/etc/apt/sources.list'].replace('stable main','stable/ main')
        with self.assertRaises(InputError):analyze(s)

    def test_comma_only_signing_cannot_pass(self):
        snapshot=self.good();snapshot['files']['/etc/apt/sources.list']='deb [signed-by=,] https://packages.example.invalid stable main'
        self.assertEqual(analyze(snapshot)['status'],'FAIL')
