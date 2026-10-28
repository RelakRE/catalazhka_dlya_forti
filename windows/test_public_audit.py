from pathlib import Path
import tempfile
import unittest
from audit_public import inspect

class AuditTests(unittest.TestCase):
    def test_documentation_examples_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'sample.json').write_text('{"Server":"https://vpn.example.com","IP":"192.0.2.30"}')
            self.assertTrue(inspect(root)['passed'])

    def test_private_profile_and_known_fingerprint_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = 'private-' + 'organization.example'
            (root / 'profile.local.json').write_text(value)
            kinds = {x['kind'] for x in inspect(root, [value])['findings']}
            self.assertIn('private-or-binary-artifact', kinds)
            self.assertIn('private-fingerprint', kinds)

    def test_personal_path_and_private_ip_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            personal = 'C:' + '/' + 'Users' + '/' + 'sample-person' + '/settings'
            address = '.'.join(map(str, [10, 13, 17, 19]))
            (root / 'leak.md').write_text(personal + '\n' + address)
            kinds = {x['kind'] for x in inspect(root)['findings']}
            self.assertIn('personal-home-path', kinds)
            self.assertIn('non-documentation-private-ip', kinds)

    def test_plaintext_password_field_rejected(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = 'synthetic-' + 'test-value'
            (root / 'config.json').write_text(json.dumps(dict(password=secret)))
            self.assertIn('plaintext-secret-field', {x['kind'] for x in inspect(root)['findings']})

if __name__ == '__main__':
    unittest.main()
