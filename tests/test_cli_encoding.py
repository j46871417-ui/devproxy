"""Russian CLI help must survive a non-Cyrillic redirected console."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


class CliEncodingTests(unittest.TestCase):
    def test_russian_help_uses_utf8_with_cp1252_streams(self):
        root = Path(__file__).resolve().parents[1]
        env = dict(os.environ, PYTHONIOENCODING='cp1252')
        for arguments in (['--help'], ['antigravity-recovery', '--help']):
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, str(root / 'devproxy.py'), *arguments],
                                        env=env, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', errors='replace'))
                output = result.stdout.decode('utf-8')
                self.assertIn('Antigravity', output)
                self.assertTrue(any('\u0400' <= character <= '\u04ff' for character in output))


if __name__ == '__main__':
    unittest.main()
