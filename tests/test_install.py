import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
import install as installer


def source_archive(extra=None):
    root = Path(__file__).resolve().parents[1]
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as out:
        for file in [root/'devproxy.py', *root.glob('devproxy_pkg/**/*.py')]:
            out.writestr('devproxy-fixture/' + file.relative_to(root).as_posix(), file.read_bytes())
        for name, value in (extra or {}).items():
            entry = zipfile.ZipInfo('placeholder')
            entry.filename = name
            entry.orig_filename = name
            out.writestr(entry, value)
    return data.getvalue()


class Installation(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.prefix = Path(temp.name)/'prefix with spaces'

    def test_clean_install_complete_package_and_reinstall(self):
        data = source_archive()
        launcher, package = installer.install(data, self.prefix, hashlib.sha256(data).hexdigest())
        self.assertTrue((package/'devproxy_pkg/core/tunnel.py').is_file())
        self.assertTrue(launcher.is_file())
        if os.name == 'nt':
            command = [sys.executable,str(package/'devproxy.py'),'--version']
        else:
            command = [str(launcher),'--version']
        result = subprocess.run(command,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'2.0.1')
        second, _ = installer.install(data,self.prefix)
        self.assertEqual(second,launcher)

    def test_offline_checkout_install_command(self):
        result = subprocess.run([sys.executable, str(Path(installer.__file__)), '--from-checkout', '--prefix', str(self.prefix)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.prefix/'bin'/('devproxy.cmd' if os.name == 'nt' else 'devproxy')).is_file())

    def test_checksum_mismatch_does_not_install(self):
        with self.assertRaises(ValueError):
            installer.install(source_archive(),self.prefix,'0'*64)
        self.assertFalse(self.prefix.exists())

    def test_incomplete_archive_does_not_replace_existing_launcher(self):
        launcher,_ = installer.install(source_archive(),self.prefix)
        before = launcher.read_bytes()
        data = io.BytesIO()
        with zipfile.ZipFile(data,'w') as out:
            out.writestr('devproxy.py','print("2.0.1")')
        with self.assertRaises(ValueError):
            installer.install(data.getvalue(),self.prefix)
        self.assertEqual(launcher.read_bytes(),before)

    def test_archive_path_traversal_and_symlink_rejected(self):
        for name in ('devproxy-fixture/../../outside.py','/absolute.py','devproxy-fixture/evil\\file.py'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                installer.install(source_archive({name:b'bad'}),self.prefix)
        data = io.BytesIO()
        with zipfile.ZipFile(data,'w') as out:
            entry = zipfile.ZipInfo('link')
            entry.external_attr = (0o120777 << 16)
            out.writestr(entry,'/tmp/outside')
        with self.assertRaises(ValueError):
            installer.install(data.getvalue(),self.prefix)
