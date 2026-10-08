"""Regression tests for failed loopback navigation and reversible vendor edits."""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from devproxy_pkg.core import antigravity_recovery as recovery
from devproxy_pkg.core.launcher import ApplicationSession
from devproxy_pkg.core.profile import ProxyProfile


def fixture(unknown=False):
    files = {
        'utils.js': ('const electron_1 = require("electron");\n'
                     'function createWindow(url, storageManager) {\n'
                     '    const win = new electron_1.BrowserWindow();\n'
                     + (recovery.ANCHOR if not unknown else '    return win;') + '\n}\n').encode(),
        'constants.js': b"exports.WINDOW_ORIGIN = 'https://127.0.0.1';",
        'languageServer.js': b'function setupLocalCertTrust() {}',
    }
    entries = {}; payload = b''
    for name, blob in files.items():
        entries[name] = dict(size=len(blob), offset=str(len(payload)),
                             integrity=dict(algorithm='SHA256', hash=hashlib.sha256(blob).hexdigest(),
                                            blockSize=64, blocks=[hashlib.sha256(blob[i:i+64]).hexdigest() for i in range(0,len(blob),64)]))
        payload += blob
    raw = json.dumps({'files': {'dist': {'files': entries}}}, separators=(',', ':')).encode()
    length = (len(raw) + 7) // 4 * 4
    return struct.pack('<4I', 4, length + 4, length, len(raw)) + raw + b'\0' * (length - 4 - len(raw)) + payload


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.exe = Path(self.temp.name)/'Antigravity.exe'
        self.exe.write_bytes(recovery.FUSE_SENTINEL + bytes([1,9]) + b'101100011')
        (self.exe.parent/'resources').mkdir()
        self.archive = self.exe.parent/'resources/app.asar'
        self.original = fixture(); self.archive.write_bytes(self.original)
        self.running = patch.object(recovery, '_running', return_value=False); self.running.start(); self.addCleanup(self.running.stop)

    def test_preserves_all_original_payload_and_other_entry_metadata(self):
        patched = recovery.patch_archive(self.original)
        before, start, _, _ = recovery._parse(self.original)
        after, end, entry, source = recovery._parse(patched)
        self.assertEqual(patched[end:end + len(self.original)-start], self.original[start:])
        for name in ('constants.js', 'languageServer.js'):
            self.assertEqual(before['files']['dist']['files'][name], after['files']['dist']['files'][name])
        self.assertEqual(entry['integrity']['hash'], hashlib.sha256(source).hexdigest())
        self.assertEqual(entry['integrity']['blocks'], [hashlib.sha256(source[i:i+64]).hexdigest() for i in range(0,len(source),64)])
        self.assertEqual(recovery.patch_archive(patched), patched)

    def test_idempotent_install_and_exact_restore_with_backup(self):
        account = self.exe.parent/'account.json'; account.write_bytes(b'private-account-fixture')
        self.assertEqual(recovery.prepare(self.exe), 'applied')
        modified = self.archive.read_bytes()
        self.assertEqual(recovery.prepare(self.exe), 'already-applied')
        self.assertEqual(self.archive.read_bytes(), modified)
        self.assertEqual(recovery.prepare(self.exe, restore=True), 'restored')
        self.assertEqual(self.archive.read_bytes(), self.original)
        self.assertEqual(recovery.prepare(self.exe, restore=True), 'already-restored')
        self.assertEqual(account.read_bytes(), b'private-account-fixture')

    def test_updated_archive_is_not_overwritten_by_restore(self):
        recovery.prepare(self.exe)
        updated = fixture(unknown=True); self.archive.write_bytes(updated)
        with self.assertRaisesRegex(ValueError, 'изменён'):
            recovery.prepare(self.exe, restore=True)
        self.assertEqual(self.archive.read_bytes(), updated)

    def test_unknown_bundle_and_corrupt_source_not_patched(self):
        self.archive.write_bytes(fixture(unknown=True))
        with self.assertRaises(ValueError): recovery.prepare(self.exe)
        self.assertFalse(list(self.archive.parent.glob('*.bak')))
        corrupted = self.original.replace(b'const win =', b'const wim =')
        with self.assertRaisesRegex(ValueError, 'сумма'):
            recovery.patch_archive(corrupted)

    def test_embedded_integrity_enforcement_is_not_disabled(self):
        self.exe.write_bytes(recovery.FUSE_SENTINEL + bytes([1,9]) + b'101110011')
        with self.assertRaisesRegex(ValueError, 'подпись'):
            recovery.prepare(self.exe)
        self.assertEqual(self.archive.read_bytes(), self.original)

    def test_running_client_is_not_edited(self):
        with patch.object(recovery, '_running', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'Закройте'): recovery.prepare(self.exe)
        self.assertEqual(self.archive.read_bytes(), self.original)
        with recovery._archive_lock(self.archive.with_name('app.asar.devproxy-recovery.lock')):
            pass

    def test_lock_prevents_concurrent_edits_and_is_released_after_process_crash(self):
        lock = self.archive.with_name('app.asar.devproxy-recovery.lock')
        with recovery._archive_lock(lock):
            with self.assertRaises(RuntimeError):
                with recovery._archive_lock(lock): pass
        code = ('import os,sys; from pathlib import Path; '
                'from devproxy_pkg.core.antigravity_recovery import _archive_lock; '
                'guard=_archive_lock(Path(sys.argv[1])); guard.__enter__(); os._exit(0)')
        result=subprocess.run([sys.executable,'-c',code,str(lock)],timeout=10,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        with recovery._archive_lock(lock): pass
        self.assertEqual(recovery.prepare(self.exe),'applied')

    def test_missing_backup_and_foreign_patch_are_refused(self):
        recovery.prepare(self.exe)
        backup = next(self.archive.parent.glob('*.bak')); backup.write_bytes(b'wrong')
        with self.assertRaisesRegex(ValueError, 'повреждена'): recovery.prepare(self.exe, restore=True)
        self.archive.write_bytes(self.archive.read_bytes() + b'foreign-change')
        with self.assertRaisesRegex(ValueError, 'изменён'): recovery.prepare(self.exe)

    def test_patch_failure_leaves_original_and_verified_backup(self):
        atomic = recovery._atomic
        def fail_archive(path, data):
            if path == self.archive: raise OSError('fixture atomic replace failure')
            return atomic(path, data)
        with patch.object(recovery, '_atomic', side_effect=fail_archive):
            with self.assertRaises(OSError): recovery.prepare(self.exe)
        self.assertEqual(self.archive.read_bytes(), self.original)
        self.assertEqual(next(self.archive.parent.glob('*.bak')).read_bytes(), self.original)
        self.assertEqual(recovery.prepare(self.exe), 'applied')

    def test_invalid_header_rejected(self):
        for blob in (b'', b'wrong-format'*5, self.original[:80]):
            with self.subTest(size=len(blob)), self.assertRaises(ValueError): recovery.patch_archive(blob)

    def test_launcher_applies_recovery_before_spawn_and_preserves_session_policy(self):
        with ApplicationSession(ProxyProfile('fixture','http','127.0.0.1',9)) as session, \
             patch.object(recovery,'prepare') as prepare, \
             patch('devproxy_pkg.core.launcher.Launcher.launch') as launch, \
             patch('devproxy_pkg.core.windows_job.WindowsJob'):
            session.launch(str(self.exe),flags=['--proxy-server={PROXY_URL}'],electron=True,preserve_profile=True)
            prepare.assert_called_once_with(str(self.exe))
            flags, env = launch.call_args.args[1:3]
            self.assertIn('--proxy-server='+session.tunnel.proxy_url,flags)
            self.assertIn('--proxy-bypass-list=localhost;127.0.0.1;[::1]',flags)
            self.assertFalse(any(arg.startswith('--user-data-dir') for arg in flags))
            self.assertEqual(env['NODE_TLS_REJECT_UNAUTHORIZED'],'1')
            self.assertEqual(env['HTTPS_PROXY'],session.tunnel.proxy_url)
            self.assertEqual(env['NO_PROXY'],'localhost,127.0.0.1,::1')

    def test_failed_repair_does_not_spawn_unconfigured_process(self):
        with ApplicationSession(ProxyProfile('fixture','http','127.0.0.1',9)) as session, \
             patch.object(recovery,'prepare',side_effect=RuntimeError('fixture repair conflict')), \
             patch('devproxy_pkg.core.launcher.Launcher.launch') as launch:
            with self.assertRaisesRegex(RuntimeError,'conflict'):
                session.launch(str(self.exe),electron=True,preserve_profile=True)
            launch.assert_not_called()


@unittest.skipUnless(shutil.which('node'), 'Node needed to exercise actual Electron event handlers')
class NavigationTests(unittest.TestCase):
    def test_real_javascript_event_handlers_bound_retries_and_keep_external_errors(self):
        harness = r'''
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const source = JSON.parse(process.argv[1]);
const ui = 'https://127.0.0.1:12345/';
function setup() {
  const wc = new EventEmitter(); wc.isDestroyed = () => false;
  const win = new EventEmitter(); win.webContents = wc; win.isDestroyed = () => false;
  const calls = []; let messages = 0; const timers = new Map(); let serial = 0;
  win.loadURL = value => { calls.push(value); wc.emit('did-start-navigation', {}, value, false, true); return Promise.reject(Error('mock timeout')); };
  const dialog = {showMessageBox: () => { messages++; return new Promise(() => {}); }};
  new Function('win','url','electron_1','setTimeout','clearTimeout', source)(win, ui, {dialog},
    fn => { timers.set(++serial, fn); return serial; }, id => timers.delete(id));
  const fail = (code=-7, url=ui, main=true) => wc.emit('did-fail-load', {}, code, 'fixture', url, main);
  const tick = () => { const pending = [...timers.values()]; timers.clear(); pending.forEach(fn=>fn()); };
  return {win,wc,calls,timers,fail,tick,messages:()=>messages};
}
let s=setup(); s.fail(); s.fail(); assert.equal(s.timers.size,1); s.tick();
s.wc.emit('did-finish-load'); s.fail(); s.tick(); s.fail();
assert.equal(s.calls.length,3); assert.equal(s.messages(),1); assert.equal(s.timers.size,0);
for (const code of [-3,-105,-200,-201,-202,-203]) { s=setup(); s.fail(code); assert.equal(s.timers.size,0); }
for (const address of ['https://accounts.google.com/','http://127.0.0.1:12345/','https://127.0.0.1:65536/','https://127.0.0.1:12345/auth/callback']) {
  s=setup(); s.fail(-7,address); assert.equal(s.timers.size,0);
}
s=setup(); s.fail(-7,ui,false); assert.equal(s.timers.size,0);
s=setup(); s.fail(); s.win.emit('closed'); s.tick(); assert.equal(s.calls.length,1);
s=setup(); s.fail(); s.wc.emit('did-start-navigation', {}, 'https://accounts.google.com/',false,true); s.tick(); assert.equal(s.calls.length,1);
s=setup(); s.fail(); s.tick(); s.fail(); s.tick(); s.wc.emit('did-navigate',{},ui,200); s.fail(); s.tick(); assert.equal(s.calls.length,4);
console.log('Navigation recovery PASS');
'''
        result = subprocess.run([shutil.which('node'), '-e', harness, json.dumps(recovery.RECOVERY_JS)], capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('Navigation recovery PASS',result.stdout)
