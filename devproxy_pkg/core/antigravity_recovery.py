"""Reversible recovery for standalone Antigravity's loopback UI.

Does not change TLS validation, account files, proxy routing or Electron fuses.
"""
import copy
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import hashlib
import json
import mmap
import os
from pathlib import Path
import struct
import tempfile

MARKER = "// DevProxy local UI recovery v1"
ANCHOR = "    void win.loadURL(url);\n    return win;"
FUSE_SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"

RECOVERY_JS = r'''    // DevProxy local UI recovery v1
    // Only transient main-frame failures of the local HTTPS UI are recoverable.
    {
        const contents = win.webContents;
        const localUI = (value) => {
            const match = /^https:\/\/127\.0\.0\.1:([0-9]{1,5})\/$/.exec(value);
            return match !== null && Number(match[1]) > 0 && Number(match[1]) <= 65535;
        };
        let target = url;
        let attempts = 0;
        let timer = null;
        let prompting = false;
        const alive = () => !win.isDestroyed() && !contents.isDestroyed();
        const cancel = () => { if (timer !== null) clearTimeout(timer); timer = null; };
        const reload = (expected) => {
            if (!alive() || target !== expected || !localUI(expected)) return;
            void win.loadURL(expected).catch(() => {});
        };
        contents.on('did-start-navigation', (_event, next, _inPlace, mainFrame) => {
            if (!mainFrame) return;
            cancel();
            if (next !== target) { target = next; attempts = 0; }
        });
        contents.on('did-navigate', (_event, loaded, status) => {
            // did-finish-load can also fire for Chromium's error page.
            if (loaded === target && localUI(loaded) && status === 200) {
                cancel(); attempts = 0;
            }
        });
        contents.on('did-fail-load', (_event, code, _description, failed, mainFrame) => {
            if (!mainFrame || !alive() || failed !== target || !localUI(failed)
                || ![-7, -100, -101, -102].includes(code) || timer !== null || prompting) return;
            if (attempts < 2) {
                attempts++;
                console.warn(`[DevProxy] Local UI recovery ${attempts}/2, error ${code}`);
                timer = setTimeout(() => { timer = null; reload(failed); }, 750);
                return;
            }
            prompting = true;
            void electron_1.dialog.showMessageBox(win, {
                type: 'error', title: 'Antigravity: ошибка загрузки интерфейса',
                message: 'Antigravity не смог загрузить свой локальный интерфейс.',
                detail: 'Две автоматические попытки не помогли. Можно повторить загрузку. '
                    + 'Данные аккаунта и настройки прокси сохранены. Код ошибки: ' + code,
                buttons: ['Повторить', 'Оставить окно'], defaultId: 0, cancelId: 1,
            }).then(({ response }) => {
                prompting = false;
                if (response === 0 && alive() && target === failed) { attempts = 0; reload(failed); }
            }).catch(() => { prompting = false; });
        });
        win.on('closed', cancel);
    }
    void win.loadURL(url).catch(() => {});
    return win;'''


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _parse(data):
    if len(data) < 16:
        raise ValueError("Некорректный архив Antigravity.")
    outer, size, payload, length = struct.unpack_from('<4I', data)
    base = 8 + size
    if outer != 4 or size != payload + 4 or payload % 4 or length > payload - 4 or base > len(data):
        raise ValueError("Неподдерживаемый заголовок архива Antigravity.")
    if length > 8 * 1024 * 1024:
        raise ValueError("Слишком большой заголовок архива Antigravity.")
    try:
        header = json.loads(data[16:16 + length])
        entry = header['files']['dist']['files']['utils.js']
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError):
        raise ValueError("Неподдерживаемая сборка Antigravity.") from None
    if entry.get('unpacked') or 'link' in entry:
        raise ValueError("Неподдерживаемый файл интерфейса Antigravity.")
    offset, count = int(entry['offset']), entry['size']
    if offset < 0 or not isinstance(count, int) or count < 0 or base + offset + count > len(data):
        raise ValueError("Повреждённый файл интерфейса Antigravity.")
    return header, base, entry, data[base + offset:base + offset + count]


def patch_archive(data):
    header, base, entry, source = _parse(data)
    text = source.decode('utf-8')
    if MARKER in text:
        return data
    if text.count(ANCHOR) != 1 or 'function createWindow(url, storageManager)' not in text \
            or 'new electron_1.BrowserWindow' not in text or 'const electron_1 = require("electron")' not in text:
        raise ValueError("Эта версия Antigravity пока не поддерживает восстановление интерфейса.")
    dist = header['files']['dist']['files']
    for name, signature in (('constants.js', "WINDOW_ORIGIN = 'https://127.0.0.1'"),
                            ('languageServer.js', 'function setupLocalCertTrust()')):
        other = dist.get(name, {})
        if other.get('unpacked') or 'offset' not in other:
            raise ValueError("Неподдерживаемая сборка Antigravity.")
        start = base + int(other['offset'])
        if signature.encode() not in data[start:start + other['size']]:
            raise ValueError("Неподдерживаемый локальный интерфейс Antigravity.")
    integrity = entry.get('integrity')
    if integrity and (integrity.get('algorithm') != 'SHA256' or integrity.get('hash') != _digest(source)):
        raise ValueError("Контрольная сумма интерфейса Antigravity не совпадает.")
    patched = text.replace(ANCHOR, RECOVERY_JS).encode('utf-8')
    header = copy.deepcopy(header)
    entry = header['files']['dist']['files']['utils.js']
    entry.update(size=len(patched), offset=str(len(data) - base))
    if integrity:
        block_size = integrity['blockSize']
        if not isinstance(block_size, int) or block_size <= 0:
            raise ValueError("Неподдерживаемая контрольная сумма Antigravity.")
        entry['integrity'] = dict(algorithm='SHA256', hash=_digest(patched), blockSize=block_size,
                                  blocks=[_digest(patched[i:i + block_size]) for i in range(0, len(patched), block_size)])
    raw = json.dumps(header, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    payload_size = (len(raw) + 4 + 3) // 4 * 4
    prefix = struct.pack('<4I', 4, payload_size + 4, payload_size, len(raw))
    result = prefix + raw + b'\0' * (payload_size - 4 - len(raw)) + data[base:] + patched
    if _parse(result)[3] != patched:
        raise ValueError("Проверка изменённого архива Antigravity не прошла.")
    return result


def _check_fuses(executable):
    with executable.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as binary:
        pos = binary.find(FUSE_SENTINEL)
        if pos < 0 or binary.find(FUSE_SENTINEL, pos + 32) >= 0:
            raise ValueError("Не удалось проверить защиту архива Antigravity.")
        wire = binary[pos + 32:pos + 48]
    # Fuse v1, EnableEmbeddedAsarIntegrityValidation at index 4. Never change it.
    if len(wire) < 7 or wire[0] != 1 or wire[1] < 5 or wire[6] != ord('0'):
        raise ValueError("Antigravity проверяет подпись архива; исправление не применяется.")


def _running():
    if os.name != 'nt':
        return False
    class Entry(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('usage', wintypes.DWORD), ('pid', wintypes.DWORD),
                    ('heap', ctypes.c_size_t), ('module', wintypes.DWORD), ('threads', wintypes.DWORD),
                    ('parent', wintypes.DWORD), ('priority', wintypes.LONG), ('flags', wintypes.DWORD),
                    ('name', wintypes.WCHAR * 260)]
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    api.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    api.Process32FirstW.argtypes = api.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = api.CreateToolhelp32Snapshot(2, 0)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError("Не удалось проверить запущенный Antigravity.")
    try:
        entry = Entry(); entry.size = ctypes.sizeof(entry)
        ok = api.Process32FirstW(handle, ctypes.byref(entry))
        if not ok:
            raise OSError("Не удалось прочитать список процессов.")
        while ok:
            if entry.name.lower() == 'antigravity.exe':
                return True
            ok = api.Process32NextW(handle, ctypes.byref(entry))
        return False
    finally:
        api.CloseHandle(handle)


def _atomic(path, data):
    fd, name = tempfile.mkstemp(prefix='devproxy-recovery-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextmanager
def _archive_lock(path):
    # The OS releases the lock on process death; a stale marker cannot block
    # all future launches as an O_EXCL-only marker would.
    with path.open('a+b') as stream:
        if os.fstat(stream.fileno()).st_size == 0:
            stream.write(b'\0'); stream.flush()
        stream.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError("Исправление Antigravity уже выполняется; повторите запуск позже.") from None
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == 'nt':
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def prepare(executable, restore=False):
    executable = Path(executable).resolve()
    if executable.name.lower() != 'antigravity.exe':
        return 'not-applicable'
    archive = executable.parent / 'resources' / 'app.asar'
    if not archive.is_file():
        return 'not-applicable'
    lock = archive.with_name('app.asar.devproxy-recovery.lock')
    with _archive_lock(lock):
        if archive.stat().st_size > 128 * 1024 * 1024:
            raise ValueError("Неподдерживаемый размер архива Antigravity.")
        original = archive.read_bytes()
        journal = archive.with_name('app.asar.devproxy-recovery.json')
        _, _, _, current = _parse(original)
        if MARKER.encode() in current or restore:
            if not journal.is_file():
                raise ValueError("Нет журнала восстановления Antigravity; архив не изменён.")
            record = json.loads(journal.read_text(encoding='utf-8'))
            if restore and _digest(original) == record['original_sha256']:
                return 'already-restored'
            if _digest(original) != record['patched_sha256']:
                raise ValueError("Архив Antigravity изменён другой программой; он не перезаписан.")
            _check_fuses(executable)
            if not restore:
                return 'already-applied'
            if _running():
                raise RuntimeError("Закройте Antigravity перед восстановлением исходного архива.")
            digest = record['original_sha256']
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError("Некорректный журнал восстановления Antigravity.")
            backup = archive.with_name('app.asar.devproxy-recovery-' + digest[:12] + '.bak')
            source = backup.read_bytes()
            if _digest(source) != digest:
                raise ValueError("Резервная копия Antigravity повреждена; архив не изменён.")
            _atomic(archive, source)
            return 'restored'
        _check_fuses(executable)
        if _running():
            raise RuntimeError("Закройте Antigravity перед первым запуском с исправлением чёрного экрана.")
        patched = patch_archive(original)
        digest = _digest(original)
        backup = archive.with_name('app.asar.devproxy-recovery-' + digest[:12] + '.bak')
        if backup.exists():
            if _digest(backup.read_bytes()) != digest:
                raise ValueError("Резервная копия Antigravity изменена; исправление не применено.")
        else:
            _atomic(backup, original)
        record = dict(original_sha256=digest, patched_sha256=_digest(patched), recovery_version=1)
        _atomic(journal, json.dumps(record, indent=2).encode('utf-8'))
        if archive.read_bytes() != original:
            raise RuntimeError("Antigravity обновился во время исправления; архив не перезаписан.")
        _atomic(archive, patched)
        return 'applied'
