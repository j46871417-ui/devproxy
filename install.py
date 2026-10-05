#!/usr/bin/env python3
"""Install a complete, pinned source package without editing shell rc files."""
import argparse
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

VERSION = '2.0.1'


def install(archive, prefix, expected_sha256=None):
    if expected_sha256 and hashlib.sha256(archive).hexdigest() != expected_sha256.lower():
        raise ValueError('Archive SHA-256 mismatch.')
    if len(archive) > 32 * 1024 * 1024:
        raise ValueError('Source archive exceeds size limit.')
    prefix = Path(prefix).expanduser().resolve()
    library = prefix / 'lib' / 'devproxy'
    library.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.install-', dir=library))
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            entries = bundle.infolist()
            if sum(e.file_size for e in entries) > 64 * 1024 * 1024:
                raise ValueError('Expanded source archive exceeds size limit.')
            names = [e.filename for e in entries if not e.is_dir()]
            direct = 'devproxy.py' in names
            roots = {PurePosixPath(n).parts[0] for n in names}
            if not direct and len(roots) != 1:
                raise ValueError('Archive must contain a single project root.')
            extracted = set()
            for entry in entries:
                path = PurePosixPath(entry.filename)
                if path.is_absolute() or '..' in path.parts or chr(92) in entry.orig_filename or ':' in entry.filename:
                    raise ValueError('Unsafe archive path.')
                if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError('Archive symlinks are unsupported.')
                relative = path if direct else PurePosixPath(*path.parts[1:])
                if entry.is_dir():
                    continue
                wanted = str(relative) in ('devproxy.py', 'README.md', 'LICENSE') or (
                    relative.parts and relative.parts[0] == 'devproxy_pkg' and relative.suffix == '.py')
                if not wanted:
                    continue
                if str(relative) in extracted:
                    raise ValueError('Duplicate archive path.')
                extracted.add(str(relative))
                target = stage.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(bundle.read(entry))
        if not (stage/'devproxy.py').is_file() or not (stage/'devproxy_pkg'/'__init__.py').is_file():
            raise ValueError('Archive is missing the Python entrypoint or package.')
        smoke = subprocess.run([sys.executable, str(stage/'devproxy.py'), '--version'], text=True, capture_output=True)
        if smoke.returncode != 0 or smoke.stdout.strip() != VERSION:
            raise ValueError('Package smoke test/version check failed.')
        digest = hashlib.sha256(archive).hexdigest()[:16]
        destination = library / (VERSION + '-' + digest)
        if destination.exists():
            # An existing immutable version must still match its archive content.
            if any(not (destination/name).is_file() or (stage/name).read_bytes() != (destination/name).read_bytes() for name in extracted):
                raise ValueError('Existing installation differs from the verified package.')
        else:
            os.replace(stage, destination)
        binary = prefix/'bin'
        binary.mkdir(parents=True, exist_ok=True)
        if os.name == 'nt':
            launcher = binary/'devproxy.cmd'
            content = '@echo off\r\n"' + sys.executable + '" "' + str(destination/'devproxy.py') + '" %*\r\nexit /b %errorlevel%\r\n'
        else:
            launcher = binary/'devproxy'
            content = '#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' ' + shlex.quote(str(destination/'devproxy.py')) + ' "$@"\n'
        fd, temp = tempfile.mkstemp(prefix='.devproxy-', dir=binary)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8', newline='') as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp, 0o755)
            os.replace(temp, launcher)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
        return launcher, destination
    finally:
        # This path is created above and always remains within our staging root.
        if stage.exists() and stage.resolve().parent == library.resolve() and stage.name.startswith('.install-'):
            shutil.rmtree(stage)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Install DevProxy complete source package')
    parser.add_argument('--archive', help='Local ZIP archive (source distribution)')
    parser.add_argument('--from-checkout', action='store_true', help='Install the complete local checkout without downloading')
    parser.add_argument('--sha256', help='Expected archive SHA-256')
    parser.add_argument('--prefix', default=str(Path.home()/'.local'))
    parser.add_argument('--version', default='v' + VERSION)
    args = parser.parse_args(argv)
    try:
        if sys.version_info < (3, 11):
            raise ValueError('Python 3.11 or newer is required.')
        if args.archive and args.from_checkout:
            raise ValueError('Choose --archive or --from-checkout.')
        if args.from_checkout:
            root = Path(__file__).resolve().parent
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as bundle:
                for file in [root/'devproxy.py', *root.glob('devproxy_pkg/**/*.py')]:
                    bundle.write(file, file.relative_to(root).as_posix())
            data = buffer.getvalue()
        elif args.archive:
            data = Path(args.archive).read_bytes()
        else:
            if not re.fullmatch(r'v\d+\.\d+\.\d+', args.version):
                raise ValueError('Select an explicit release tag such as v2.0.1.')
            url = 'https://codeload.github.com/j46871417-ui/devproxy/zip/refs/tags/' + args.version
            with urllib.request.urlopen(url, timeout=30) as response:
                data = response.read(32 * 1024 * 1024 + 1)
        launcher, directory = install(data, args.prefix, args.sha256)
        print('Installed:', launcher)
        print('Package:', directory)
        print('Add', launcher.parent, 'to PATH if needed. Shell configuration was not modified.')
        return 0
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print('Installation failed:', str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
