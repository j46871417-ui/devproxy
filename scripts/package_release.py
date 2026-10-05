"""Smoke-test the frozen executable and make a portable release archive."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import zipfile
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from devproxy_pkg import __version__

parser = argparse.ArgumentParser()
parser.add_argument('--name', required=True)
parser.add_argument('--output', default='release')
args = parser.parse_args()
binary = ROOT/'dist'/('devproxy.exe' if os.name == 'nt' else 'devproxy')
result = subprocess.run([str(binary), '--version'], capture_output=True, text=True)
if result.returncode or result.stdout.strip() != __version__:
    raise SystemExit('Frozen executable version/smoke test failed.')
output = Path(args.output).resolve()
output.mkdir(parents=True, exist_ok=True)
archive = output/(args.name + '.zip')
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
    bundle.write(binary, binary.name)
    for name in ('README.md', 'MATRIX.md', 'LICENSE'):
        bundle.write(ROOT/name,name)
    if os.name == 'nt':
        bundle.write(ROOT/'НАСТРОИТЬ_ПРОКСИ.bat','НАСТРОИТЬ_ПРОКСИ.bat')
checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
(output/(archive.name + '.sha256')).write_text(checksum+'  '+archive.name+'\n',encoding='ascii')
print(archive, checksum)
