"""Reproducible Windows source/test/build gate. Invoke from the repository root."""
import compileall
from pathlib import Path
import subprocess
import sys
import zipfile
import tkinter


def run(*args):
    subprocess.run([sys.executable, *args], check=True)


def main():
    if sys.platform != "win32":
        raise SystemExit("Windows release build requires Windows")
    root = Path(__file__).resolve().parents[1]
    import os
    os.chdir(root)
    output = Path(os.environ.get("DEVPROXY_BUILD_DIR", str(root / "dist"))).resolve()
    if not output.is_relative_to(root) or output == root:
        raise SystemExit("Build output must be a subdirectory of the project")
    output.mkdir(parents=True, exist_ok=True)
    os.environ["PYTHONIOENCODING"] = "utf-8"
    if not compileall.compile_dir("devproxy_pkg", quiet=1):
        raise SystemExit("Compile check failed")
    run("-m", "unittest", "discover", "-s", "tests", "-v")
    data_args = ["--add-data", str(root / "devproxy_pkg/resources") + ";devproxy_pkg/resources"]
    # Tcl/Tk 9 in Python 3.14 embeds resources in zipfs; current PyInstaller
    # discovery reports a virtual path and misses these archives.
    if tkinter.Tcl().eval("info library").startswith("//zipfs:"):
        library = Path(sys.base_prefix) / "tcl"
        extracted = root / "build" / "tk-resources"
        for package, destination in (("tcl", "_tcl_data"), ("tk", "_tk_data")):
            archives = sorted(library.glob(f"lib{package}*.zip"))
            if len(archives) != 1:
                raise SystemExit("Cannot identify Tcl/Tk resource archive")
            with zipfile.ZipFile(archives[0]) as resources:
                resources.extractall(extracted)
            source = extracted / (package + "_library")
            data_args += ["--add-data", str(source) + ";" + destination]
    run("-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--console",
        "--name", "devproxy", "--distpath", str(output), *data_args, "devproxy.py")
    run("-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed",
        "--name", "devproxy-gui", "--distpath", str(output), *data_args, "devproxy_gui.py")
    subprocess.run([str(output / "devproxy.exe"), "--help"], check=True)
    # A cold onefile extraction plus antivirus scanning can exceed 30s on
    # Windows. Keep a bounded gate, with enough time for first-run scanning.
    subprocess.run([str(output / "devproxy.exe"), "--self-test-ui"], check=True, timeout=90)
    subprocess.run([str(output / "devproxy-gui.exe"), "--self-test"], check=True, timeout=90)
    with zipfile.ZipFile(output / "devproxy-windows-x64.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for name in ("devproxy.exe", "devproxy-gui.exe"):
            archive.write(output / name, name)
        for name in ("README.md", "MATRIX.md", "REPORT.md", "LICENSE"):
            archive.write(root / name, name)
    import hashlib
    sums = []
    for name in ("devproxy.exe", "devproxy-gui.exe", "devproxy-windows-x64.zip"):
        data = (output / name).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        sums.append(f"{digest}  {name}\n")
    (output / "SHA256SUMS.txt").write_text("".join(sums), encoding="utf-8")


if __name__ == "__main__":
    main()
