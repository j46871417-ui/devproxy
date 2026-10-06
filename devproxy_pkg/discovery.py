"""Bounded, read-only application discovery and persisted first-run app list."""
import glob
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET


def canonical(path):
    return os.path.normcase(os.path.realpath(path)).casefold()


def windows_roots():
    result = []
    local = os.environ.get("LOCALAPPDATA")
    if local:
        result += [str(Path(local) / "Programs"), local]
    result += [os.environ.get("ProgramFiles", r"C:\Program Files"),
               os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")]
    return list(dict.fromkeys(filter(None, result)))


def pattern_paths(adapter):
    candidates = []
    for root in windows_roots():
        for pattern in getattr(adapter, "path_patterns", []):
            candidates.extend(glob.glob(str(Path(root) / pattern))[:100])
        if adapter.app_id in ("idea", "pycharm", "webstorm", "rider", "goland", "clion", "phpstorm", "rubymine", "datagrip", "rustrover", "fleet"):
            for name in adapter.names:
                for pattern in (f"JetBrains/Toolbox/apps/*/bin/{name}.exe",
                                f"JetBrains/Toolbox/apps/*/*/bin/{name}.exe",
                                f"JetBrains/Toolbox/apps/*/*/*/bin/{name}.exe"):
                    candidates.extend(glob.glob(str(Path(root) / pattern))[:100])
    home = Path.home()
    if adapter.app_id in ("codex", "opencode", "claude"):
        for folder in (home / ".local/bin", home / ("." + adapter.app_id) / "bin",
                       Path(os.environ.get("LOCALAPPDATA", str(home))) / "OpenAI/Codex/bin"):
            for name in adapter.names:
                candidates.extend(glob.glob(str(folder / (name + ".exe")))[:100])
                if adapter.app_id == "codex":
                    candidates.extend(glob.glob(str(folder / "*" / "codex.exe"))[:100])
    return candidates


def registry_entries():
    if os.name != "nt":
        return []
    import winreg
    entries = []
    def value(key, name):
        try:
            return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return ""
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            for base in (r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                         r"Software\Microsoft\Windows\CurrentVersion\App Paths"):
                try:
                    with winreg.OpenKey(hive, base, 0, winreg.KEY_READ | view) as parent:
                        for index in range(min(winreg.QueryInfoKey(parent)[0], 2000)):
                            try:
                                with winreg.OpenKey(parent, winreg.EnumKey(parent, index)) as key:
                                    path = value(key, "DisplayIcon") if base.endswith("Uninstall") else value(key, "")
                                    name = value(key, "DisplayName") if base.endswith("Uninstall") else winreg.EnumKey(parent, index)
                                    if isinstance(path, str):
                                        match = re.match(r'^\s*"([^"]+)"', path)
                                        path = match[1] if match else re.sub(r",\s*-?\d+$", "", path.strip())
                                    else:
                                        path = ""
                                    location = value(key, "InstallLocation") if base.endswith("Uninstall") else ""
                                    entries.append(dict(name=name if isinstance(name, str) else "", path=path,
                                                        location=location if isinstance(location, str) else "", source="registry"))
                            except OSError:
                                continue
                except OSError:
                    continue
    return entries


def shell_entries():
    if os.name != "nt":
        return []
    script = Path(__file__).parent / "resources/discover_windows.ps1"
    executable = shutil.which("powershell.exe")
    if not executable or not script.is_file():
        return []
    process = job = None
    try:
        from .core.windows_job import WindowsJob
        job = WindowsJob()
        process = subprocess.Popen([executable, "-NoLogo", "-NoProfile", "-NonInteractive",
                                    "-ExecutionPolicy", "Bypass", "-File", str(script)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   creationflags=0x08000004, shell=False)
        job.attach_and_resume(process)
        output, _ = process.communicate(timeout=25)
        if process.returncode:
            return []
        # Windows PowerShell may encode redirected output with the active code page.
        text = output.decode("utf-8-sig", errors="replace").strip()
        values = json.loads(text)
        return [entry for entry in values if isinstance(entry, dict)] if isinstance(values, list) else []
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []
    finally:
        if job:
            job.close()
        if process:
            if process.poll() is None:
                process.kill()
            process.communicate()


def entry_paths(entry, adapter):
    path = entry.get("path", "")
    basename = Path(path).name.lower()
    exe_names = {name.lower() if name.lower().endswith(".exe") else name.lower() + ".exe" for name in adapter.names}
    descriptor = entry.get("name", "").casefold()
    label = adapter.display_name.casefold()
    aliases = {adapter.app_id.casefold(), label}
    if adapter.app_id == "codex" and path and not any(part.casefold() in ("bin", "vendor", "runtimes") for part in Path(path).parts) and "cli" not in descriptor:
        return []
    # Codex Desktop may share a basename with the CLI. PATH/bin/vendor workers
    # must never be classified as Desktop.
    if adapter.app_id == "codex-gui":
        if any(part.casefold() in ("bin", "vendor", "runtimes") for part in Path(path).parts):
            return []
        aliases.add("codex")
    if adapter.app_id == "vscode-insiders" and "insiders" not in descriptor + path.casefold():
        return []
    if adapter.app_id == "vscode" and "insiders" in descriptor + path.casefold():
        return []
    candidates = [path] if basename in exe_names else []
    location = entry.get("location", "")
    if location and any(alias in descriptor for alias in aliases):
        for name in exe_names:
            for relative in (name, "bin/" + name, "app/" + name, "Common7/IDE/" + name):
                candidates.append(str(Path(location) / relative))
        if entry.get("source") == "package":
            manifest = Path(location) / "AppxManifest.xml"
            try:
                root = ET.parse(manifest).getroot()
                for element in root.iter():
                    executable = element.attrib.get("Executable")
                    if executable and Path(executable).name.lower() in exe_names:
                        candidate = Path(location) / executable
                        if candidate.resolve().is_relative_to(Path(location).resolve()):
                            candidates.append(str(candidate))
            except (OSError, ET.ParseError):
                pass
    return candidates


def npm_candidate(adapter):
    packages = {"codex": ("@openai/codex", "@openai/codex-win32-x64"),
                "opencode": ("opencode-ai", "opencode-windows-x64", "opencode-windows-x64-baseline"),
                "claude": ("@anthropic-ai/claude-code",)}
    if adapter.app_id not in packages:
        return None
    roots = []
    roaming = os.environ.get("APPDATA")
    if roaming:
        roots.append(Path(roaming) / "npm/node_modules")
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots += [Path(local) / "npm/node_modules", Path(local) / "fnm/node-versions"]
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if directory:
            roots.append(Path(directory) / "node_modules")
    for root in dict.fromkeys(roots):
        for package in packages[adapter.app_id]:
            base = root / package
            if not base.is_dir():
                continue
            exe = adapter.app_id + ".exe"
            for pattern in (exe, "bin/" + exe, "*/*/" + exe, "*/*/*/" + exe,
                            "node_modules/*/bin/" + exe, "node_modules/@*/*/vendor/*/codex/" + exe):
                for path in glob.glob(str(base / pattern))[:50]:
                    if os.path.isfile(path):
                        return path, []
            # Read the package's declared CLI entry; never execute a .cmd wrapper.
            node = shutil.which("node.exe")
            try:
                data = json.loads((base / "package.json").read_text(encoding="utf-8"))
                binary = data.get("bin", {})
                script = binary.get(adapter.app_id) if isinstance(binary, dict) else binary
                if node and isinstance(script, str):
                    path = (base / script).resolve()
                    if path.is_relative_to(base.resolve()) and path.is_file() and path.suffix in (".js", ".mjs", ".cjs"):
                        return node, [str(path)]
            except (OSError, ValueError):
                pass
    return None


def discover_applications(entries=None):
    from .adapters import list_adapters
    entries = registry_entries() + shell_entries() if entries is None else entries
    records = []
    for adapter in list_adapters():
        candidates = adapter.get_executable_paths() + pattern_paths(adapter)
        for entry in entries:
            candidates.extend(entry_paths(entry, adapter))
        existing = []
        seen = set()
        for path in candidates:
            if path and path.lower().endswith(".exe") and os.path.isfile(path) and canonical(path) not in seen:
                seen.add(canonical(path))
                existing.append(str(Path(path).resolve()))
        arguments = []
        if existing:
            # Prefer ordinary installs/PATH ahead of protected WindowsApps files.
            existing.sort(key=lambda path: ("windowsapps" in path.casefold(),))
            executable = existing[0]
        else:
            native = npm_candidate(adapter)
            if not native:
                continue
            executable, arguments = native
        records.append(dict(id=adapter.app_id, name=adapter.display_name, executable=executable,
                            arguments=arguments, electron=adapter.electron and not arguments,
                            selected=False, source="auto"))
    return records


def merge_applications(saved, found):
    by_id = {item["id"]: item for item in found}
    result, used = [], set()
    for record in saved:
        if not isinstance(record, dict) or not isinstance(record.get("executable"), str) or not record.get("id"):
            continue
        if record.get("source") != "manual" and record["id"] in by_id:
            updated = dict(by_id[record["id"]])
            updated["selected"] = bool(record.get("selected"))
            result.append(updated)
            used.add(record["id"])
        else:
            result.append(record)
            used.add(record["id"])
    result.extend(record for record in found if record["id"] not in used)
    return result
