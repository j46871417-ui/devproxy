"""Process-scoped proxy environment and explicit session ownership."""
import ctypes
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from .tunnel import LocalTunnel


class WindowsJob:
    """Kill the launched process tree when its owning proxy session ends."""
    def __init__(self, process):
        from ctypes import wintypes as w

        class Basic(ctypes.Structure):
            _fields_ = [('ProcessTime', ctypes.c_int64), ('JobTime', ctypes.c_int64),
                        ('Flags', w.DWORD), ('MinWorkingSet', ctypes.c_size_t), ('MaxWorkingSet', ctypes.c_size_t),
                        ('ActiveProcessLimit', w.DWORD), ('Affinity', ctypes.c_size_t),
                        ('Priority', w.DWORD), ('Scheduling', w.DWORD)]

        class Io(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ('ReadOps', 'WriteOps', 'OtherOps', 'ReadBytes', 'WriteBytes', 'OtherBytes')]

        class Limits(ctypes.Structure):
            _fields_ = [('Basic', Basic), ('Io', Io), ('ProcessMemory', ctypes.c_size_t),
                        ('JobMemory', ctypes.c_size_t), ('PeakProcessMemory', ctypes.c_size_t), ('PeakJobMemory', ctypes.c_size_t)]

        api = ctypes.WinDLL('kernel32', use_last_error=True)
        api.CreateJobObjectW.argtypes, api.CreateJobObjectW.restype = [ctypes.c_void_p, w.LPCWSTR], w.HANDLE
        api.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        api.SetInformationJobObject.restype = w.BOOL
        api.AssignProcessToJobObject.argtypes, api.AssignProcessToJobObject.restype = [w.HANDLE, w.HANDLE], w.BOOL
        api.CloseHandle.argtypes, api.CloseHandle.restype = [w.HANDLE], w.BOOL
        handle = api.CreateJobObjectW(None, None)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = Limits()
        limits.Basic.Flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        try:
            if not api.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise ctypes.WinError(ctypes.get_last_error())
            if process.poll() is None and not api.AssignProcessToJobObject(handle, int(process._handle)):
                raise ctypes.WinError(ctypes.get_last_error())
        except Exception:
            api.CloseHandle(handle)
            raise
        self.api, self.handle = api, handle

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def command_for(executable, extra_args):
    """Use the JS entrypoint of npm shims instead of handing arguments to cmd."""
    if os.name == 'nt' and executable.lower().endswith(('.cmd', '.bat')):
        with open(executable, encoding='utf-8-sig') as handle:
            text = handle.read()
        matches = re.findall(r'"%dp0%[\\/]([^"\r\n]+\.js)"', text, re.IGNORECASE)
        if not matches:
            raise ValueError('Batch launcher unsupported. Select the native executable with --executable.')
        script = os.path.normpath(os.path.join(os.path.dirname(executable), matches[-1]))
        node = os.path.join(os.path.dirname(executable), 'node.exe')
        node = node if os.path.isfile(node) else shutil.which('node')
        if not node or not os.path.isfile(script):
            raise ValueError('Node.js launcher entrypoint not found.')
        return [node, script] + list(extra_args)
    return [executable] + list(extra_args)


class Launcher:
    @staticmethod
    def launch(executable, extra_args=None, env_vars=None, wait=False, cwd=None):
        if not os.path.isfile(executable) and not shutil.which(executable):
            raise FileNotFoundError('Application executable not found.')
        env = os.environ.copy()
        env.update(env_vars or {})
        process = subprocess.Popen(command_for(executable, extra_args or []), env=env, cwd=cwd,
                                   start_new_session=os.name != 'nt',
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
        if wait:
            process.wait()
        return process

    @classmethod
    def launch_with_tunnel(cls, executable, profile, adapter_cli_flags=None, extra_args=None,
                           wait=True, keep_alive=False, user_data_dir=None, no_proxy=None):
        tunnel, process, job, handed_off = LocalTunnel(profile), None, None, False
        session_lock = None
        try:
            if user_data_dir:
                if not wait:
                    raise ValueError('GUI sessions require an owning, waiting launcher.')
                directory = Path(user_data_dir).expanduser().resolve()
                directory.mkdir(parents=True, exist_ok=True)
                session_lock = directory / '.devproxy-session.lock'
                try:
                    fd = os.open(session_lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                except FileExistsError:
                    session_lock = None
                    raise ValueError('This GUI profile already has a proxy session. If a prior launcher crashed, close its application before removing .devproxy-session.lock.') from None
                with os.fdopen(fd, 'w') as handle:
                    handle.write(str(os.getpid()))
                user_data_dir = str(directory)
            port = tunnel.start()
            url = f'http://127.0.0.1:{port}'
            # Preserve explicit corporate bypasses; document that bypassed targets
            # are intentionally outside the tunnel. --no-proxy overrides them.
            existing = no_proxy if no_proxy is not None else os.environ.get('no_proxy', os.environ.get('NO_PROXY', ''))
            exclusions = [x for x in re.split(r'[\s,]+', existing) if x]
            for host in ('localhost', '127.0.0.1', '::1'):
                if host not in exclusions:
                    exclusions.append(host)
            bypass = ','.join(exclusions)
            env = {k: url for k in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')}
            env.update(NO_PROXY=bypass, no_proxy=bypass, NODE_USE_ENV_PROXY='1')
            flags = [f.replace('{PROXY_URL}', url) for f in (adapter_cli_flags or [])]
            args = list(extra_args or [])
            if user_data_dir:
                if any(a == '--user-data-dir' or a.startswith('--user-data-dir=') for a in args):
                    raise ValueError('Use DevProxy --user-data-dir instead of passing it after --.')
                flags.append('--user-data-dir=' + user_data_dir)
                if '--wait' not in flags:
                    flags.append('--wait')
            process = cls.launch(executable, flags + args, env, wait=False)
            if os.name == 'nt' and isinstance(process, subprocess.Popen):
                job = WindowsJob(process)
            if wait:
                process.wait()
                if keep_alive and process.returncode == 0:
                    print('GUI launcher exited. Proxy remains active. Close the application and press Ctrl+C to end the session.')
                    while True:
                        time.sleep(0.25)
                return process, tunnel
            # The caller owns both handles for non-waiting use.
            if job:
                process.devproxy_job = job
            handed_off = True
            return process, tunnel
        finally:
            if wait or not handed_off:
                if job:
                    job.close()
                elif process is not None:
                    if os.name != 'nt' and isinstance(process, subprocess.Popen):
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                    elif process.poll() is None:
                        process.terminate()
                tunnel.stop()
                if session_lock is not None:
                    session_lock.unlink(missing_ok=True)


def shutil_which(command):
    return shutil.which(command)
