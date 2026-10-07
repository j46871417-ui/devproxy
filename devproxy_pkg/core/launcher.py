"""Session owner for transport, isolated Electron profile and application lifetime."""
import atexit
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from .tunnel import LocalTunnel


class RoutingUnavailable(RuntimeError):
    pass


class ApplicationSession:
    backend = "native-environment"
    guarantees_per_app_routing = False

    def __init__(self, profile, bind_port=0, profile_provider=None):
        self.profile = profile
        # The provider supplies current saved metadata and secret for each NEW
        # connection; existing streams keep the profile they opened with.
        self.tunnel = LocalTunnel(profile, bind_port=bind_port, profile_provider=profile_provider)
        self.processes = []
        self._directories = []
        self._job = None
        self._lock = threading.RLock()
        self.closed = False
        atexit.register(self.stop)

    def start(self, require_fail_closed=False):
        if require_fail_closed:
            raise RoutingUnavailable("Strict per-application routing requires a WFP redirector; this build only supports native/environment proxy configuration")
        with self._lock:
            if self.closed:
                raise RuntimeError("Session already stopped")
            self.tunnel.start()
        return self

    def launch(self, executable, flags=None, extra_args=None, electron=False, console=False, preserve_profile=False):
        with self._lock:
            if self.closed or not self.tunnel.is_running:
                raise RuntimeError("Start the session first")
            arguments = [flag.replace("{PROXY_URL}", self.tunnel.proxy_url) for flag in (flags or [])]
            extra_args = list(extra_args or [])
            forbidden = ("--proxy-server", "--proxy-bypass-list", "--no-proxy-server", "--user-data-dir",
                         "--ignore-certificate-errors", "--ignore-urlfetcher-cert-requests")
            if any(arg.split("=", 1)[0] in forbidden for arg in extra_args):
                raise ValueError("Application arguments cannot override session proxy, profile or TLS policy")
            if electron and not preserve_profile:
                directory = tempfile.TemporaryDirectory(prefix="devproxy-session-")
                self._directories.append(directory)
                user = os.path.join(directory.name, "User")
                os.makedirs(user)
                with open(os.path.join(user, "settings.json"), "w", encoding="utf-8") as f:
                    json.dump({"http.proxy": self.tunnel.proxy_url, "http.proxySupport": "override",
                               "http.proxyStrictSSL": True}, f)
                arguments += ["--user-data-dir=" + directory.name]
            if electron:
                # Electron apps can serve their own UI on loopback. Never send it to the upstream proxy.
                arguments += ["--proxy-bypass-list=localhost;127.0.0.1;[::1]", "--disable-quic"]
            arguments += extra_args
            env = {}
            for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
                env[name] = self.tunnel.proxy_url
            env.update(NO_PROXY="localhost,127.0.0.1,::1", no_proxy="localhost,127.0.0.1,::1", NODE_TLS_REJECT_UNAUTHORIZED="1")
            if os.name == "nt" and self._job is None:
                from .windows_job import WindowsJob
                self._job = WindowsJob()
            creationflags = 4 if self._job else 0
            if os.name == "nt" and console:
                creationflags |= subprocess.CREATE_NEW_CONSOLE
            proc = Launcher.launch(executable, arguments, env, creationflags=creationflags)
            try:
                if self._job:
                    self._job.attach_and_resume(proc)
            except BaseException:
                proc.kill()
                proc.wait()
                raise
            self.processes = [p for p in self.processes if p.poll() is None]
            self.processes.append(proc)
            return proc

    def active(self):
        if self.closed:
            return False
        if self._job:
            return bool(self._job.active_count())
        return any(proc.poll() is None for proc in self.processes)

    def wait(self):
        try:
            while self.active():
                time.sleep(0.1)
            return self.processes[0].wait() if self.processes else 0
        finally:
            self.stop()

    def stop(self):
        with self._lock:
            if self.closed:
                return
            self.closed = True
            if self._job:
                self._job.close()  # Kernel kills descendants, including on DevProxy crash.
            for proc in self.processes:
                if proc.poll() is None:
                    proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            self.tunnel.stop()
            for directory in self._directories:
                try:
                    directory.cleanup()
                except OSError:
                    # Windows may release descendant file handles asynchronously.
                    for _ in range(20):
                        time.sleep(0.05)
                        try:
                            directory.cleanup()
                            break
                        except OSError:
                            pass
            atexit.unregister(self.stop)

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


class Launcher:
    @staticmethod
    def launch(executable, extra_args=None, env_vars=None, wait=False, cwd=None, creationflags=0):
        executable = os.path.abspath(executable) if os.path.isfile(executable) else shutil.which(executable)
        if not executable or not os.path.isfile(executable):
            raise FileNotFoundError("Application executable not found")
        if os.name == "nt" and not executable.lower().endswith(".exe"):
            raise ValueError("Select the actual EXE; batch and command wrappers are unsupported")
        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)
        proc = subprocess.Popen([executable] + list(extra_args or []), env=env, cwd=cwd,
                                shell=False, creationflags=creationflags)
        if wait:
            proc.wait()
        return proc

    @classmethod
    def launch_with_tunnel(cls, executable, profile, adapter_cli_flags=None, extra_args=None, wait=True):
        session = ApplicationSession(profile)
        try:
            session.start()
            flags = adapter_cli_flags or []
            proc = session.launch(executable, flags, extra_args,
                                  electron=any(f.startswith("--proxy-server") for f in flags))
            if wait:
                session.wait()
            else:
                def monitor():
                    session.wait()
                threading.Thread(target=monitor, daemon=True, name="DevProxySession").start()
            # A nonblocking caller must explicitly stop the owning session.
            session.tunnel.session = session
            return proc, session.tunnel
        except BaseException:
            session.stop()
            raise


def shutil_which(cmd):
    return shutil.which(cmd)
