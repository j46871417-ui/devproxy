"""
Launcher: Safe process execution with isolated environment and command-line arguments.
Rules:
- NEVER uses shell=True.
- Passes clean list of arguments.
- Safely injects HTTP_PROXY / HTTPS_PROXY / ALL_PROXY into the target child process ONLY.
- Leaves global machine / user environment untouched.
"""

import os
import sys
import subprocess
from typing import List, Dict, Optional, Tuple
from .tunnel import LocalTunnel
from .profile import ProxyProfile


class Launcher:
    @staticmethod
    def launch(
        executable: str,
        extra_args: Optional[List[str]] = None,
        env_vars: Optional[Dict[str, str]] = None,
        wait: bool = False,
        cwd: Optional[str] = None
    ) -> subprocess.Popen:
        """
        Executes binary safely without shell=True.
        """
        if not os.path.exists(executable) and not shutil_which(executable):
            raise FileNotFoundError(f"Executable not found: {executable}")

        cmd = [executable]
        if extra_args:
            cmd.extend(extra_args)

        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)

        # On Windows, avoid console window popping up if launching GUI, or attach properly
        creationflags = 0
        
        proc = subprocess.Popen(
            cmd,
            env=env,
            cwd=cwd,
            creationflags=creationflags
        )
        if wait:
            proc.wait()
        return proc

    @classmethod
    def launch_with_tunnel(
        cls,
        executable: str,
        profile: ProxyProfile,
        adapter_cli_flags: Optional[List[str]] = None,
        extra_args: Optional[List[str]] = None,
        wait: bool = True
    ) -> Tuple[subprocess.Popen, LocalTunnel]:
        """
        Starts ephemeral LocalTunnel and launches application configured to use it.
        When session ends, tunnel is automatically terminated.
        """
        tunnel = LocalTunnel(profile)
        port = tunnel.start()

        local_proxy_url = f"http://127.0.0.1:{port}"
        
        # Prepare environment
        env_vars = {
            "HTTP_PROXY": local_proxy_url,
            "HTTPS_PROXY": local_proxy_url,
            "ALL_PROXY": local_proxy_url,
            "http_proxy": local_proxy_url,
            "https_proxy": local_proxy_url,
            "all_proxy": local_proxy_url,
            "NO_PROXY": "localhost,127.0.0.1,::1",
            "no_proxy": "localhost,127.0.0.1,::1"
        }

        # Combine arguments
        cmd_args = []
        if adapter_cli_flags:
            for flag in adapter_cli_flags:
                cmd_args.append(flag.replace("{PROXY_URL}", local_proxy_url))
        if extra_args:
            cmd_args.extend(extra_args)

        proc = cls.launch(executable, extra_args=cmd_args, env_vars=env_vars, wait=wait)
        return proc, tunnel


def shutil_which(cmd: str) -> Optional[str]:
    import shutil
    return shutil.which(cmd)
