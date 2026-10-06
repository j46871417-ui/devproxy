"""Per-user authenticated named-pipe control; only approved app IDs can launch."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import threading
import time
from multiprocessing.connection import Client, Listener, AuthenticationError
from .recovery import get_devproxy_state_path


def endpoint():
    identity = hashlib.sha256(os.path.abspath(get_devproxy_state_path()).lower().encode()).hexdigest()[:24]
    return r"\\.\pipe\DevProxy-" + identity


def auth_key(create=False):
    path = Path(get_devproxy_state_path()).with_name("agent.key")
    if create and not path.exists():
        try:
            with path.open("xb") as file:
                file.write(secrets.token_bytes(32))
        except FileExistsError:
            pass
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError("Invalid agent authentication key")
    return key


def request(message, timeout=15):
    with Client(endpoint(), family="AF_PIPE", authkey=auth_key()) as connection:
        connection.send_bytes(json.dumps(message).encode("utf-8"))
        if not connection.poll(timeout):
            raise TimeoutError("Background agent did not respond")
        result = json.loads(connection.recv_bytes(65536))
    if not result.get("ok"):
        raise RuntimeError(result.get("error", "Background operation failed"))
    return result


class AgentServer:
    def __init__(self, dispatch):
        self.dispatch = dispatch
        self.closed = False
        self.listener = Listener(endpoint(), family="AF_PIPE", authkey=auth_key(create=True))
        self.thread = threading.Thread(target=self.run, daemon=True, name="DevProxyControl")
        self.thread.start()

    def run(self):
        while not self.closed:
            try:
                with self.listener.accept() as connection:
                    if not connection.poll(3):
                        continue
                    message = json.loads(connection.recv_bytes(65536))
                    result = self.dispatch(message)
                    connection.send_bytes(json.dumps(result, ensure_ascii=False).encode("utf-8"))
            except (OSError, EOFError, ValueError, AuthenticationError):
                if self.closed:
                    return

    def close(self):
        self.closed = True
        self.listener.close()


def request_with_start(message, command):
    try:
        return request(message)
    except (OSError, EOFError):
        import subprocess
        subprocess.Popen(command + ["--background"], creationflags=subprocess.CREATE_NO_WINDOW)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        try:
            return request(message)
        except (OSError, EOFError):
            time.sleep(0.15)
    raise TimeoutError("Background agent failed to start")
