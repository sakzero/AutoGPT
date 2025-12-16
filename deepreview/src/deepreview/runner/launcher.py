import os
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Optional, TextIO


class AppLauncher:
    def __init__(self, analyzer, python_executable=None, env=None, log_path: Optional[str | Path] = None):
        self.analyzer = analyzer
        self.python_executable = python_executable or sys.executable
        self.env = self._ensure_utf8(env or os.environ.copy())
        self.process = None
        self._stdout_buffer = deque(maxlen=200)
        self._stderr_buffer = deque(maxlen=200)
        self._stream_threads = []
        self.log_path = Path(log_path) if log_path else None
        self._log_file: Optional[TextIO] = None
        self._log_lock = threading.Lock()

    def _ensure_utf8(self, env):
        env.setdefault("PYTHONUTF8", "1")
        env.setdefault("PYTHONIOENCODING", "utf-8")
        return env

    def start(self):
        """Starts the target application in a subprocess."""
        if not self.analyzer.entry_file:
            print("[Launcher] No entry file to start.")
            return False
            
        print(f"[Launcher] Starting {os.path.basename(self.analyzer.entry_file)}...")

        cmd = [self.python_executable, self.analyzer.entry_file]
        if self.analyzer.framework == "django":
            cmd.extend(["runserver", str(self.analyzer.port)])

        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_file = self.log_path.open("w", encoding="utf-8")

        self.process = subprocess.Popen(
            cmd,
            cwd=self.analyzer.root_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=self.env,
        )
        self._start_stream_threads()
        return True

    def wait_for_health_check(self, timeout=15):
        start_time = time.time()
        print(f"[Launcher] Waiting for 127.0.0.1:{self.analyzer.port}...")
        while time.time() - start_time < timeout:
            try:
                with socket.create_connection(("127.0.0.1", self.analyzer.port), timeout=1):
                    print(f"[Launcher] Port {self.analyzer.port} is OPEN.")
                    return True
            except (ConnectionRefusedError, socket.timeout, OSError):
                time.sleep(0.5)
        return False

    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            print("[Launcher] Target app stopped.")
            self.process = None
        if self._log_file:
            with self._log_lock:
                self._log_file.close()
            self._log_file = None

    def run_exploit(self, exploit_path):
        print("[Launcher] Running exploit script...")
        try:
            result = subprocess.run(
                [self.python_executable, exploit_path],
                capture_output=True, 
                text=True, 
                timeout=10,
                env=self.env,
                cwd=self.analyzer.root_dir,
            )
            return result.stdout or "", result.stderr or ""
        except Exception as e:
            return None, str(e)

    def get_recent_logs(self):
        stdout = "\n".join(self._stdout_buffer)
        stderr = "\n".join(self._stderr_buffer)
        return stdout, stderr

    def _start_stream_threads(self):
        if not self.process:
            return
        self._stream_threads = [
            threading.Thread(
                target=self._capture_stream,
                args=(self.process.stdout, self._stdout_buffer, "[Target][stdout]"),
                daemon=True,
            ),
            threading.Thread(
                target=self._capture_stream,
                args=(self.process.stderr, self._stderr_buffer, "[Target][stderr]"),
                daemon=True,
            ),
        ]
        for thread in self._stream_threads:
            thread.start()

    def _capture_stream(self, stream, buffer, prefix):
        if not stream:
            return
        for line in stream:
            cleaned = line.rstrip()
            if cleaned:
                buffer.append(cleaned)
                print(f"{prefix} {cleaned}")
                if self._log_file:
                    with self._log_lock:
                        self._log_file.write(f"{prefix} {cleaned}\n")
        stream.close()
