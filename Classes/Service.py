import threading
import subprocess
import os
import signal
import time
import socket

class Service(threading.Thread):
    def __init__(self, name, filename):
        super().__init__()
        self.name = name
        self.filename = filename
        self._stop_event = threading.Event()
        self.proc = None

    def off(self):
        if not self.is_alive():
            return
        # try:
        #     with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        #         s.connect(f"/tmp/{self.name}_control.sock")
        #         s.send(f"stop".encode())
        #         response = s.recv(1024).decode()
        # except Exception as e:
        #     return
        self._stop_event.set()
        if self.is_alive() and self.proc:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
        return

    def help(self):
        # TODO: Implement help message for the service by sending a command to the service socket and return the recv str
        return "TODO HELP message"

    def info(self):
        if self.is_alive():
            return f"Service: {self.name}\nStatus: Running\nPID:{self.proc.pid}\nScript: {self.filename}"
        else:
            return f"Service: {self.name}\nStatus: Stopped\nScript: {self.filename}"

    def run(self):
        try:
            self.proc = subprocess.Popen(
                ["sudo", "./firenv/bin/python3", "-u", self.filename], # TODO remove -u for production
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                text=True,
                preexec_fn=os.setsid,
            )

            while not self._stop_event.is_set():
                output = self.proc.stdout.readline()
                if output == '' and self.proc.poll() is not None:
                    break
                # if output:
                #     print(f"\n\033[1m\033[33m[{self.name}] \033[0m{output.strip()}")
        except Exception as e:
            print(f"Error in {self.name} supervisor: {e}")
        finally:
            pass