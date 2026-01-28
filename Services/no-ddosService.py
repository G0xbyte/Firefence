import socket
import json
import logging
import threading
import redis
import os

logging.basicConfig(
    filename='no-ddos_activity.log',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S'
)

class NoDDOSService:
    def __init__(self, ctrl_socket="/tmp/no-ddos_control.sock"):
        self.ctrl_socket = ctrl_socket
        self.filter_socket = "/tmp/filter_control.sock"
        self.pkt_socket = "/tmp/sniffer.sock"
        self.sniff_window = 5
        self.threshold = 150
        self.redis = redis.Redis(host='localhost', port=6379, db=27, decode_responses=True)

    def stop(self):
        if os.path.exists(self.ctrl_socket):
            os.remove(self.ctrl_socket)
        logging.info("No DDOS service stopped.")

    def run(self):
        cmd_thread = threading.Thread(target=self._cmd_listener, daemon=True)
        cmd_thread.start()
        self._pkt_listener()

    def _cmd_listener(self):
        if os.path.exists(self.ctrl_socket):
            os.remove(self.ctrl_socket)

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(self.ctrl_socket)
            server.listen(1)
            while True:
                conn, _ = server.accept()
                with conn:
                    data = conn.recv(1024).decode().strip()
                    if not data:
                        continue
                    result = self._run_cmd(data.split(' '))
                    if result:
                        conn.sendall(result.encode())

    def _run_cmd(self, data):
        logging.info(f"CMD recv: {data}\n")

        if data[0] == "off":
            self.stop()
        elif data[0] == "help":
            help_msg = (
                "No DDOS Service Commands:\n"
                "  help                      - Show this help message\n"
            )
            return help_msg
        return "Unknown command or wrong parameters. Type no-ddos help\n"

    def _pkt_listener(self):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(self.pkt_socket)
            buffer = ""
            logging.info("No DDOS service started.")
            while True:
                data = client.recv(4096).decode()
                if not data: break
                buffer += data
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    self._process_pkt(line)
        except Exception as e:
            logging.error(f"Error while connecting to sniffer service, is the sniffer service activated?\n Error: {e}")

    def _process_pkt(self, pkt):
        src_ip = json.loads(pkt).get("src")

        if self.redis.exists(f"blocked:{src_ip}"):
            return

        current_count = self.redis.incr(src_ip)

        if current_count == 1:
            self.redis.expire(src_ip, self.sniff_window)
            logging.info(f"Monitoring new IP: {src_ip}")

        if current_count > self.threshold:
            result = self.send_cmd(f"timeout {src_ip}")
            if "Error" in result:
                logging.error(f"Failed to block IP {src_ip} via filter service.")
                return
            self.redis.setex(f"blocked:{src_ip}", 60, "true")
            return

    def send_cmd(self, cmd):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(self.filter_socket)
                s.sendall(f"{cmd}".encode())
                response = s.recv(1024).decode()
                if response:
                    logging.info(f"CMD response: {response}")
                    return response
        except Exception as e:
            logging.error(f"Error while connecting to sniffer service, is the sniffer service activated?\n Error: {e}")
            return "Error"

noDDOS = NoDDOSService()
noDDOS.run()