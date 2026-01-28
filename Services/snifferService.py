from scapy.all import sniff, IP
import logging
import threading
import os
import socket
import json

logging.basicConfig(
    filename='sniffer_activity.log',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S'
)

class SnifferService:
    def __init__(self, ctrl_socket="/tmp/sniffer_control.sock"):
        self.ctrl_socket = ctrl_socket
        self.pkt_socket = "/tmp/sniffer.sock"
        self.clients = []
        self.running = True

        if os.path.exists(self.pkt_socket):
            os.remove(self.pkt_socket)

        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.pkt_socket)
        self.server.listen(5)
        self.server.setblocking(False)

    def stop(self):
        self.server.close()
        self.clients.clear()
        self.running = False
        if os.path.exists(self.pkt_socket):
            os.remove(self.pkt_socket)
        if os.path.exists(self.ctrl_socket):
            os.remove(self.ctrl_socket)
        logging.info("Sniffer service stopped.")

    def run(self):
        threading.Thread(target=self._cmd_listener, daemon=True).start()
        threading.Thread(target=self._acc_client, daemon=True).start()
        logging.info("Sniffer service started.")
        sniff(iface=["eth0", "eth1"], filter="ip", prn=self._packet_handler, store=0) # TODO iface=["eth0", "eth1"] change depending of environment (config file ?)

    def _cmd_listener(self):
        if os.path.exists(self.ctrl_socket):
            os.remove(self.ctrl_socket)

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.bind(self.ctrl_socket)
            s.listen(1)
            while True:
                conn, _ = s.accept()
                with conn:
                    data = conn.recv(1024).decode().strip()
                    if not data:
                        continue
                    self._run_cmd(data)

    def _acc_client(self):
        while self.running:
            try:
                con, _ = self.server.accept()
                self.clients.append(con)
                logging.info(f"New client connected. {con}") # TODO remove debug
            except BlockingIOError:
                pass
            except Exception as e:
                if self.running:
                    logging.error(f"Error accepting client: {e}")
                break

    def _run_cmd(self, data):
        cmd = data.split()
        logging.info(f"CMD recv: {data}\n")

        if cmd[0] == "off":
            self.stop()

    def _packet_handler(self, pkt):
        if IP in pkt:
            data = json.dumps({
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "proto": pkt[IP].proto,
                "len": pkt[IP].len
            }) + "\n"

            for client in self.clients[:]:
                try:
                    client.sendall(data.encode())
                except:
                    self.clients.remove(client)

sniffer = SnifferService()
sniffer.run()