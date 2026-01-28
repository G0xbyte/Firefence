import socket
import json
import logging
import threading
import os
from pyroute2 import IPSet
import iptc

# TODO Connect with anti DDOS
# TODO Anti exfiltration system
# TODO Remove here the sniffer broadcast no need to handle packet in this service && Move logging packet to sniffer service
# TODO Persistence doesn't work

logging.basicConfig(
    filename='filter_activity.log',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S'
)

class FilterService:
    def __init__(self, ctrl_socket="/tmp/filter_control.sock"):
        self.ctrl_socket = ctrl_socket
        self.pkt_socket = "/tmp/sniffer.sock"
        self.log_pkts = False
        self.ipset = IPSet()
        self.table = iptc.Table(iptc.Table.FILTER)
        self.sets_conf = [("firefence-whitelist", "ACCEPT", 0), ("firefence-blacklist", "DROP", 0), ("firefence-timeout", "DROP", 60)]
        self.persistence_file = f"/etc/firefence/ipset.conf"
        self._setup_rules()

    def stop(self):
        if os.path.exists(self.ctrl_socket):
            os.remove(self.ctrl_socket)
        self.ipset.close()
        logging.info("Filter service stopped.")

    def _setup_rules(self):
        self._load_ipset()
        for set_name, action, timeout in self.sets_conf:
            try:
                self.ipset.create(set_name, stype="hash:ip", family=socket.AF_INET, timeout=timeout)

                for chain_name, match_type in [("INPUT", "src"), ("OUTPUT", "dst")]:
                    logging.info(f"chain: {chain_name} | match_type: {match_type}")
                    chain = iptc.Chain(self.table, chain_name)
                    rule = iptc.Rule()
                    match = rule.create_match("set")
                    match.match_set = [set_name, match_type]
                    rule.target = iptc.Target(rule, action)
                    if rule not in chain.rules:
                        logging.info(f"Inserting rule for {set_name} in {chain_name} chain.")
                        chain.insert_rule(rule)
            except Exception as e:
                logging.info(f"Kernel setup warning: {e}")

    def _load_ipset(self):
        try:
            if os.path.exists(self.persistence_file):
                with open(self.persistence_file, 'r') as f:
                    data = json.load(f)

                for set_name, ip_list in data.items():
                    if set_name in self.sets_conf[0]:
                        try:
                            self.ipset.flush(set_name)
                        except:
                            pass
                        for ip in ip_list:
                            try:
                                self.ipset.add(set_name, ip, etype="ip")
                                logging.info(f"Loaded {ip} into {set_name}")
                            except Exception as e:
                                logging.warning(f"Failed to load {ip} into {set_name}: {e}")
        except Exception as e:
            logging.error(f"Error loading ipset from {self.persistence_file}: {e}")

    def _save_ipset(self):
        try:
            os.makedirs(os.path.dirname(self.persistence_file), exist_ok=True)

            data = {}
            for set_name, _, _ in self.sets_conf:
                try:
                    content = next(self.ipset.list(set_name))
                    members = content.get('members', [])
                    ip_list = [m.get('value') for m in members if m.get('value')]
                    data[set_name] = ip_list
                except StopIteration:
                    logging.warning(f"Set {set_name} not found in kernel.")
                    data[set_name] = []
                except Exception as e:
                    logging.warning(f"Error saving {set_name}: {e}")
                    data[set_name] = []

            with open(self.persistence_file, 'w') as f:
                json.dump(data, f)
            logging.info(f"IP sets saved to {self.persistence_file}")
        except Exception as e:
            logging.error(f"Error saving ipset to {self.persistence_file}: {e}")

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
        elif data[0] == "log" and len(data) > 1:
            return self.log_pkt(data[1].lower())
        elif data[0] == "blacklist" and len(data) == 2 :
            return self.ban_ip(data[1])
        elif data[0] == "unblacklist" and len(data) == 2 :
            return self.unban_ip(data[1])
        elif data[0] == "whitelist" and len(data) == 2 :
            return self.whitelist_ip(data[1])
        elif data[0] == "unwhitelist" and len(data) == 2:
            return self.unwhitelist_ip(data[1])
        elif data[0] == "list":
            return self.see_lists()
        elif data[0] == "timeout" and len(data) == 2:
            return self.set_timeout(data[1])
        elif data[0] == "help":
            help_msg = (
                "Filter Service Commands:\n"
                "  off                       - Stop the filter service\n"
                "  log [on|off]              - Enable or disable packet logging\n"
                "  blacklist <IP>            - Add an IP to the blacklist\n"
                "  unblacklist <IP>          - Remove an IP from the blacklist\n"
                "  whitelist <IP>            - Add an IP to the whitelist\n"
                "  unwhitelist <IP>          - Remove an IP from the whitelist\n"
                "  timeout <IP>              - Timeout (60s) an IP\n"
                "  list                      - Show current blacklists and whitelists\n"
                "  help                      - Show this help message\n"
            )
            return help_msg
        return "Unknown command or wrong parameters. Type filter help\n"


    def _pkt_listener(self):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(self.pkt_socket)
            buffer = ""
            logging.info("Filter service started.")
            while True:
                data = client.recv(4096).decode()
                if not data: break
                buffer += data
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    self._process_pkt(line)
        except Exception as e:
            logging.error(f"Error while connecting to sniffer service, is the sniffer service activated?")

    def _process_pkt(self, pkt_data):
        if self.log_pkts:
            packet = json.loads(pkt_data)
            logging.info(f"PKT recv: {packet}")
        packet = json.loads(pkt_data)
        src_ip = packet.get("src")

    def log_pkt(self, status):
        if status in ["true", "1", "yes", "on"]:
            status = True
        elif status in ["false", "0", "no", "off"]:
            status = False
        self.log_pkts = status
        logging.info(f"Packet logging set to {self.log_pkts}")
        return f"Packet logging (filter_activity.log) set to {self.log_pkts}\n"


    def ban_ip(self, ip, timeout=0):
        try:
            self.ipset.add("firefence-blacklist", ip, etype="ip")
            self._save_ipset()
            logging.info(f"{ip} added to blacklist")
            return f"{ip} added to blacklist\n"
        except Exception as e:
            logging.error(f"Error banning {ip}: {e}")
            return f"Error banning {ip}: {e}\n"

    def unban_ip(self, ip):
        try:
            self.ipset.delete("firefence-blacklist", ip, etype="ip")
            self._save_ipset()
            logging.info(f"{ip} removed from blacklist")
            return f"{ip} removed from blacklist\n"
        except Exception as e:
            logging.error(f"Error unbanning {ip}: {e}")
            return f"Error unbanning {ip}: {e}\n"

    def whitelist_ip(self, ip):
        try:
            self.ipset.add("firefence-whitelist", ip, etype="ip")
            self._save_ipset()
            logging.info(f"{ip} added to Whitelist")
            return f"{ip} added to Whitelist\n"
        except Exception as e:
            logging.error(f"Error whitelisting {ip}: {e}")
            return f"Error whitelisting {ip}: {e}\n"

    def unwhitelist_ip(self, ip):
        try:
            self.ipset.delete("firefence-whitelist", ip, etype="ip")
            self._save_ipset()
            logging.info(f"{ip} removed from Whitelist")
            return f"{ip} removed from Whitelist\n"
        except Exception as e:
            logging.error(f"Error removing {ip} from whitelist: {e}")
            return f"Error removing {ip} from whitelist: {e}\n"

    def set_timeout(self, ip):
        if self.ipset.test("firefence-whitelist", ip, etype="ip"):
            logging.info(f"Attempted to timeout whitelisted IP {ip}, action ignored.")
            return f"Cannot timeout whitelisted IP {ip}\n"
        try:
            self.ipset.add("firefence-timeout", ip, etype="ip", timeout=60)
            self._save_ipset()
            logging.info(f"{ip} timed out for 60s")
            return f"{ip} timed out for 60s\n"
        except Exception as e:
            logging.error(f"Error timing out {ip}: {e}")
            return f"Error timing out {ip}: {e}\n"

    def see_lists(self):
        result = "\n--- Active IP Sets ---\n"
        for set_name, _, _ in self.sets_conf:
            try:
                content = next(self.ipset.list(set_name))
                members = content.get('members', [])
                ip_list = [m.get('value') for m in members] if members else ["Empty"]
                result += f"{set_name}: {', '.join(ip_list)}\n"
            except Exception as e:
                result += f"{set_name}: Error retrieving list ({e})\n"
        return result

filter = FilterService()
filter.run()