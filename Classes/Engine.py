from scapy.all import IP, DNS, TCP, Raw
from scapy.layers.http import HTTPRequest, HTTP
from scapy.utils import PcapWriter

from netfilterqueue import NetfilterQueue
from datetime import datetime
import subprocess
import threading
import socket

from Classes.Logging import log, logging
from Classes.Services.DataLossPrevention import DataLossPrevention
from Classes.Services.DdosShield import DdosShield

SERVICES = {
    "ddos-shield": DdosShield,
    "dlp": DataLossPrevention,
    "fail2ban": None,
    "webids": None,
}

class SnifferEngine():
    def __init__(self, config, firewall):
        self.config = config
        self.firewall = firewall
        self.name = config['name']
        self.id = config['id']
        self.services = {}
        self.active_services = {}
        self.running = False
        self.thread = None

        for service in config["services"]:
            if service['id'] not in SERVICES:
                log(f"<warning>[{self.name}] Service {service['id']} not found in engine</warning>")
                continue
            self.services[service['id']] = SERVICES[service['id']]
        self._setup()

    def _setup(self):
        raise NotImplementedError("Setup method must be implemented by subclasses.")

    def _add_service(self, service_name):
        if service_name not in self.services or service_name in self.active_services:
            log(f"<warning>[{self.name}] Service {service_name} does not exist or is already active in engine.</warning>")
            return False

        service_cfg = next((service for service in self.config["services"] if service["id"] == service_name), None)
        instance = self.services[service_name](service_cfg, self.firewall)

        try:
            instance._start()
            self.active_services[service_name] = instance
            log(f"<ok>[{self.name}] Service {service_name} started in engine.</ok>", log=logging.INFO)
            return True
        except Exception as e:
            log(f"<error>[{self.name}] Failed to start service {service_name}: {e}</error>")
            return False

    def _stop_service(self, service_name):
        if service_name not in self.services or service_name not in self.active_services:
            log(f"<warning>[{self.name}] Service {service_name} does not exist or is not active in engine.</warning>")
            return False
        instance = self.active_services[service_name]
        try:
            instance._stop()
            del self.active_services[service_name]
            log(f"<error>[{self.name}] Stopped {service_name} from engine.</error>", log=logging.INFO)
            return True
        except Exception as e:
            log(f"<error>[{self.name}] Failed to stop service {service_name} in engine: {e}</error>")
            return False

    def _get_services(self):
        result = []
        for name in self.services:
            result.append(name)
        return result

    def _get_status(self):
        result = {
            "engine_name": f"{self.name}",
            "status": "active" if self.running else "inactive",
            "services": {}
            }
        for service_name in self.services:
            if service_name in self.active_services:
                result["services"][service_name] = "active"
            else:
                result["services"][service_name] = "inactive"
        return result

    def _start(self):
        self.running = True
        log(f"<ok>[{self.name}] Started</ok>", log=logging.INFO)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        raise NotImplementedError(f"[{self.name}] Start method must be implemented by subclasses.")

    def _stop(self):
        self.running = False
        service_names = list(self.active_services.keys())

        for name in service_names:
            self._stop_service(name)
        self.active_services.clear()

        try:
            if self.thread:
                self.thread.join(timeout=2.0)
        except Exception as e:
            pass
        log(f"<error>[{self.name}] Stopped</error>", log=logging.INFO)

    def _packet_callback(self, pkt):
        raise NotImplementedError("Packet callback must be implemented by subclasses.")

    def _cmd_callback(self, target, cmd, args):
        if target == self.id:
            if not hasattr(self, cmd):
                log(f"<warning>[{self.name}] {cmd} doesn't exists.</warning>")
                return
            method = getattr(self, cmd)
            method(args)
            return
        if target in self.active_services:
            inst = self.active_services[target]
            if not inst or not hasattr(inst, cmd):
                log(f"<warning>[{self.name}] {cmd} doesn't exists.</warning>")
                return
            method = getattr(inst, cmd)
            method(args)
            return
        log(f"<warning>[[{self.name}] doesn't exists or is not running.</warning>")
        return

class PktSnifferEngine(SnifferEngine):
    def _setup(self):
        self.chains = ["INPUT", "OUTPUT"]
        self.queue_num = self.config["queue_nb"]
        self.nfqueue = NetfilterQueue()
        self.do_log = False

        # self.methods = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS")

        start_time = datetime.now().strftime('%d-%m-%y-%H:%M:%S')
        self.cap_file = self.config["capture_file_name"] + f"{start_time}" + ".pcap"
        self.pkt_w = None

        self.ipt_add_rules()

    def ipt_rm_rules(self):
        for chain in self.chains:
            while True:
                result = subprocess.run(["sudo", "iptables", "-D", chain, "-j", "NFQUEUE", "--queue-num", str(self.queue_num)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode != 0:
                    break

    def ipt_add_rules(self):
        for chain in self.chains:
            check = subprocess.run(["sudo", "iptables", "-C", chain, "-j", "NFQUEUE", "--queue-num", str(self.queue_num)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if check.returncode != 0:
                subprocess.run(["sudo", "iptables", "-I", chain, "-j", "NFQUEUE", "--queue-num", str(self.queue_num)], check=True)

    def _packet_callback(self, nf_packet):
        pkt = IP(nf_packet.get_payload())

        should_drop = False


        if pkt.haslayer(TCP) and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
            nf_packet.accept()
            return

        print(f"DEBUG: {pkt.summary()}")

        if self.do_log:
            self.pkt_w.write(bytes(pkt))

        debug = False

        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            print(f"DNS detected")
            debug = True
        elif pkt.haslayer(HTTPRequest):
            print(f"HTTP Request detected: {pkt[HTTPRequest].Method}")
            debug = True

        print(f"DEBUG: {debug}")
        if debug:
            for _, inst in self.active_services.items():
                if not inst._process(pkt):
                    should_drop = True
                    break

        if should_drop:
            log(f"<info>[{self.name}] Pkt drop: {pkt.src} {pkt.dst}</info>")
            nf_packet.drop()
        else:
            nf_packet.accept()

    def _run(self):
        self.nfqueue.bind(self.queue_num, self._packet_callback)

        fd = self.nfqueue.get_fd()
        sock = socket.fromfd(fd, socket.AF_NETLINK, socket.SOCK_RAW)
        sock.settimeout(1.0)

        try:
            while self.running:
                try:
                    self.nfqueue.run()
                except socket.timeout:
                    continue
        except Exception as e:
            import traceback
            error_details = traceback.extract_stack()
            log(f"<error>[PKTSNIFF] {self.name} encountered an error: {error_details}</error>", log=logging.ERROR)
            self._stop()
        finally:
            if self.pkt_w:
                self.pkt_w.close()
            self.ipt_rm_rules()
            self.nfqueue.unbind()
            sock.close()

    def log(self, args):
        if args[0] == "true" or args[0] == "on":
            if not self.pkt_w:
                self.pkt_w = PcapWriter(self.cap_file, sync=True, linktype=101)
            log(f"<info>[PKTSNIFF] Logging on ({self.cap_file})</info>")
            self.do_log = True
            return
        if args[0] == "false" or args[0] == "off":
            log(f"<info>[PKTSNIFF] Logging off</info>")
            self.do_log = False
            return
        log(f"<warning>[PKTSNIFF] Invalid logging status: {args[0]}\n\tOptions: true / on | false / off</warning>")

class LogSnifferEngine(SnifferEngine):
    def _setup(self):
        pass

    def _run(self):
        print(f"[LOGSNIFF] Starting..")
