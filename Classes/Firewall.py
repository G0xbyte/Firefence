from .Logging import logging, log
import socket
import iptc
from pyroute2 import IPSet
import errno

class Firewall():
    def __init__(self, config):
        self.config = config
        self.name = self.config['name']
        self.ipset = IPSet()
        self.table = iptc.Table(iptc.Table.FILTER)
        self.lists = {}

        for list in self.config["lists"]:
            self.lists[list['name']] = list

        self._setup_rules()

    def _setup_rules(self):
        for set_name, data in self.lists.items():
            chains = data['chains']
            action = data['action']
            timeout = data['timeout']

            try:
                self.ipset.create(set_name, stype="hash:ip", family=socket.AF_INET, timeout=timeout)

                for chain_name in chains:
                    match_type = "src" if chain_name == "INPUT" else "dst"
                    chain = iptc.Chain(self.table, chain_name)
                    rule = iptc.Rule()
                    match = rule.create_match("set")
                    match.match_set = [set_name, match_type]
                    rule.target = iptc.Target(rule, action)
                    if rule not in chain.rules:
                        chain.insert_rule(rule)
            except Exception as e:
                if isinstance(e.args, tuple) and e.args[0] == errno.EEXIST:
                    return
                log(f"<warning>[Firewall] Kernel setup warning: {e}</warning>")

    def ban_ip(self, ip):
        if self.ipset.test("firefence-whitelist", ip, etype="ip"):
            log(f"<warning>[Firewall] Attempted to timeout whitelisted IP {ip}, action ignored.</warning>")

        try:
            self.ipset.add("firefence-blacklist", ip, etype="ip")
            log(f"<info>[Firewall] {ip} added to blacklist</info>", logging.INFO)
        except Exception as e:
            log(f"<error>[Firewall] Error banning {ip}: {e}</error>")

    def unban_ip(self, ip):
        try:
            self.ipset.delete("firefence-blacklist", ip, etype="ip")
            log(f"<info>[Firewall] {ip} removed from blacklist</info>", logging.INFO)
        except Exception as e:
            log(f"<error>[Firewall] Error unbanning {ip}: {e}</error>")

    def whitelist_ip(self, ip):
        try:
            self.ipset.add("firefence-whitelist", ip, etype="ip")
            log(f"<info>[Firewall] {ip} added to Whitelist</info>", logging.INFO)
        except Exception as e:
            log(f"<error>[Firewall] Error whitelisting {ip}: {e}</error>")

    def unwhitelist_ip(self, ip):
        try:
            self.ipset.delete("firefence-whitelist", ip, etype="ip")
            log(f"<info>[Firewall] {ip} removed from Whitelist</info>", logging.INFO)
        except Exception as e:
            log(f"<error>[Firewall] Error removing {ip} from whitelist: {e}</error>")

    def set_timeout(self, ip, time):
        if self.ipset.test("firefence-whitelist", ip, etype="ip"):
            log(f"<warning>[Firewall] Attempted to timeout whitelisted IP {ip}, action ignored.</warning>")

        try:
            self.ipset.add("firefence-timeout", ip, etype="ip", timeout=time)
            log(f"<info>[Firewall] {ip} timed out for {time}</info>", logging.INFO)
        except Exception as e:
            log(f"<error>[Firewall] Error timing out {ip}: {e}</error>")

    def see_lists(self):
        log(f"<warning>[Firewall] DEBUG lists: {self.lists}</warning>")
        result = "<info>"
        for set_name, data in self.lists.items():
            chains = data['chains']
            action = data['action']
            timeout = data['timeout']

            result += f"{set_name} (Action: {action}, Timeout: {timeout}s) - Chains: {', '.join(chains)}\n"
            try:
                content = next(self.ipset.list(set_name))
                members = content.get('members', [])
                ip_list = [m.get('value') for m in members] if members else ["Empty"]
                result += f"{set_name}: {', '.join(ip_list)}\n"
            except Exception as e:
                result += f"{set_name}: Error retrieving list ({e})\n"
        log(result + "</info>")