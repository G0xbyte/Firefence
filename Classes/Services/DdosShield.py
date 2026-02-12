from ..Servicev2 import BaseService
from ..Logging import log

import redis

class DdosShield(BaseService):
    def _setup(self):
        self.threshold = self.config["threshold"]
        self.timeout = self.config["timeout"]
        self.sniff_window = self.config["window"]
        self.dbindex = self.config["db_index"]

        self.redis = redis.Redis(host='localhost', port=6379, db=27, decode_responses=True)


    def _process(self, pkt):
        src_ip = pkt.dst

        if self.redis.exists(f"blocked:{src_ip}"):
            return

        current_count = self.redis.incr(src_ip)

        if current_count == 1:
            self.redis.expire(src_ip, self.sniff_window)
            log(f"<info>[DDOS] Monitoring new IP: {src_ip}<info>")

        if current_count > self.threshold:
            self.firewall.set_timeout(src_ip, self.timeout)
            self.redis.setex(f"blocked:{src_ip}", self.timeout, "true")
            return
        return True