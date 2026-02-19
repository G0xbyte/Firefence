from ..Servicev2 import BaseService
from ..Logging import log, logging

import redis

import traceback

class DdosShield(BaseService):
    def _setup(self):
        self.threshold = self.config["threshold"]
        self.timeout = self.config["timeout"]
        self.sniff_window = self.config["window"]
        self.dbindex = self.config["db_index"]
        self.dbport = self.config["db_port"]
        self.host = self.config["host"]

        self.redis = redis.Redis(host=self.host, port=self.dbport, db=self.dbindex, decode_responses=True)

    def _process(self, pkt):
        src_ip = pkt.dst

        log(f"<info>[DDOS] analyzing {src_ip} -> {pkt.dst}: {pkt.summary()}</info>")
        try:
            if self.redis.exists(f"blocked:{src_ip}"):
                return False

            current_count = self.redis.incr(src_ip)

            if current_count == 1:
                self.redis.expire(src_ip, self.sniff_window)
                log(f"<info>[DDOS] Monitoring new IP: {src_ip}</info>")

            if current_count > self.threshold:
                self.firewall.set_timeout(src_ip, self.timeout)
                self.redis.setex(f"blocked:{src_ip}", self.timeout, "true")
                log(f"<warning>[DDOS] IP {src_ip} blocked for {self.timeout} seconds (count: {current_count})</warning>")
                return False
            return True
        except Exception as e:
            error_details = traceback.format_exc()
            log(f"<error>[DDOS] Error processing IP {src_ip}: {error_details}</error>", log=logging.ERROR)
            return True
