from ..Servicev2 import BaseService
from ..Logging import log, logging

import re

class WebIDS(BaseService):
    def _setup(self):
        self.threshold = int(self.config.get("threshold", 5))
        self.timeout = int(self.config.get("timeout", 3600))
        self.paths = self.config.get("paths", [])
        self.regex = self.config.get("regex", [])

    def _process(self, logline):
        for pattern in self.regex:
            match = re.search(pattern, logline)
            if match:
                try:
                    ip_address = match.group('ip')
                    log(f"<warning>[{self.name}] Match found for IP {ip_address}: {logline[:50]}...</warning>")
                except IndexError:
                    log(f"<warning>[{self.name}] Match found but no 'ip' group in regex: {pattern}</warning>")
                break