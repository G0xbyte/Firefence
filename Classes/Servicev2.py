from .Logging import log

class BaseService:
    def __init__(self, config, firewall):
        self.config = config
        self.firewall = firewall
        self.name = config['name']
        self.running = False

    def _get_status(self):
        return self.running

    def _stop(self):
        log(f"<info>[{self.name}] Stopping..</info>")
        self.running = False

    def _start(self):
        log(f"<info>[{self.name}] Starting..</info>")
        self._setup()
        self.running = True

    def _process(self, data):
        raise NotImplementedError("Setup method must be implemented by subclasses.")

    def _setup(self):
        raise NotImplementedError("Setup method must be implemented by subclasses.")


