
import os
import sys
import psutil
import tomllib

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout

from Classes.Engine import PktSnifferEngine, LogSnifferEngine
from Classes.Firewall import Firewall
from Classes.Logging import logging, log, log_setup, style

# TODO del for prod
import traceback

ENGINES = {
    "pkt-sniffer": PktSnifferEngine,
    "log-sniffer": LogSnifferEngine
}

class CliEngine():
    commands = {}

    def __init__(self, config):
        self.running = True
        self.config = config
        self.active_engine = {}
        self.firewall = Firewall(self.config["firewall"])

        for engine in self.config["engines"]:
            if engine not in ENGINES:
                log(f"<warning>[!] {engine} is register into the config but not into CliEngine __init__</warning>", log=logging.WARNING)

    @classmethod
    def command(cls, name):
        def decorator(func):
            cls.commands[name] = func
            return func
        return decorator

    def get_bar_data(self):
        self.check_health_services()

        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        net = psutil.net_io_counters()
        sent, recv = net.bytes_sent / 1024**2, net.bytes_recv / 1024**2
        return [
            ('class:bold', f' CPU {cpu:>4}% '),
            ('class:bottom-bar.divider', '┃'),
            ('class:bold', f' RAM {ram:>4}% '),
            ('class:bottom-bar.divider', '┃'),
            ('class:bold', f' ↑ {sent:>.1f}MB ↓ {recv:>.1f}MB '),
            ('class:bottom-bar.divider', '┃'),
            ('', ' Type "exit" to quit '),
        ]

    def process_input(self, input):
        cmd_parts = input.split()
        if cmd_parts[0] == "exit":
            self.running = False

        if cmd_parts[0] in self.commands:
            try:
                self.commands[cmd_parts[0]](self, cmd_parts[0], cmd_parts[1:])
            except TypeError as e:
                # TODO revert to e instead of detailled for prod
                error_details = traceback.format_exc()
                log(f"<error>[#] Command error: {error_details}</error>", log=logging.ERROR)
        else:
            log(f"<warning>[!] Unknown command: {cmd_parts[0]}</warning>")

    def check_health_services(self):
        for service_name in list(self.active_engine):
            instance = self.active_engine[service_name]
            if not instance.running:
                log(f"<error>[!] Service {service_name} has stopped unexpectedly.</error>", log=logging.WARNING)
                del self.active_engine[service_name]

    def start(self):
        cmd_completer = WordCompleter(list(self.commands), ignore_case=True)
        session = PromptSession(
            completer=cmd_completer,
            style=style,
            bottom_toolbar=self.get_bar_data,
            refresh_interval=0.5
        )

        log("<info>Firefence started</info>", logging.INFO)

        with patch_stdout():
            while self.running:
                try:
                    input = session.prompt('\nfirefence » ').strip()
                    if not input:
                        continue
                    self.process_input(input)
                except KeyboardInterrupt:
                    log(f"<warning>[!] Type exit to quit.</warning>")
                except EOFError:
                    log(f"<warning>[!] Type exit to quit.</warning>")
            self.stop()

    def stop(self):
        for engine_name, inst in self.active_engine.items():
            inst._stop()
        self.active_engine.clear()
        log("<info>[-] Shutting down Firefence.. bye</info>", log=logging.INFO)


@CliEngine.command("exit")
def cmd_exit(self, cmd, args):
    self.running = False

@CliEngine.command("start")
@CliEngine.command("on")
def cmd_start(self, cmd, args):
    if not args or len(args) != 1:
        log(f"<warning>[!] Invalid args for {cmd}</warning>")
        return

    engine_name, _, subservice_name = args[0].partition(".")

    if engine_name not in ENGINES:
        log(f"<warning>[!] Engine {engine_name} does not exist</warning>")
        return

    if subservice_name:
        engine = self.active_engine.get(engine_name)
        if not engine or subservice_name not in engine._get_services():
            log(f"<warning>[!] Subservice {subservice_name} does not exist in engine {engine_name} or engine not started.</warning>")
            return
        self.active_engine[engine_name]._add_service(subservice_name)
        return
    elif engine_name not in self.active_engine:
        instance = ENGINES[engine_name](self.config["engines"].get(engine_name), self.firewall)
        self.active_engine[engine_name] = instance
        instance._start()
    else:
        log(f"<warning>[!] Engine {engine_name} is already started.</warning>")

@CliEngine.command("stop")
@CliEngine.command("off")
def cmd_stop(self, cmd, args):
    if not args or len(args) != 1:
        log(f"<warning>[!] Invalid args for {cmd}</warning>")
        return

    engine_name, _, subservice_name = args[0].partition(".")

    if engine_name not in ENGINES or engine_name not in self.active_engine:
        log(f"<warning>[!] Engine {engine_name} does not exist or is already stopped.</warning>")
        return

    if subservice_name:
        engine = self.active_engine.get(engine_name)
        if not engine or subservice_name not in engine._get_services():
            log(f"<warning>[!] Subservice {subservice_name} does not exist in engine {engine_name}.</warning>")
            return
        self.active_engine[engine_name]._stop_service(subservice_name)
    else:
        self.active_engine[engine_name]._stop()
        del self.active_engine[engine_name]

@CliEngine.command("status")
@CliEngine.command("info")
def cmd_status(self, cmd, args):
    if not args or len(args) == 0:
        for engine_name in ENGINES:
            if engine_name in self.active_engine:
                engine_status = self.active_engine[engine_name]._get_status()
                tag = "ok" if engine_status['status'] == "active" else "error"
                log(f"<info>Engine: {engine_status['engine_name']} - Status: <bold><{tag}>{engine_status['status']}</{tag}></bold>\n" +
                    f" Services:\n\t" + "\n\t".join([
                    f"{name}: <bold><{ 'ok' if status == 'active' else 'error' }>{status}</{ 'ok' if status == 'active' else 'error' }></bold>"
                    for name, status in engine_status["services"].items()
                ])+ "</info>\n")
            else:
                log(f"<info>Engine: {engine_name} - Status: <bold><error>inactive</error></bold></info>")
        return

@CliEngine.command("run")
@CliEngine.command("do")
def cmd_run(self, cmd, args):
    if not args or len(args) < 2:
        log(f"<warning>[!] Invalid args for {cmd}</warning>")
        return

    engine_name, _, subservice_name = args[0].partition(".")

    if engine_name not in ENGINES or engine_name not in self.active_engine:
        log(f"<warning>[!] Engine {engine_name} is not running or doesn't exists.</warning>")
        return

    engine = self.active_engine.get(engine_name)
    if subservice_name:
        engine._cmd_callback(subservice_name, args[1], args[2:])
    else:
        engine._cmd_callback(engine_name, args[1], args[2:])

@CliEngine.command("list")
@CliEngine.command("firewall")
def cmd_list(self, cmd, args):
    if args:
        log(f"<warning>[!] Invalid args for {cmd}</warning>")

    result = self.firewall.see_lists()
    log(f"<info>{result}</info>")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"\033[91m[!] This program must be run as root. Exiting.\033[0m")
        sys.exit(1)

    log_setup()
    try:
        with open('config.toml', 'rb') as f:
            config = tomllib.load(f)
    except Exception as e:
        log(f"<error>[!] Failed to load config.toml: {e}</error>", log=logging.ERROR)
        sys.exit(1)

    cli_engine = CliEngine(config)
    cli_engine.start()
