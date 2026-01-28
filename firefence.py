import psutil
import subprocess
import sys
import logging
import socket
import os
import time
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from Classes.Colors import Colors
from Classes.Service import Service

logging.basicConfig(
    filename='fireFence.log',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S'
)

class EngineCLI:
    def __init__(self):
        self.commands = {}
        self.service_data = {
            "sniffer": {"path": "Services/snifferService.py", "desc": "Network Sniffer"},
            "filter":  {"path": "Services/filterService.py",  "desc": "Traffic Filter"},
            "no-ddos": {"path": "Services/no-ddosService.py", "desc": "DDoS Protection"},
        }
        self.active_services = {}
        self.style = Style.from_dict({
            'bottom-bar': '#ffffff bg:#232627',
            'bottom-bar.cpu': '#00ff00',
            'bottom-bar.ram': '#00ff00',
            'bottom-bar.net': '#00ffff',
            'prompt': '#FDBC4B bold',
        })

    def command(self, name):
        """Decorator to register functions as CLI commands."""
        def decorator(func):
            self.commands[name] = func
            return func
        return decorator

    def get_bar_data(self):
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        net = psutil.net_io_counters()
        sent, recv = net.bytes_sent / 1024**2, net.bytes_recv / 1024**2
        return [
            ('', ' '),
            ('class:bottom-bar.cpu', f'CPU: {cpu}%'),
            ('', ' ┃ '),
            ('class:bottom-bar.ram', f'RAM: {ram}%'),
            ('', ' ┃ '),
            ('class:bottom-bar.net', f'NET: ↑{sent:.1f}MB ↓{recv:.1f}MB'),
            ('', ' ┃  Type "exit" to quit'),
        ]

    def check_services(self):
        to_delete = []

        for serv in self.active_services:
            if not self.active_services[serv].is_alive():
                to_delete.append(serv)
        for del_serv in to_delete:
            print(f"{Colors.BOLD}{Colors.WARNING}[!] {Colors.END}Service {Colors.BOLD}{Colors.BLUE}{del_serv}{Colors.END} has stopped unexpectedly.")
            logging.warning(f"Service {del_serv} has stopped unexpectedly.")
            self.active_services[del_serv].off()
            del self.active_services[del_serv]

    def run(self):
        cmd_completer = WordCompleter(list(self.commands.keys()), ignore_case=True)
        session = PromptSession(
            completer=cmd_completer,
            style=self.style,
            bottom_toolbar=self.get_bar_data,
            refresh_interval=0.5
        )

        self.commands['credits'](None)
        logging.info("CLI Session Started")

        while True:
            try:
                user_input = session.prompt('\nfirefence » ').strip()
                if not user_input:
                    continue

                logging.info(f"User Input: {user_input}")
                parts = user_input.split()
                cmd_name = parts[0].lower()
                args = parts[1:]

                if cmd_name in self.commands:
                    try:
                        self.commands[cmd_name](cmd_name, *args)
                    except TypeError as e:
                        print(f"{Colors.BOLD}{Colors.ERROR}[!!] Error:{Colors.END} {e}")
                        logging.error(f"Command Error: {e}")
                else:
                    print(f"{Colors.BOLD}{Colors.ERROR}[!!] {Colors.END}Unknown command: {Colors.BOLD}{Colors.BLUE}{cmd_name}{Colors.END}. Type {Colors.BOLD}{Colors.BLUE}help{Colors.END}.")
                    logging.warning(f"Unknown Command: {cmd_name}")
            except KeyboardInterrupt:
                print(f"{Colors.BOLD}{Colors.WARNING}[!] {Colors.END}Type {Colors.BOLD}{Colors.BLUE}exit{Colors.END} to quit.")
            except EOFError:
                print(f"{Colors.BOLD}{Colors.WARNING}[!] {Colors.END}Type {Colors.BOLD}{Colors.BLUE}exit{Colors.END} to quit.")
            # Note: Not fan about this, but if service crash while starting (ex: Start filter without starting sniffer) didn't found a better way to remove the thread.
            time.sleep(0.5) # Wait so the cmd can be executed properly
            self.check_services()
            continue

    def run_service_cmd(self, service, args):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(f"/tmp/{service}_control.sock")
                args_str = " ".join(args)
                s.sendall(f"{args_str}".encode())
                response = s.recv(1024).decode()
                if response:
                    print(f"{Colors.BOLD}{Colors.HEADER}[o]{Colors.END} {response}")
        except Exception as e:
            print(f"{Colors.BOLD}{Colors.ERROR}[!!] {Colors.END}{Colors.BOLD}{Colors.BLUE}{service}{Colors.END} is not running (socket not found).")

app = EngineCLI()

@app.command("sniffer")
@app.command("filter")
@app.command("no-ddos")
def service_handler(cmd, *args):
    service_data = app.service_data.get(cmd)
    ban_cmd = ['start', 'run', 'join', 'setDaemon']

    if not service_data:
        print(f"Unknown service: {cmd}")
        return

    if not args or args in ban_cmd:
        print(f"Usage: {cmd} [on|off|info|help]")
        return

    action = args[0].lower()

    if action == "on":
        if cmd in app.active_services:
            print(f"{Colors.BOLD}{Colors.WARNING}[!] {Colors.END}Service {Colors.BOLD}{Colors.BLUE}{cmd}{Colors.END} is already running.")
            return
        try:
            new_service = Service(cmd, service_data["path"])
            new_service.start()

            time.sleep(1)
            if new_service.is_alive():
                print(f"{Colors.BOLD}{Colors.GREEN}[+] {Colors.END}{Colors.BOLD}{Colors.BLUE}{cmd}{Colors.END} started")
                logging.info(f"{cmd} started")
                app.active_services[cmd] = new_service
            else:
                print(f"{Colors.BOLD}{Colors.ERROR}[-] {Colors.END}{Colors.BOLD}{Colors.BLUE}{cmd}{Colors.END} failed to start, did you start the sniffer ?")
                logging.error(f"{cmd} failed to start, did you start the sniffer ?")
            return
        except Exception as e:
            print(f"{Colors.BOLD}{Colors.ERROR}[!!] {Colors.END}Failed to start service {Colors.BOLD}{Colors.BLUE}{cmd}{Colors.END}: {e}")
            logging.error(f"Failed to start service {cmd}: {e}")
            return

    service = app.active_services.get(cmd)

    if not service:
        print(f"{Colors.BOLD}{Colors.WARNING}[!] {Colors.END}Service {Colors.BOLD}{Colors.BLUE}{cmd}{Colors.END} is not running.")
        return

    if hasattr(service, action):
        if action == "off":
            del app.active_services[cmd]
            print(f"{Colors.BOLD}{Colors.ERROR}[-] {Colors.END}{Colors.BOLD}{Colors.BLUE}{cmd}{Colors.END} stopped")
            logging.info(f"{cmd} stopped")
        method = getattr(service, action)
        result = method()
        if result:
            print(result)
    else:
        app.run_service_cmd(cmd, args)
    return

@app.command("services")
@app.command("status")
def services_status(args):
    print(f"\n\t{Colors.BOLD}{Colors.HEADER}━━━━━━━━━━ Services status ━━━━━━━━━━{Colors.END}\n\n")
    for name in app.service_data.keys():
        if name not in app.active_services:
            print(f"\t{name}{Colors.END}:{Colors.BOLD}{Colors.ERROR} Inactive{Colors.END}\n")
        else:
            print(f"\t{name}{Colors.END}:{Colors.BOLD}{Colors.GREEN} Active{Colors.END}\n")


@app.command("clear")
def clear_screen(args):
    subprocess.run("clear")

@app.command("logs")
def show_logs(args):
    lines = 20
    print(f"\n\t{Colors.BOLD}{Colors.HEADER}━━━━━ Showing last {lines} log entries ━━━━━{Colors.END}\n\n")
    subprocess.run(f"tail -n {lines} FireFence.log", shell=True)

@app.command("credits")
def show_credits(args=None):
    print(f"\n\n\t{Colors.BOLD}{Colors.TITLE}╔════════════════════════════════════╗\n"
                                      "\t║             FIREFENCE              ║\n"
      f"\t╚════════════════════════════════════╝{Colors.END}\n\n")
    print(f"\t{Colors.BOLD}{Colors.TITLE}Firefence{Colors.END} - a custom CLI SIEM engine made by Gxby\n")

@app.command("help")
def cmd_help(args=None):
    print(f"\n\t{Colors.BOLD}{Colors.HEADER}━━━━━ Commands ━━━━━{Colors.END}\n\n")
    for cmd in app.commands.keys():
        print(f"\t- {Colors.END}{Colors.BOLD}{Colors.BLUE}{cmd}{Colors.END}")

@app.command("exit")
@app.command("quit")
def cmd_exit(args=None):
    print(f"{Colors.BOLD}{Colors.BLUE}[:/] {Colors.END}Exiting...")
    for service in app.active_services.values():
        service.off()
    sys.exit(0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{Colors.BOLD}{Colors.ERROR}[!!] {Colors.END}This program must be run as root. Exiting.")
        sys.exit(1)
    app.run()