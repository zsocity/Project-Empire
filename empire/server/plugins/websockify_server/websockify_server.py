import contextlib
import logging

import websockify

from empire.server.common import helpers
from empire.server.common.plugins import Plugin
from empire.server.core.plugin_service import PluginService

log = logging.getLogger(__name__)


class Plugin(Plugin):
    def onLoad(self):
        self.main_menu = None
        self.csharpserver_proc = None
        self.info = {
            "Name": "websockify_server",
            "Authors": [
                {
                    "Name": "Anthony Rose",
                    "Handle": "@Cx01N",
                    "Link": "https://twitter.com/Cx01N_",
                }
            ],
            "Description": (
                "Websockify server for TCP proxy/bridge to connect applications. For example: "
                "run the websockify server to connect the VNC server to noVNC."
            ),
            "Software": "",
            "Techniques": ["T1090"],
            "Comments": ["https://github.com/novnc/websockify"],
        }

        self.options = {
            "SourceHost": {
                "Description": "Address of the source host.",
                "Required": True,
                "Value": "0.0.0.0",
            },
            "SourcePort": {
                "Description": "Port on source host.",
                "Required": True,
                "Value": "5910",
            },
            "TargetHost": {
                "Description": "Address of the target host.",
                "Required": True,
                "Value": "",
            },
            "TargetPort": {
                "Description": "Port on target host.",
                "Required": True,
                "Value": "5900",
            },
            "Status": {
                "Description": "Start/stop the Empire C# server.",
                "Required": True,
                "Value": "start",
                "SuggestedValues": ["start", "stop"],
                "Strict": True,
            },
        }

    def execute(self, command):
        # This is for parsing commands through the api
        try:
            self.websockify_proc = None
            # essentially switches to parse the proper command to execute
            self.status = command["Status"]
            return self.do_websockify(command)
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

    def do_websockify(self, command):
        """
        Check if the Empire C# server is already running.
        """
        if self.websockify_proc:
            self.enabled = True
        else:
            self.enabled = False

        if self.status == "status":
            if self.enabled:
                return "[+] Websockify server is currently running"
            return "[!] Websockify server is currently stopped"

        if self.status == "stop":
            if self.enabled:
                self.shutdown()
                return "[!] Stopped Websockify server"
            return "[!] Websockify server is already stopped"

        if self.status == "start":
            source_host = command["SourceHost"]
            source_port = int(command["SourcePort"])
            target_host = command["TargetHost"]
            target_port = int(command["TargetPort"])

            server = websockify.LibProxyServer(
                target_host=target_host,
                target_port=target_port,
                listen_host=source_host,
                listen_port=source_port,
            )

            self.websockify_proc = helpers.KThread(target=server.serve_forever)
            self.websockify_proc.daemon = True
            self.websockify_proc.start()
            return "[+] Websockify server successfully started"
        return None

    def shutdown(self):
        with contextlib.suppress(Exception):
            self.websockify_proc.kill()
