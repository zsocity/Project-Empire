import csv
import io

from empire.server.common.empire import MainMenu
from empire.server.common.plugins import Plugin
from empire.server.core.db import models
from empire.server.core.db.models import PluginTaskStatus
from empire.server.core.plugin_service import PluginService


class Plugin(Plugin):
    def onLoad(self):
        self.info = {
            "Name": "basic_reporting",
            "Authors": [
                {
                    "Name": "Vincent Rose",
                    "Handle": "@vinnybod",
                    "Link": "https://github.com/vinnybod",
                }
            ],
            "Description": "Generates credentials.csv, sessions.csv, and master.log. Writes to server/data directory.",
            "Software": "",
            "Techniques": [],
            "Comments": [],
        }

        self.options = {
            "report": {
                "Description": "Reports to generate.",
                "Required": True,
                "Value": "all",
                "SuggestedValues": ["session", "credential", "log", "all"],
                "Strict": True,
            }
        }
        self.install_path = ""

    def execute(self, command, **kwargs):
        """
        Parses commands from the API
        """
        user = kwargs["user"]
        db = kwargs["db"]
        input = f'Generating reports for: {command["report"]}'
        plugin_task = models.PluginTask(
            plugin_id=self.info["Name"],
            input=input,
            input_full=input,
            user_id=user.id,
            status=PluginTaskStatus.completed,
        )
        output = ""
        db_downloads = []

        report = command["report"]
        if report in ["session", "all"]:
            db_download = self.session_report(db, user)
            db_downloads.append(db_download)
            output += f"[*] Session report generated to {db_download.location}\n"
        if report in ["credential", "all"]:
            db_download = self.credential_report(db, user)
            db_downloads.append(db_download)
            output += f"[*] Credential report generated to {db_download.location}\n"
        if report in ["log", "all"]:
            db_download = self.generate_report(db, user)
            db_downloads.append(db_download)
            output += f"[*] Log report generated to {db_download.location}\n"

        output += "[*] Execution complete.\n"
        plugin_task.output = output
        plugin_task.downloads = db_downloads
        db.add(plugin_task)
        db.flush()

    def register(self, mainMenu: MainMenu):
        """
        Any modifications to the mainMenu go here - e.g.
        registering functions to be run by user commands
        """
        self.install_path = mainMenu.installPath
        self.main_menu = mainMenu
        self.plugin_service: PluginService = mainMenu.pluginsv2

    def session_report(self, db, user):
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["SessionID", "Hostname", "User Name", "First Check-in"])
        for row in db.query(models.Agent).all():
            writer.writerow(
                [row.session_id, row.hostname, row.username, row.firstseen_time]
            )

        output_str = out.getvalue()
        return self.main_menu.downloadsv2.create_download_from_text(
            db, user, output_str, "sessions.csv", "basic_reporting"
        )

    def credential_report(self, db, user):
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["Domain", "Username", "Host", "Cred Type", "Password"])
        for row in db.query(models.Credential).all():
            writer.writerow(
                [row.domain, row.username, row.host, row.credtype, row.password]
            )

        output_str = out.getvalue()
        return self.main_menu.downloadsv2.create_download_from_text(
            db, user, output_str, "credentials.csv", "basic_reporting"
        )

    def generate_report(self, db, user):
        out = io.StringIO()
        out.write("Empire Master Taskings & Results Log by timestamp\n")
        out.write("=" * 50 + "\n\n")
        for row in db.query(models.AgentTask).all():
            row: models.AgentTask
            username = row.user.username if row.user else "None"
            out.write(
                f"\n{xstr(row.created_at)} - {xstr(row.id)} ({xstr(row.agent_id)})> "
                f"{xstr(username)}\n {xstr(row.input)}\n {xstr(row.output)}\n"
            )

        output_str = out.getvalue()
        return self.main_menu.downloadsv2.create_download_from_text(
            db, user, output_str, "master.log", "basic_reporting"
        )

    def shutdown(self):
        """
        Kills additional processes that were spawned
        """
        # If the plugin spawns a process provide a shutdown method for when Empire exits else leave it as pass
        pass


def xstr(s):
    """
    Safely cast to a string with a handler for None
    """
    if s is None:
        return ""
    if isinstance(s, bytes):
        return s.decode("utf-8")
    return str(s)
