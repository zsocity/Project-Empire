import logging

from prompt_toolkit import HTML
from prompt_toolkit.completion import Completion

from empire.client.src.EmpireCliState import state
from empire.client.src.menus.Menu import Menu
from empire.client.src.utils import print_util, table_util
from empire.client.src.utils.autocomplete_util import (
    filtered_search_list,
    position_util,
)
from empire.client.src.utils.cli_util import command, register_cli_commands

log = logging.getLogger(__name__)


@register_cli_commands
class CredentialMenu(Menu):
    def __init__(self):
        super().__init__(display_name="credentials", selected="")

    def autocomplete(self):
        return self._cmd_registry + super().autocomplete()

    def get_completions(self, document, complete_event, cmd_line, word_before_cursor):
        if cmd_line[0] in ["remove"] and position_util(cmd_line, 2, word_before_cursor):
            for cred in filtered_search_list(
                word_before_cursor, state.credentials.keys()
            ):
                full = state.credentials[cred]
                help_text = print_util.truncate(
                    f"{full.get('username', '')}, {full.get('domain', '')}, {full.get('password', '')}",
                    width=75,
                )
                yield Completion(
                    cred,
                    display=HTML(f"{full['id']} <purple>({help_text})</purple>"),
                    start_position=-len(word_before_cursor),
                )
            yield Completion("all", start_position=-len(word_before_cursor))

        yield from super().get_completions(
            document, complete_event, cmd_line, word_before_cursor
        )

    def on_enter(self):
        state.get_credentials()
        self.list()
        return True

    @command
    def list(self) -> None:
        """
        Get running/available agents

        Usage: list
        """
        cred_list = []
        for cred in state.get_credentials().values():
            cred_list.append(
                [
                    str(cred["id"]),
                    cred["credtype"],
                    cred["domain"],
                    cred["username"],
                    cred["host"],
                    cred["password"][:50],
                    cred["sid"],
                    cred["os"],
                ]
            )

        cred_list.insert(
            0,
            [
                "ID",
                "CredType",
                "Domain",
                "UserName",
                "Host",
                "Password/Hash",
                "SID",
                "OS",
            ],
        )

        table_util.print_table(cred_list, "Credentials")

    @command
    def remove(self, cred_id: str) -> None:
        """
        Removes specified credential ID. if 'all' is provided, all credentials will be removed.

        Usage: remove <cred_id>
        """
        if cred_id == "all":
            choice = input(
                print_util.color(
                    "[>] Are you sure you want to remove all credentials? [y/N] ",
                    "red",
                )
            )
            if choice.lower() == "y":
                for key in state.credentials:
                    self.remove_credential(key)
        else:
            self.remove_credential(cred_id)

        state.get_credentials()

    @staticmethod
    def remove_credential(cred_id: str):
        response = state.remove_credential(cred_id)
        if response.status_code == 204:
            log.info("Credential " + cred_id + " removed")
        elif "detail" in response:
            log.error(response["detail"])


credential_menu = CredentialMenu()
