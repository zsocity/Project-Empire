from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.utils.module_util import handle_error_message


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ):
        script_path = params["ScriptPath"]
        script_cmd = params["ScriptCmd"]
        script = ""

        if script_path != "":
            try:
                with open(f"{script_path}") as data:
                    script = data.read()
            except Exception:
                return handle_error_message(
                    "[!] Could not read script source path at: " + str(script_path)
                )

            script += "\n"

        script += f"{script_cmd}"

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end="",
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
