import base64
import fnmatch
import importlib.util
import logging
import os
import warnings
from pathlib import Path

import yaml
from packaging.version import parse
from sqlalchemy.orm import Session

from empire.server.api.v2.module.module_dto import (
    ModuleBulkUpdateRequest,
    ModuleUpdateRequest,
)
from empire.server.common import helpers
from empire.server.common.converter.load_covenant import _convert_covenant_to_empire
from empire.server.core.config import empire_config
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.core.download_service import DownloadService
from empire.server.core.exceptions import (
    ModuleExecutionException,
    ModuleValidationException,
)
from empire.server.core.module_models import EmpireModule, LanguageEnum
from empire.server.core.obfuscation_service import ObfuscationService
from empire.server.utils.option_util import convert_module_options, validate_options

log = logging.getLogger(__name__)


class ModuleService:
    def __init__(self, main_menu):
        self.main_menu = main_menu
        self.obfuscation_service: ObfuscationService = main_menu.obfuscationv2
        self.download_service: DownloadService = main_menu.downloadsv2

        self.modules = {}

        with SessionLocal.begin() as db:
            self.load_modules(db)

    def get_all(self):
        return self.modules

    def get_by_id(self, uid: str):
        return self.modules.get(uid)

    def update_module(
        self, db: Session, module: EmpireModule, module_req: ModuleUpdateRequest
    ):
        db_module: models.Module = (
            db.query(models.Module).filter(models.Module.id == module.id).first()
        )
        db_module.enabled = module_req.enabled

        self.modules.get(module.id).enabled = module_req.enabled

    def update_modules(self, db: Session, module_req: ModuleBulkUpdateRequest):
        db_modules: list[models.Module] = (
            db.query(models.Module)
            .filter(models.Module.id.in_(module_req.modules))
            .all()
        )

        for db_module in db_modules:
            db_module.enabled = module_req.enabled

        for db_module in db_modules:
            self.modules.get(db_module.id).enabled = module_req.enabled

    def execute_module(  # noqa: PLR0913 PLR0912 PLR0915
        self,
        db: Session,
        agent: models.Agent,
        module_id: str,
        params: dict,
        ignore_language_version_check: bool = False,
        ignore_admin_check: bool = False,
        modified_input: str | None = None,
    ) -> tuple[dict | None, str | None]:
        """
        Execute the module. Note this doesn't actually add the task to the queue,
        it only generates the module data needed for a task to be created.
        :param module_id: str
        :param params: the execution parameters
        :param user_id: the user executing the module
        :return: tuple with the response and an error message (if applicable)
        """
        module = self.get_by_id(module_id)

        if not module:
            return None, f"Module not found for id {module_id}"
        if not module.enabled:
            return None, "Cannot execute disabled module"

        if modified_input:
            module = self._create_modified_module(module, modified_input)

        cleaned_options, err = self._validate_module_params(
            db, module, agent, params, ignore_language_version_check, ignore_admin_check
        )

        if err:
            raise ModuleValidationException(err)

        module_data = self._generate_script(
            db,
            module,
            cleaned_options,
        )
        if isinstance(module_data, tuple):
            warnings.warn(
                "Returning a tuple on errors from module generation is deprecated. Raise exceptions instead."
                "https://bc-security.gitbook.io/empire-wiki/module-development/powershell-modules#custom-generate",
                DeprecationWarning,
                stacklevel=5,
            )
            (module_data, err) = module_data
        else:
            # Not all modules return a tuple. If they just return a single value,
            # we don't want to throw an unpacking error.
            err = None
        if not module_data or module_data == "":
            # This should probably be a ModuleExecutionException, but
            # for backwards compatability with 5.x, it needs to raise a 400
            raise ModuleValidationException(err or "module produced an empty script")
        if not module_data.isascii():
            # This previously returned 'None, 'module source contains non-ascii characters'
            # Was changed in 4.3 to print a warning.
            log.warning(f"Module source for {module_id} contains non-ascii characters")

        if module.language == LanguageEnum.powershell:
            module_data = helpers.strip_powershell_comments(module_data)

        if module.language == LanguageEnum.python:
            module_data = helpers.strip_python_comments(module_data)

        task_command = ""
        if agent.language != "ironpython" or (
            agent.language == "ironpython" and module.language == "python"
        ):
            if module.language == LanguageEnum.csharp:
                task_command = "TASK_CSHARP"
            # build the appropriate task command and module data blob
            elif module.background:
                # if this module should be run in the background
                extension = module.output_extension
                if extension and extension != "":
                    # if this module needs to save its file output to the server
                    #   format- [15 chars of prefix][5 chars extension][data]
                    save_file_prefix = module.name.split("/")[-1]
                    module_data = (
                        save_file_prefix.rjust(15) + extension.rjust(5) + module_data
                    )
                    task_command = "TASK_CMD_JOB_SAVE"
                else:
                    task_command = "TASK_CMD_JOB"
            elif module.language == LanguageEnum.bof:
                task_command = "TASK_CSHARP"
            else:
                # if this module is run in the foreground
                extension = module.output_extension
                if module.output_extension and module.output_extension != "":
                    # if this module needs to save its file output to the server
                    #   format- [15 chars of prefix][5 chars extension][data]
                    save_file_prefix = module.name.split("/")[-1][:15]
                    module_data = (
                        save_file_prefix.rjust(15) + extension.rjust(5) + module_data
                    )
                    task_command = "TASK_CMD_WAIT_SAVE"
                else:
                    task_command = "TASK_CMD_WAIT"

        elif agent.language == "ironpython" and module.language == "powershell":
            if module.background:
                # if this module should be run in the background
                extension = module.output_extension
                if extension and extension != "":
                    # if this module needs to save its file output to the server
                    #   format- [15 chars of prefix][5 chars extension][data]
                    save_file_prefix = module.name.split("/")[-1]
                    module_data = (
                        save_file_prefix.rjust(15) + extension.rjust(5) + module_data
                    )
                    task_command = "TASK_POWERSHELL_CMD_JOB_SAVE"
                else:
                    task_command = "TASK_POWERSHELL_CMD_JOB"

            else:
                # if this module is run in the foreground
                extension = module.output_extension
                if module.output_extension and module.output_extension != "":
                    # if this module needs to save its file output to the server
                    #   format- [15 chars of prefix][5 chars extension][data]
                    save_file_prefix = module.name.split("/")[-1][:15]
                    module_data = (
                        save_file_prefix.rjust(15) + extension.rjust(5) + module_data
                    )
                    task_command = "TASK_POWERSHELL_CMD_WAIT_SAVE"
                else:
                    task_command = "TASK_POWERSHELL_CMD_WAIT"

        elif agent.language == "ironpython" and module.language == "csharp":
            task_command = "TASK_CSHARP"

        return {"command": task_command, "data": module_data}, None

    def generate_bof_data(
        self,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
    ) -> tuple[str, str]:
        bof_module = self.modules["csharp_inject_bof_inject_bof"]

        compiler = self.main_menu.pluginsv2.get_by_id("csharpserver")
        if not compiler.status == "ON":
            raise ModuleValidationException("csharpserver plugin not running")

        compiler_dict: dict = yaml.safe_load(bof_module.compiler_yaml)
        del compiler_dict[0]["Empire"]

        if params["Architecture"] == "x64":
            script_path = empire_config.directories.module_source / module.bof.x64
            bof_data = script_path.read_bytes()
            b64_bof_data = base64.b64encode(bof_data).decode("utf-8")

        elif params["Architecture"] == "x86":
            compiler_dict[0]["ReferenceSourceLibraries"][0]["EmbeddedResources"][0][
                "Name"
            ] = "RunOF.beacon_funcs.x64.o"
            compiler_dict[0]["ReferenceSourceLibraries"][0]["EmbeddedResources"][0][
                "Location"
            ] = "RunOF.beacon_funcs.x64.o"
            compiler_dict[0]["ReferenceSourceLibraries"][0][
                "Location"
            ] = "RunOF\\RunOF32\\"

            script_path = empire_config.directories.module_source / module.bof.x86
            bof_data = script_path.read_bytes()
            b64_bof_data = base64.b64encode(bof_data).decode("utf-8")

        compiler_yaml: str = yaml.dump(compiler_dict, sort_keys=False)

        file_name = compiler.do_send_message(
            compiler_yaml, bof_module.name, confuse=obfuscate
        )
        if file_name == "failed":
            raise ModuleExecutionException("module compile failed")

        script_file = (
            self.main_menu.installPath
            + "/csharp/Covenant/Data/Tasks/CSharp/Compiled/"
            + "net40"
            + "/"
            + file_name
            + ".compiled"
        )

        script_end = f",-a:{b64_bof_data}"

        if module.bof.entry_point != "":
            script_end += f" -e:{params['EntryPoint']}"

        return script_file, script_end

    def _validate_module_params(  # noqa: PLR0913
        self,
        db: Session,
        module: EmpireModule,
        agent: models.Agent,
        params: dict[str, str],
        ignore_language_version_check: bool = False,
        ignore_admin_check: bool = False,
    ) -> tuple[dict[str, str] | None, str | None]:
        """
        Given a module and execution params, validate the input and return back a clean Dict for execution.
        :param module: EmpireModule
        :param params: the execution parameters set by the user
        :return: tuple with options and the error message (if applicable)
        """
        converted_options = convert_module_options(module.options)
        options, err = validate_options(
            converted_options, params, db, self.download_service
        )

        if err:
            return None, err

        if not ignore_language_version_check:
            module_version = parse(module.min_language_version or "0")
            agent_version = parse(agent.language_version or "0")
            # check if the agent/module PowerShell versions are compatible
            if module_version > agent_version:
                raise ModuleValidationException(
                    f"module requires language version {module.min_language_version} but agent running language version {agent.language_version}",
                )

        if module.needs_admin and not ignore_admin_check and not agent.high_integrity:
            raise ModuleValidationException(
                "module needs to run in an elevated context"
            )

        return options, None

    def _generate_script(  # noqa: PLR0911
        self,
        db: Session,
        module: EmpireModule,
        params: dict,
        obfuscation_config: models.ObfuscationConfig = None,
    ) -> tuple[str | None, str | None]:
        """
        Generate the script to execute
        :param module: the execution parameters (already validated)
        :param params: the execution parameters
        :param obfuscation_config: the obfuscation config. If not provided, will look up from the db.
        :return: tuple containing the generated script and an error if it exists
        """
        if not obfuscation_config:
            obfuscation_config = self.obfuscation_service.get_obfuscation_config(
                db, module.language
            )
        if not obfuscation_config:
            obfuscation_enabled = False
            obfuscation_command = None
        else:
            obfuscation_enabled = obfuscation_config.enabled
            obfuscation_command = obfuscation_config.command

        if module.advanced.custom_generate:
            # In a future release we could refactor the modules to accept an obuscation_config,
            #  but there's little benefit to doing so at this point. So I'm saving myself the pain.
            try:
                return module.advanced.generate_class.generate(
                    self.main_menu,
                    module,
                    params,
                    obfuscation_enabled,
                    obfuscation_command,
                )
            except (ModuleValidationException, ModuleExecutionException) as e:
                raise e
            except Exception as e:
                log.error(f"Error generating script: {e}", exc_info=True)
                return None, "Error generating script."
        elif module.language == LanguageEnum.powershell:
            return self._generate_script_powershell(module, params, obfuscation_config)
        # We don't have obfuscation for other languages yet, but when we do,
        # we can pass it in here.
        elif module.language == LanguageEnum.python:
            return self._generate_script_python(module, params, obfuscation_config)
        elif module.language == LanguageEnum.csharp:
            return self._generate_script_csharp(module, params, obfuscation_config)
        elif module.language == LanguageEnum.bof:
            if not obfuscation_config:
                obfuscation_config = self.obfuscation_service.get_obfuscation_config(
                    db, LanguageEnum.csharp
                )
            return self._generate_script_bof(module, params, obfuscation_config)
        return None

    def _generate_script_bof(
        self,
        module: EmpireModule,
        params: dict,
        obfuscation_config: models.ObfuscationConfig,
    ) -> str:
        script_file, script_end = self.generate_bof_data(
            module=module, params=params, obfuscate=obfuscation_config.enabled
        )

        for key, v in params.items():
            value = v
            if key in ["Agent", "Architecture"]:
                continue
            for option in module.options:
                if option.name == key:
                    if value == "":
                        value = " "
                    script_end += f" -{option.format}:{value}"

        return f"{script_file}|{script_end}"

    def _generate_script_python(
        self,
        module: EmpireModule,
        params: dict,
        obfuscaton_config: models.ObfuscationConfig,
    ) -> str:
        obfuscate = obfuscaton_config.enabled

        if module.script_path:
            script_path = os.path.join(
                empire_config.directories.module_source,
                module.script_path,
            )
            with open(script_path) as stream:
                script = stream.read()
        else:
            script = module.script

        for key, value in params.items():
            if key.lower() != "agent" and key.lower() != "computername":
                script = script.replace("{{ " + key + " }}", value).replace(
                    "{{" + key + "}}", value
                )

        if obfuscate:
            script = self.obfuscation_service.python_obfuscate(script)

        return script

    def _generate_script_powershell(
        self,
        module: EmpireModule,
        params: dict,
        obfuscaton_config: models.ObfuscationConfig,
    ) -> str:
        obfuscate = obfuscaton_config.enabled
        obfuscate_command = obfuscaton_config.command

        if module.script_path:
            script, err = self.get_module_source(
                module_name=module.script_path,
                obfuscate=obfuscate,
                obfuscate_command=obfuscate_command,
            )

            if err:
                raise ModuleValidationException(err)
        elif obfuscate:
            script = self.obfuscation_service.obfuscate(
                module.script, obfuscate_command
            )
        else:
            script = module.script

        script_end = f" {module.script_end} "
        option_strings = []

        # This is where the code goes for all the modules that do not have a custom generate function.
        for key, value in params.items():
            if (
                key.lower() not in ["agent", "computername", "outputfunction"]
                and value
                and value != ""
            ):
                if value.lower() == "true":
                    # if we're just adding a switch
                    # wannabe mustache templating.
                    # If we want to get more advanced, we can import a library for it.
                    this_option = module.advanced.option_format_string_boolean.replace(
                        "{{ KEY }}", str(key)
                    ).replace("{{KEY}}", str(key))
                    option_strings.append(f"{this_option}")
                elif value.lower() == "false":
                    # Have to add a continue for false statements, else it adds -option 'False'
                    continue
                else:
                    this_option = (
                        module.advanced.option_format_string.replace(
                            "{{ KEY }}", str(key)
                        )
                        .replace("{{KEY}}", str(key))
                        .replace("{{ VALUE }}", str(value))
                        .replace("{{VALUE}}", str(value))
                    )
                    option_strings.append(f"{this_option}")

        script_end = (
            script_end.replace("{{ PARAMS }}", " ".join(option_strings))
            .replace("{{PARAMS}}", " ".join(option_strings))
            .replace(
                "{{ OUTPUT_FUNCTION }}", params.get("OutputFunction", "Out-String")
            )
            .replace("{{OUTPUT_FUNCTION}}", params.get("OutputFunction", "Out-String"))
        )

        # obfuscate the invoke command and append to script
        return self.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscate_command,
        )

    def _generate_script_csharp(
        self,
        module: EmpireModule,
        params: dict,
        obfuscation_config: models.ObfuscationConfig,
    ) -> str:
        try:
            compiler = self.main_menu.pluginsv2.get_by_id("csharpserver")
            if not compiler.status == "ON":
                raise ModuleValidationException("csharpserver plugin not running")
            file_name = compiler.do_send_message(
                module.compiler_yaml, module.name, confuse=obfuscation_config.enabled
            )
            if file_name == "failed":
                raise ModuleExecutionException("module compile failed")

            script_file = (
                self.main_menu.installPath
                + "/csharp/Covenant/Data/Tasks/CSharp/Compiled/"
                + (params["DotNetVersion"]).lower()
                + "/"
                + file_name
                + ".compiled"
            )
            param_string = ""
            for key, value in params.items():
                if (
                    key.lower() not in ["agent", "computername", "dotnetversion"]
                    and value
                    and value != ""
                ):
                    param_string += "," + value

            return f"{script_file}|{param_string}"
        except (ModuleValidationException, ModuleExecutionException) as e:
            raise e
        except Exception as e:
            log.error(f"dotnet compile error: {e}")
            raise ModuleExecutionException("dotnet compile error") from e

    def _create_modified_module(self, module: EmpireModule, modified_input: str):
        """
        Return a copy of the original module with the input modified.
        """
        modified_module = module.model_copy(deep=True)
        modified_module.script = modified_input
        modified_module.script_path = None

        if modified_module.language == LanguageEnum.csharp:
            compiler_dict = yaml.safe_load(modified_module.compiler_yaml)
            compiler_dict[0]["Code"] = modified_input
            modified_module.compiler_yaml = yaml.safe_dump(compiler_dict)

        return modified_module

    def load_modules(self, db: Session):
        """
        Load Empire modules.
        """
        root_path = f"{self.main_menu.installPath}/modules/"

        log.info(f"v2: Loading modules from: {root_path}")

        for root, _dirs, files in os.walk(root_path):
            for filename in files:
                if not filename.lower().endswith(
                    ".yaml"
                ) and not filename.lower().endswith(".yml"):
                    continue

                file_path = os.path.join(root, filename)

                # don't load up any of the templates
                if fnmatch.fnmatch(filename, "*template.yaml"):
                    continue

                # instantiate the module and save it to the internal cache
                try:
                    with open(file_path) as stream:
                        if file_path.lower().endswith(".covenant.yaml"):
                            yaml2 = yaml.safe_load(stream)
                            for covenant_module in yaml2:
                                # remove None values so pydantic can apply defaults
                                yaml_module = {
                                    k: v
                                    for k, v in covenant_module.items()
                                    if v is not None
                                }
                                self._load_module(db, yaml_module, root_path, file_path)
                        else:
                            yaml2 = yaml.safe_load(stream)
                            yaml_module = {
                                k: v for k, v in yaml2.items() if v is not None
                            }
                            self._load_module(db, yaml_module, root_path, file_path)
                except Exception as e:
                    log.error(f"Error loading module {filename}: {e}")

    def _load_module(self, db: Session, yaml_module, root_path, file_path: str):
        # extract just the module name from the full path
        module_name = file_path.split(root_path)[-1][0:-5]

        if file_path.lower().endswith(".covenant.yaml"):
            cov_yaml_module = _convert_covenant_to_empire(yaml_module, file_path)
            module_name = f"{module_name[:-9]}/{cov_yaml_module['name']}"
            cov_yaml_module["id"] = self.slugify(module_name)
            my_model = EmpireModule(**cov_yaml_module)
        else:
            yaml_module["id"] = self.slugify(module_name)
            my_model = EmpireModule(**yaml_module)

        if my_model.advanced.custom_generate:
            if not os.path.exists(file_path[:-4] + "py"):
                raise Exception("No File to use for custom generate.")
            spec = importlib.util.spec_from_file_location(
                module_name + ".py", file_path[:-5] + ".py"
            )
            imp_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(imp_mod)
            my_model.advanced.generate_class = imp_mod.Module()
        elif my_model.script_path:
            if not os.path.exists(
                os.path.join(
                    empire_config.directories.module_source,
                    my_model.script_path,
                )
            ):
                raise Exception(
                    f"File provided in script_path does not exist: { module_name }"
                )
        elif my_model.script:
            pass
        elif my_model.language == LanguageEnum.bof:
            if not (
                empire_config.directories.module_source / my_model.bof.x86
            ).exists():
                raise Exception(f"x86 bof file provided does not exist: {module_name}")
            if not (
                empire_config.directories.module_source / my_model.bof.x64
            ).exists():
                raise Exception(f"x64 bof file provided does not exist: {module_name}")
        else:
            raise Exception(
                "Must provide a valid script, script_path, or custom generate function"
            )

        mod = db.query(models.Module).filter(models.Module.id == my_model.id).first()

        if not mod:
            mod = models.Module(
                id=my_model.id,
                name=module_name,
                enabled=True,
                tactic=my_model.tactics,
                technique=my_model.techniques,
                software=my_model.software,
            )
            db.add(mod)

        self.modules[self.slugify(module_name)] = my_model
        self.modules[self.slugify(module_name)].enabled = mod.enabled

    def get_module_script(self, module_id: str):
        mod: EmpireModule = self.modules.get(module_id)

        if not mod:
            return None

        if mod.script_path:
            script_path = (
                Path(empire_config.directories.module_source) / mod.script_path
            )
            script = script_path.read_text()
        else:
            script = mod.script

        return script

    def get_module_source(
        self, module_name: str, obfuscate: bool = False, obfuscate_command: str = ""
    ) -> tuple[str | None, str | None]:
        """
        Get the obfuscated/unobfuscated module source code.
        """
        try:
            if obfuscate:
                obfuscated_module_source = (
                    empire_config.directories.obfuscated_module_source
                )
                module_path = os.path.join(obfuscated_module_source, module_name)
                # If pre-obfuscated module exists then return code
                if os.path.exists(module_path):
                    with open(module_path) as f:
                        obfuscated_module_code = f.read()
                    return obfuscated_module_code, None

                # If pre-obfuscated module does not exist then generate obfuscated code and return it
                module_source = empire_config.directories.module_source
                module_path = os.path.join(module_source, module_name)
                with open(module_path) as f:
                    module_code = f.read()
                obfuscated_module_code = self.obfuscation_service.obfuscate(
                    module_code, obfuscate_command
                )
                return obfuscated_module_code, None

            # Use regular/unobfuscated code
            module_source = empire_config.directories.module_source
            module_path = os.path.join(module_source, module_name)
            with open(module_path) as f:
                module_code = f.read()
            return module_code, None
        except Exception:
            return None, f"[!] Could not read module source path at: {module_source}"

    def finalize_module(
        self,
        script: str,
        script_end: str,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ) -> str:
        """
        Combine script and script end with obfuscation if needed.
        """
        if "PowerSploit File: PowerView.ps1" in script:
            module_name = script_end.lstrip().split(" ")[0]
            script = helpers.generate_dynamic_powershell_script(script, module_name)

        script += script_end
        if obfuscate:
            script = self.obfuscation_service.obfuscate(script, obfuscation_command)
        return self.obfuscation_service.obfuscate_keywords(script)

    @staticmethod
    def slugify(module_name: str):
        return module_name.lower().replace("/", "_")

    def delete_all_modules(self, db: Session):
        for module in list(self.modules.values()):
            db_module: models.Module = (
                db.query(models.Module).filter(models.Module.id == module.id).first()
            )
            if db_module:
                db.delete(db_module)
            del self.modules[module.id]
        db.flush()


def auto_get_source(func):
    def wrapper(*args, **kwargs):
        main_menu = args[0]
        module = args[1]
        obfuscate = args[3]
        obfuscation_command = args[4]

        script, err = main_menu.modulesv2.get_module_source(
            module_name=module.script_path,
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        if err:
            raise ModuleValidationException(err)

        return func(*args, script=script, **kwargs)

    return wrapper


def auto_finalize(func):
    def wrapper(*args, **kwargs):
        script, script_end = func(*args, **kwargs)

        main_menu = args[0]
        obfuscate = args[3]
        obfuscation_command = args[4]

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )

    return wrapper
