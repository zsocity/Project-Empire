import logging
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest
import yaml
from _pytest.logging import LogCaptureHandler

from empire.server.core.exceptions import (
    ModuleValidationException,
)
from empire.test.conftest import patch_config


def convert_options_to_params(options):
    params = {}
    for option in options:
        params[option.name] = option.value
    return params


def fake_obfuscate(psScript, obfuscation_command):
    return psScript


@contextmanager
def catch_logs(level: int, logger: logging.Logger) -> LogCaptureHandler:
    """Context manager that sets the level for capturing of logs.

    After the end of the 'with' statement the level is restored to its original value.

    :param level: The level.
    :param logger: The logger to update.
    """
    handler = LogCaptureHandler()
    orig_level = logger.level
    logger.setLevel(level)
    logger.addHandler(handler)
    try:
        yield handler
    finally:
        logger.setLevel(orig_level)
        logger.removeHandler(handler)


@pytest.fixture(scope="function")
def main_menu_mock(models):
    main_menu = Mock()
    main_menu.installPath = "empire/server"

    main_menu.obfuscationv2 = Mock()
    obf_conf_mock = MagicMock()
    main_menu.obfuscationv2.get_obfuscation_config = Mock(
        side_effect=lambda x, y: obf_conf_mock
    )
    main_menu.obfuscationv2.get_obfuscation_config = Mock(
        return_value=models.ObfuscationConfig(
            language="python", command="", enabled=False
        )
    )
    main_menu.obfuscationv2.obfuscate = Mock(side_effect=fake_obfuscate)
    main_menu.obfuscationv2.obfuscate_keywords = Mock(side_effect=lambda x: x)

    yield main_menu


@pytest.fixture(scope="function")
def module_service(main_menu_mock):
    from empire.server.core.module_service import ModuleService

    module_service = ModuleService(main_menu_mock)
    main_menu_mock.modulesv2 = module_service

    yield module_service


@pytest.mark.slow
def test_load_modules(main_menu_mock, models, db):
    """
    This is just meant to be a small smoke test to ensure that the modules
    that come with Empire can be loaded properly at startup and a script can
    be generated with the default values.
    """
    # https://github.com/pytest-dev/pytest/issues/3697
    # caplog not working for some reason.
    from empire.server.core.module_service import ModuleService

    with catch_logs(
        level=logging.INFO, logger=logging.getLogger(ModuleService.__module__)
    ) as handler:
        module_service = ModuleService(main_menu_mock)

        messages = [x.message for x in handler.records if x.levelno >= logging.WARNING]

    if messages:
        pytest.fail(f"warning messages encountered during testing: {messages}")

    min_modules = 300
    assert len(module_service.modules) > min_modules
    assert len(db.query(models.Module).all()) > min_modules

    for key, module in module_service.modules.items():
        if not module.advanced.custom_generate:
            try:
                err = None
                resp = module_service._generate_script(
                    db, module, convert_options_to_params(module.options), None
                )

                if isinstance(resp, tuple):
                    resp, err = resp

                if err != "csharpserver plugin not running":
                    # fail if a module fails to generate a script.
                    assert (
                        resp is not None and len(resp) > 0
                    ), f"No generated script for module {key}"

            except ModuleValidationException as e:
                # not gonna bother mocking out the csharp server right now.
                if str(e) == "csharpserver plugin not running":
                    pass


def test_execute_custom_generate(
    module_service, session_local, agent, models, install_path
):
    with session_local.begin() as db:
        file_path = "empire/test/data/modules/test_custom_module.yaml"
        root_path = f"{install_path}/modules/"
        path = Path(file_path)
        module_service._load_module(
            db, yaml.safe_load(path.read_text()), root_path, file_path
        )

        db_agent = (
            db.query(models.Agent).filter(models.Agent.session_id == agent).first()
        )
        execute, err = module_service.execute_module(
            db,
            db_agent,
            "empire_test_data_modules_test_custom_module",
            {"Agent": agent},
            ignore_admin_check=True,
            ignore_language_version_check=True,
        )

        assert err is None
        assert execute["data"] == "This is the module code."


def test_auto_get_source(
    empire_config, module_service, session_local, agent, models, install_path
):
    with session_local.begin() as db, patch_config(empire_config):
        source_path = Path(
            "empire/test/data/module_source/custom_module_auto_get_source.py"
        )
        file_path = "empire/test/data/modules/test_custom_module_auto_get_source.yaml"
        root_path = f"{install_path}/modules/"
        path = Path(file_path)
        module_service._load_module(
            db, yaml.safe_load(path.read_text()), root_path, file_path
        )

        db_agent = (
            db.query(models.Agent).filter(models.Agent.session_id == agent).first()
        )
        execute, err = module_service.execute_module(
            db,
            db_agent,
            "empire_test_data_modules_test_custom_module_auto_get_source",
            {"Agent": agent},
            ignore_admin_check=True,
            ignore_language_version_check=True,
        )

        assert err is None
        assert execute["data"].strip() == source_path.read_text().strip()


def test_auto_finalize(
    empire_config, module_service, session_local, agent, models, install_path
):
    with session_local.begin() as db, patch_config(empire_config):
        file_path = "empire/test/data/modules/test_custom_module_auto_finalize.yaml"
        root_path = f"{install_path}/modules/"
        path = Path(file_path)
        module_service._load_module(
            db, yaml.safe_load(path.read_text()), root_path, file_path
        )

        db_agent = (
            db.query(models.Agent).filter(models.Agent.session_id == agent).first()
        )
        execute, err = module_service.execute_module(
            db,
            db_agent,
            "empire_test_data_modules_test_custom_module_auto_finalize",
            {"Agent": agent},
            ignore_admin_check=True,
            ignore_language_version_check=True,
        )

        assert err is None
        assert execute["data"].strip() == "ScriptScriptEnd"
