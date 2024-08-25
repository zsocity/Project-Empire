import json

import pytest

from empire.server.core.hooks import hooks


@pytest.fixture(scope="function")
def existing_processes(session_local, models, host):
    with session_local.begin() as db:
        existing_processes = [
            models.HostProcess(
                host_id=host,
                process_id=1,
                process_name="should_be_stale",
                architecture="x86",
                user="test_user",
            ),
            models.HostProcess(
                host_id=host,
                process_id=2,
                process_name="should_be_updated",
                architecture="x86",
                user="test_user",
            ),
            models.HostProcess(
                host_id=host,
                process_id=3,
                process_name="should_be_same",
                architecture="x86",
                user="test_user",
            ),
        ]
        db.add_all(existing_processes)

    yield

    with session_local.begin() as db:
        db.query(models.HostProcess).delete()


def test_ps_hook(client, session_local, models, host, agent, existing_processes):
    with session_local.begin() as db:
        output = json.dumps(
            [
                {
                    "CMD": "has_been_updated",
                    "PID": 2,
                    "Arch": "x86_64",
                    "UserName": "test_user",
                },
                {
                    "CMD": "should_be_same",
                    "PID": 3,
                    "Arch": "x86",
                    "UserName": "test_user",
                },
                {
                    "CMD": "should_be_new",
                    "PID": 4,
                    "Arch": "x86",
                    "UserName": "test_user",
                },
            ]
        )
        db_agent = (
            db.query(models.Agent).filter(models.Agent.session_id == agent).first()
        )
        task = models.AgentTask(
            id=1,
            agent_id=agent,
            agent=db_agent,
            input="ps",
            status=models.AgentTaskStatus.pulled,
            output=output,
            original_output=output,
        )
        hooks.run_hooks(hooks.BEFORE_TASKING_RESULT_HOOK, db, task)
        db.flush()
        processes = db.query(models.HostProcess).all()

        expected_processes = 4
        assert len(processes) == expected_processes
        assert processes[0].process_name == "should_be_stale"
        assert processes[0].stale is True
        assert processes[1].process_name == "has_been_updated"
        assert processes[1].stale is False
        assert processes[2].process_name == "should_be_same"
        assert processes[2].stale is False
        assert processes[3].process_name == "should_be_new"
        assert processes[3].stale is False
