import math
from datetime import datetime

from fastapi import Depends, HTTPException, Query

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.plugin.plugin_task_dto import (
    PluginTask,
    PluginTaskOrderOptions,
    PluginTasks,
    domain_to_dto_plugin_task,
)
from empire.server.api.v2.shared_dependencies import CurrentSession
from empire.server.api.v2.shared_dto import (
    BadRequestResponse,
    NotFoundResponse,
    OrderDirection,
)
from empire.server.api.v2.tag import tag_api
from empire.server.api.v2.tag.tag_dto import TagStr
from empire.server.core.db import models
from empire.server.core.db.models import PluginTaskStatus
from empire.server.core.download_service import DownloadService
from empire.server.core.plugin_service import PluginService
from empire.server.server import main

download_service: DownloadService = main.downloadsv2
plugin_service: PluginService = main.pluginsv2

router = APIRouter(
    prefix="/api/v2/plugins",
    tags=["plugins", "tasks"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


async def get_plugin(plugin_id: str):
    plugin = plugin_service.get_by_id(plugin_id)

    if plugin:
        return plugin

    raise HTTPException(404, f"Plugin not found for id {plugin_id}")


async def get_task(uid: int, db: CurrentSession, plugin=Depends(get_plugin)):
    task = plugin_service.get_task(db, plugin.info["Name"], uid)

    if task:
        return task

    raise HTTPException(
        404, f"Task not found for plugin {plugin.info['Name']} and task id {uid}"
    )


tag_api.add_endpoints_to_taggable(router, "/{plugin_id}/tasks/{uid}/tags", get_task)


@router.get("/tasks", response_model=PluginTasks)
async def read_tasks_all_plugins(
    db: CurrentSession,
    limit: int = -1,
    page: int = 1,
    include_full_input: bool = False,
    include_output: bool = True,
    since: datetime | None = None,
    order_by: PluginTaskOrderOptions = PluginTaskOrderOptions.id,
    order_direction: OrderDirection = OrderDirection.desc,
    status: PluginTaskStatus | None = None,
    plugins: list[str] | None = Query(None),
    users: list[int] | None = Query(None),
    tags: list[TagStr] | None = Query(None),
    query: str | None = None,
):
    tasks, total = plugin_service.get_tasks(
        db,
        plugins=plugins,
        users=users,
        tags=tags,
        limit=limit,
        offset=(page - 1) * limit,
        include_full_input=include_full_input,
        include_output=include_output,
        since=since,
        order_by=order_by,
        order_direction=order_direction,
        status=status,
        q=query,
    )

    tasks_converted = [
        domain_to_dto_plugin_task(x, include_full_input, include_output) for x in tasks
    ]

    return PluginTasks(
        records=tasks_converted,
        page=page,
        total_pages=math.ceil(total / limit),
        limit=limit,
        total=total,
    )


@router.get("/{plugin_id}/tasks", response_model=PluginTasks)
async def read_tasks(
    db: CurrentSession,
    limit: int = -1,
    page: int = 1,
    include_full_input: bool = False,
    include_output: bool = True,
    since: datetime | None = None,
    order_by: PluginTaskOrderOptions = PluginTaskOrderOptions.id,
    order_direction: OrderDirection = OrderDirection.desc,
    status: PluginTaskStatus | None = None,
    users: list[int] | None = Query(None),
    tags: list[TagStr] | None = Query(None),
    plugin=Depends(get_plugin),
    query: str | None = None,
):
    tasks, total = plugin_service.get_tasks(
        db,
        plugins=[plugin.info["Name"]],
        users=users,
        tags=tags,
        limit=limit,
        offset=(page - 1) * limit,
        include_full_input=include_full_input,
        include_output=include_output,
        since=since,
        order_by=order_by,
        order_direction=order_direction,
        status=status,
        q=query,
    )

    tasks_converted = [
        domain_to_dto_plugin_task(x, include_full_input, include_output) for x in tasks
    ]

    return PluginTasks(
        records=tasks_converted,
        page=page,
        total_pages=math.ceil(total / limit) if limit > 0 else page,
        limit=limit,
        total=total,
    )


@router.get("/{plugin_id}/tasks/{uid}", response_model=PluginTask)
async def read_task(
    uid: int,
    db: CurrentSession,
    plugin=Depends(get_plugin),
    db_task: models.PluginTask = Depends(get_task),
):
    if not db_task:
        raise HTTPException(status_code=404, detail="Task not found")

    return domain_to_dto_plugin_task(db_task)
