from fastapi import Depends, HTTPException

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.api.v2.stager.stager_dto import (
    StagerTemplate,
    StagerTemplates,
    domain_to_dto_template,
)
from empire.server.server import main

stager_template_service = main.stagertemplatesv2

router = APIRouter(
    prefix="/api/v2/stager-templates",
    tags=["stager-templates"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


@router.get("/", response_model=StagerTemplates)
async def get_stager_templates():
    templates = [
        domain_to_dto_template(x[1], x[0])
        for x in stager_template_service.get_stager_templates().items()
    ]

    return {"records": templates}


@router.get(
    "/{uid}",
    response_model=StagerTemplate,
)
async def get_stager_template(uid: str):
    template = stager_template_service.get_stager_template(uid)

    if not template:
        raise HTTPException(status_code=404, detail="Stager template not found")

    return domain_to_dto_template(template, uid)
