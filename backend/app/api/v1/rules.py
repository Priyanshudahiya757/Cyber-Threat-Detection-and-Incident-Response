"""
app/api/v1/rules.py

Purpose:
    Admin endpoints to view/enable/disable rule-based detection rules
    without redeploy. Enabled state is persisted in MongoDB
    `detection_rules` and applied to the live RuleEngine.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.core.dependencies import require_role
from app.db import mongo
from app.detection.engine import default_rule_engine
from app.models.user_schema import UserInDB, UserRole

router = APIRouter(prefix="/rules", tags=["Detection Rules"])


class RuleUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    config: Optional[dict] = Field(default=None, description="Optional threshold overrides")


@router.get("")
async def list_rules(
    current_user: UserInDB = Depends(require_role(UserRole.ADMIN, UserRole.SOC_ANALYST)),
):
    return {
        "rules": [
            {
                "rule_name": rule.rule_name,
                "description": rule.description,
                "mitre_technique": rule.mitre_technique,
                "enabled": rule.enabled,
                "config": dict(rule.config._values) if rule.config else {},
            }
            for rule in default_rule_engine.list_rules()
        ]
    }


@router.patch("/{rule_name}")
async def update_rule(
    rule_name: str,
    body: RuleUpdateRequest,
    current_user: UserInDB = Depends(require_role(UserRole.ADMIN)),
):
    rule = default_rule_engine.get_rule(rule_name)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_name}' not found")

    enabled = rule.enabled if body.enabled is None else body.enabled
    if body.enabled is not None:
        default_rule_engine.set_rule_enabled(rule_name, body.enabled)

    if body.config:
        for key, value in body.config.items():
            rule.config._values[key] = value

    saved = await mongo.upsert_rule_config(rule_name, enabled=enabled, config=body.config)
    saved["_id"] = str(saved["_id"])
    return {
        "rule_name": rule.rule_name,
        "description": rule.description,
        "mitre_technique": rule.mitre_technique,
        "enabled": rule.enabled,
        "config": dict(rule.config._values) if rule.config else {},
        "persisted": saved,
    }
