"""
app/api/v1/rules.py

Purpose:
    View detection rules and (admin only) enable/disable them or tune
    their settings without a redeploy. Changes apply to the live
    RuleEngine immediately and are persisted in MongoDB
    `detection_rules`, from where main.py restores them at startup.
"""
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.core.dependencies import get_current_user, require_admin
from app.core.logging_config import audit_event
from app.db import mongo
from app.detection.engine import default_rule_engine
from app.detection.rules.base_rule import BaseRule, IntSetting, RuleConfigError
from app.models.user_schema import UserInDB

router = APIRouter(prefix="/rules", tags=["Detection Rules"])


class RuleUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    config: Optional[Dict[str, Any]] = Field(default=None, description="Setting overrides, e.g. {'threshold': 6}")


def _describe(rule: BaseRule) -> dict:
    return {
        "rule_name": rule.rule_name,
        "description": rule.description,
        "mitre_technique": rule.mitre_technique,
        "enabled": rule.enabled,
        "config": dict(rule.config),
        "settings": {
            name: (
                {"type": "integer", "default": setting.default, "min": setting.minimum, "max": setting.maximum}
                if isinstance(setting, IntSetting)
                else {"type": "string_list", "default": list(setting.default)}
            )
            for name, setting in rule.settings.items()
        },
    }


@router.get("")
async def list_rules(current_user: UserInDB = Depends(get_current_user)):
    return {"rules": [_describe(rule) for rule in default_rule_engine.list_rules()]}


@router.patch("/{rule_name}")
async def update_rule(rule_name: str, body: RuleUpdateRequest, admin: UserInDB = Depends(require_admin)):
    rule = default_rule_engine.get_rule(rule_name)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_name}' not found")

    if body.config:
        try:
            rule.update_config(body.config)
        except RuleConfigError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    if body.enabled is not None:
        rule.enabled = body.enabled

    await mongo.upsert_rule_config(rule_name, enabled=rule.enabled, config=dict(rule.config))
    audit_event("rule_updated", rule=rule_name, enabled=rule.enabled, config=rule.config, actor=admin.username)
    return _describe(rule)
