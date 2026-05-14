#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from typing import Any, TypedDict, List

from .bakery_api.v1 import (
    OS,
    Plugin,
    PluginConfig,
    FileGenerator,
    register,
)


class HtmlContentStatusRule(TypedDict):
    condition: tuple[str, Any]
    state: str


class HtmlContentCheckItem(TypedDict):
    service_prefix: str
    service: str
    file_path: str
    default_state: str
    status_rules: List[HtmlContentStatusRule]


class HtmlContentCheckConfig(TypedDict):
    checks: List[HtmlContentCheckItem]


STATE_MAP = {
    "ok": "0",
    "warn": "1",
    "crit": "2",
    "unknown": "3",
}


OPERATOR_MAP = {
    "contains": "contains",
    "equals": "equals",
    "regex": "regex",
    "startswith": "startswith",
    "endswith": "endswith",
    "less_than": "<",
    "less_equal": "<=",
    "greater_than": ">",
    "greater_equal": ">=",
    "between": "between",
    "outside": "outside",
}


def _sanitize(value: str) -> str:
    return value.replace("|", "/")


def _service_name(check: HtmlContentCheckItem) -> str:
    prefix = check.get("service_prefix", "Content of").strip()
    service = check["service"].strip()

    if prefix:
        return f"{prefix} {service}"

    return service


def _condition_parts(rule: HtmlContentStatusRule) -> tuple[str, str]:
    operator_name, value = rule["condition"]
    operator = OPERATOR_MAP.get(operator_name, "contains")

    if operator_name in ("between", "outside"):
        value_string = f"{value['min']}:{value['max']}"
    else:
        value_string = str(value)

    return operator, value_string


def _config_lines(conf: HtmlContentCheckConfig) -> List[str]:
    lines = []

    for check in conf.get("checks", []):
        status_rules = []

        for rule in check.get("status_rules", []):
            operator, value = _condition_parts(rule)
            state = STATE_MAP.get(rule["state"], "3")

            status_rules.append(
                f"{_sanitize(operator)}={_sanitize(value)}={state}"
            )

        line = "|".join(
            [
                _sanitize(_service_name(check)),
                _sanitize(check["file_path"]),
                STATE_MAP.get(check["default_state"], "3"),
                *status_rules,
            ]
        )

        lines.append(line)

    return lines


def get_html_content_check_files(conf: HtmlContentCheckConfig) -> FileGenerator:
    yield Plugin(
        base_os=OS.LINUX,
        source=Path("html_content_check"),
        target=Path("html_content_check"),
        interval=0,
    )

    yield PluginConfig(
        base_os=OS.LINUX,
        lines=_config_lines(conf),
        target=Path("html_content_check.cfg"),
        include_header=False,
    )


register.bakery_plugin(
    name="html_content_check",
    files_function=get_html_content_check_files,
)
