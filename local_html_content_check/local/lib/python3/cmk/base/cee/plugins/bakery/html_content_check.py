#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from typing import TypedDict, List

from .bakery_api.v1 import (
    OS,
    Plugin,
    PluginConfig,
    FileGenerator,
    register,
)


class HtmlContentStatusRule(TypedDict):
    pattern: str
    state: str


class HtmlContentCheckItem(TypedDict):
    service: str
    file_path: str
    mode: str
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


def _sanitize(value: str) -> str:
    return value.replace("|", "/")


def _config_lines(conf: HtmlContentCheckConfig) -> List[str]:
    lines = []

    for check in conf.get("checks", []):
        status_rules = []

        for rule in check.get("status_rules", []):
            pattern = _sanitize(rule["pattern"])
            state = STATE_MAP.get(rule["state"], "3")
            status_rules.append(f"{pattern}={state}")

        line = "|".join(
            [
                _sanitize(check["service"]),
                _sanitize(check["file_path"]),
                check["mode"],
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
