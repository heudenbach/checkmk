#!/usr/bin/env python3

from pathlib import Path

from .bakery_api.v1 import (
    FileGenerator,
    OS,
    Plugin,
    register,
)


def get_trivy_report_files(conf: dict) -> FileGenerator:
    yield Plugin(
        base_os=OS.LINUX,
        source=Path("trivy_report"),
        target=Path("trivy_report"),
    )


register.bakery_plugin(
    name="trivy_report_bakery",
    files_function=get_trivy_report_files,
)