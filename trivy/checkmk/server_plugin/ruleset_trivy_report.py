#!/usr/bin/env python3

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
    DefaultValue,
    Dictionary,
    DictElement,
    FixedValue,
    Integer,
)
from cmk.rulesets.v1.form_specs.validators import NumberInRange
from cmk.rulesets.v1.rule_specs import (
    CheckParameters,
    HostCondition,
    Topic,
)


def _optional_threshold(title_text, help_text):
    return CascadingSingleChoice(
        title=Title(title_text),
        help_text=Help(help_text),
        prefill=DefaultValue("disabled"),
        elements=[
            CascadingSingleChoiceElement(
                name="disabled",
                title=Title("Disabled"),
                parameter_form=FixedValue(
                    value=None,
                ),
            ),
            CascadingSingleChoiceElement(
                name="enabled",
                title=Title("Enabled"),
                parameter_form=Integer(
                    title=Title("Findings threshold"),
                    prefill=DefaultValue(1),
                    custom_validate=(
                        NumberInRange(min_value=1),
                    ),
                ),
            ),
        ],
    )


def _optional_age_threshold(title_text, help_text, default_hours):
    return CascadingSingleChoice(
        title=Title(title_text),
        help_text=Help(help_text),
        prefill=DefaultValue("enabled"),
        elements=[
            CascadingSingleChoiceElement(
                name="disabled",
                title=Title("Disabled"),
                parameter_form=FixedValue(
                    value=None,
                ),
            ),
            CascadingSingleChoiceElement(
                name="enabled",
                title=Title("Enabled"),
                parameter_form=Integer(
                    title=Title("Age in hours"),
                    prefill=DefaultValue(default_hours),
                    custom_validate=(
                        NumberInRange(min_value=1),
                    ),
                ),
            ),
        ],
    )


def _severity_form(title_text):
    return Dictionary(
        title=Title(title_text),
        elements={
            "warn_count": DictElement(
                required=True,
                parameter_form=_optional_threshold(
                    "WARN threshold",
                    f"Number of {title_text} findings required for WARN.",
                ),
            ),
            "crit_count": DictElement(
                required=True,
                parameter_form=_optional_threshold(
                    "CRIT threshold",
                    f"Number of {title_text} findings required for CRIT.",
                ),
            ),
        },
    )


def _parameter_form():
    return Dictionary(
        title=Title("Trivy vulnerability report"),
        elements={
            "critical": DictElement(
                required=True,
                parameter_form=_severity_form("CRITICAL"),
            ),

            "high": DictElement(
                required=True,
                parameter_form=_severity_form("HIGH"),
            ),

            "medium": DictElement(
                required=True,
                parameter_form=_severity_form("MEDIUM"),
            ),

            "low": DictElement(
                required=True,
                parameter_form=_severity_form("LOW"),
            ),

            "unknown": DictElement(
                required=True,
                parameter_form=_severity_form("UNKNOWN"),
            ),

            "age_warn": DictElement(
                required=True,
                parameter_form=_optional_age_threshold(
                    "WARN if Trivy report is too old",
                    "Maximum report age before WARN.",
                    8,
                ),
            ),

            "age_crit": DictElement(
                required=True,
                parameter_form=_optional_age_threshold(
                    "CRIT if Trivy report is too old",
                    "Maximum report age before CRIT.",
                    14,
                ),
            ),
        },
    )


rule_spec_trivy_report = CheckParameters(
    name="trivy_report",
    title=Title("Trivy vulnerability report"),
    topic=Topic.GENERAL,
    parameter_form=_parameter_form,
    condition=HostCondition(),
)