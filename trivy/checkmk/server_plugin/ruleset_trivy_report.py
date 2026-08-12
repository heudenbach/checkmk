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


def _optional_threshold(title_text, help_text, default_enabled=False):
    return CascadingSingleChoice(
        title=Title(title_text),
        help_text=Help(help_text),
        prefill=DefaultValue(
            "enabled" if default_enabled else "disabled"
        ),
        elements=[
            CascadingSingleChoiceElement(
                name="disabled",
                title=Title("Disabled"),
                parameter_form=FixedValue(value=None),
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
                parameter_form=FixedValue(value=None),
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


def _priority_form(title_text, help_text, warn_default=False, crit_default=False):
    return Dictionary(
        title=Title(title_text),
        help_text=Help(help_text),
        elements={
            "warn_count": DictElement(
                required=True,
                parameter_form=_optional_threshold(
                    "WARN threshold",
                    f"Number of {title_text} findings required for WARN.",
                    warn_default,
                ),
            ),
            "crit_count": DictElement(
                required=True,
                parameter_form=_optional_threshold(
                    "CRIT threshold",
                    f"Number of {title_text} findings required for CRIT.",
                    crit_default,
                ),
            ),
        },
    )


def _parameter_form():
    return Dictionary(
        title=Title("Trivy vulnerability report"),
        elements={
            "p1": DictElement(
                required=True,
                parameter_form=_priority_form(
                    "P1 - Immediate",
                    "Highest operational priority. Normally includes known exploitation or other immediate-action conditions.",
                    crit_default=True,
                ),
            ),
            "p2": DictElement(
                required=True,
                parameter_form=_priority_form(
                    "P2 - High",
                    "High operational priority, for example HIGH vendor severity combined with ACTION_REQUIRED.",
                    warn_default=True,
                ),
            ),
            "p3": DictElement(
                required=True,
                parameter_form=_priority_form(
                    "P3 - Normal",
                    "Runtime-relevant findings requiring action without P1/P2 escalation.",
                ),
            ),
            "p4": DictElement(
                required=True,
                parameter_form=_priority_form(
                    "P4 - Review",
                    "Findings currently assigned to review rather than immediate remediation.",
                ),
            ),
            "kev": DictElement(
                required=True,
                parameter_form=_priority_form(
                    "CISA KEV",
                    "Findings present in the CISA Known Exploited Vulnerabilities catalog.",
                    crit_default=True,
                ),
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