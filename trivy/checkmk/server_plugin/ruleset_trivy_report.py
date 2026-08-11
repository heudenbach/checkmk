#!/usr/bin/env python3

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
    DefaultValue,
    Dictionary,
    DictElement,
    FixedValue,
    Float,
    Integer,
    List,
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


def _range_form():
    return Dictionary(
        title=Title("CVSS range"),
        elements={
            "minimum": DictElement(
                required=True,
                parameter_form=Float(
                    title=Title("Minimum CVSS score"),
                    prefill=DefaultValue(0.0),
                    custom_validate=(
                        NumberInRange(
                            min_value=0.0,
                            max_value=10.0,
                        ),
                    ),
                ),
            ),

            "maximum": DictElement(
                required=True,
                parameter_form=Float(
                    title=Title("Maximum CVSS score"),
                    prefill=DefaultValue(10.0),
                    custom_validate=(
                        NumberInRange(
                            min_value=0.0,
                            max_value=10.0,
                        ),
                    ),
                ),
            ),

            "warn_count": DictElement(
                required=True,
                parameter_form=_optional_threshold(
                    "WARN threshold",
                    "Enable this threshold if this CVSS range "
                    "should cause WARN.",
                ),
            ),

            "crit_count": DictElement(
                required=True,
                parameter_form=_optional_threshold(
                    "CRIT threshold",
                    "Enable this threshold if this CVSS range "
                    "should cause CRIT.",
                ),
            ),
        },
    )


def _parameter_form():
    return Dictionary(
        title=Title("Trivy vulnerability report"),
        elements={
            "ranges": DictElement(
                required=True,
                parameter_form=List(
                    title=Title("CVSS score ranges"),
                    help_text=Help(
                        "Define any number of CVSS ranges. "
                        "Ranges must not overlap."
                    ),
                    element_template=_range_form(),
                    editable_order=True,
                ),
            ),

            "unknown_warn": DictElement(
                required=True,
                parameter_form=_optional_threshold(
                    "WARN for findings without CVSS",
                    "Configure whether findings without a numerical "
                    "CVSS score should cause WARN.",
                ),
            ),

            "unknown_crit": DictElement(
                required=True,
                parameter_form=_optional_threshold(
                    "CRIT for findings without CVSS",
                    "Configure whether findings without a numerical "
                    "CVSS score should cause CRIT.",
                ),
            ),

            "age_warn": DictElement(
                required=True,
                parameter_form=_optional_age_threshold(
                    "WARN if Trivy report is too old",
                    "Set the maximum report age before the service "
                    "changes to WARN.",
                    8,
                ),
            ),

            "age_crit": DictElement(
                required=True,
                parameter_form=_optional_age_threshold(
                    "CRIT if Trivy report is too old",
                    "Set the maximum report age before the service "
                    "changes to CRIT.",
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