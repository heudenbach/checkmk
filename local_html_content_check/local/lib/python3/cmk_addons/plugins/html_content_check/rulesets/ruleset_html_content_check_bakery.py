#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cmk.rulesets.v1 import Title, Help
from cmk.rulesets.v1.form_specs import (
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
    DefaultValue,
    DictElement,
    Dictionary,
    Float,
    List,
    String,
    SingleChoice,
    SingleChoiceElement,
)
from cmk.rulesets.v1.rule_specs import AgentConfig, Topic


def _state_choice(title):
    return SingleChoice(
        title=Title(title),
        elements=[
            SingleChoiceElement(name="ok", title=Title("OK")),
            SingleChoiceElement(name="warn", title=Title("WARN")),
            SingleChoiceElement(name="crit", title=Title("CRIT")),
            SingleChoiceElement(name="unknown", title=Title("UNKNOWN")),
        ],
        prefill=DefaultValue("unknown"),
    )


def _range_form():
    return Dictionary(
        elements={
            "min": DictElement(
                required=True,
                parameter_form=Float(
                    title=Title("Minimum"),
                    prefill=DefaultValue(20.0),
                ),
            ),
            "max": DictElement(
                required=True,
                parameter_form=Float(
                    title=Title("Maximum"),
                    prefill=DefaultValue(40.0),
                ),
            ),
        }
    )


def _condition_choice():
    return CascadingSingleChoice(
        title=Title("Condition"),
        elements=[
            CascadingSingleChoiceElement(
                name="contains",
                title=Title("Text contains"),
                parameter_form=String(
                    title=Title("Text"),
                    prefill=DefaultValue("alive"),
                ),
            ),
            CascadingSingleChoiceElement(
                name="equals",
                title=Title("Text equals"),
                parameter_form=String(
                    title=Title("Text"),
                    prefill=DefaultValue("OK"),
                ),
            ),
            CascadingSingleChoiceElement(
                name="regex",
                title=Title("Regular expression"),
                parameter_form=String(
                    title=Title("Pattern"),
                    prefill=DefaultValue("alive"),
                ),
            ),
            CascadingSingleChoiceElement(
                name="startswith",
                title=Title("Text starts with"),
                parameter_form=String(
                    title=Title("Text"),
                    prefill=DefaultValue("OK"),
                ),
            ),
            CascadingSingleChoiceElement(
                name="endswith",
                title=Title("Text ends with"),
                parameter_form=String(
                    title=Title("Text"),
                    prefill=DefaultValue("OK"),
                ),
            ),
            CascadingSingleChoiceElement(
                name="less_than",
                title=Title("Numeric less than"),
                parameter_form=Float(
                    title=Title("Number"),
                    prefill=DefaultValue(40.0),
                ),
            ),
            CascadingSingleChoiceElement(
                name="less_equal",
                title=Title("Numeric less than or equal"),
                parameter_form=Float(
                    title=Title("Number"),
                    prefill=DefaultValue(40.0),
                ),
            ),
            CascadingSingleChoiceElement(
                name="greater_than",
                title=Title("Numeric greater than"),
                parameter_form=Float(
                    title=Title("Number"),
                    prefill=DefaultValue(80.0),
                ),
            ),
            CascadingSingleChoiceElement(
                name="greater_equal",
                title=Title("Numeric greater than or equal"),
                parameter_form=Float(
                    title=Title("Number"),
                    prefill=DefaultValue(80.0),
                ),
            ),
            CascadingSingleChoiceElement(
                name="between",
                title=Title("Numeric range inclusive"),
                parameter_form=_range_form(),
            ),
            CascadingSingleChoiceElement(
                name="outside",
                title=Title("Outside numeric range"),
                parameter_form=_range_form(),
            ),
        ],
        prefill=DefaultValue("contains"),
    )


def _parameter_form():
    return Dictionary(
        title=Title("File Content Check"),
        help_text=Help(
            "Configure local file content status checks for the Checkmk agent. "
            "Each check reads a local file and evaluates status rules in order."
        ),
        elements={
            "checks": DictElement(
                required=True,
                parameter_form=List(
                    title=Title("File content checks"),
                    element_template=Dictionary(
                        elements={
                            "service_prefix": DictElement(
                                required=True,
                                parameter_form=String(
                                    title=Title("Service name prefix"),
                                    prefill=DefaultValue("Content of"),
                                ),
                            ),
                            "service": DictElement(
                                required=True,
                                parameter_form=String(
                                    title=Title("Service name"),
                                    prefill=DefaultValue("Application Status"),
                                ),
                            ),
                            "file_path": DictElement(
                                required=True,
                                parameter_form=String(
                                    title=Title("File path"),
                                    prefill=DefaultValue("/var/www/html/status.html"),
                                ),
                            ),
                            "default_state": DictElement(
                                required=True,
                                parameter_form=_state_choice("State if no rule matches"),
                            ),
                            "status_rules": DictElement(
                                required=True,
                                parameter_form=List(
                                    title=Title("Status matching rules"),
                                    element_template=Dictionary(
                                        elements={
                                            "condition": DictElement(
                                                required=True,
                                                parameter_form=_condition_choice(),
                                            ),
                                            "state": DictElement(
                                                required=True,
                                                parameter_form=_state_choice("State"),
                                            ),
                                        }
                                    ),
                                ),
                            ),
                        }
                    ),
                ),
            ),
        },
    )


rule_spec_html_content_check_bakery = AgentConfig(
    name="html_content_check",
    title=Title("File Content Check"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form,
)
