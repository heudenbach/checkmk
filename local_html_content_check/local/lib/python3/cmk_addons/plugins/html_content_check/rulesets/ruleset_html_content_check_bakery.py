#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cmk.rulesets.v1 import Title, Help
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
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


def _parameter_form():
    return Dictionary(
        title=Title("HTML content checks"),
        help_text=Help("Configure local HTML content status checks for the Checkmk agent."),
        elements={
            "config_dir": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("Configuration directory"),
                    prefill=DefaultValue("/etc/check_mk"),
                ),
            ),
    
            "checks": DictElement(
                required=True,
                parameter_form=List(
                    title=Title("HTML content checks"),
                    element_template=Dictionary(
                        elements={
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
                                    title=Title("HTML file path"),
                                    prefill=DefaultValue("/var/www/html/status.html"),
                                ),
                            ),
                            "mode": DictElement(
                                required=True,
                                parameter_form=SingleChoice(
                                    title=Title("Match mode"),
                                    elements=[
                                        SingleChoiceElement(
                                            name="contains",
                                            title=Title("Plain text contains"),
                                        ),
                                        SingleChoiceElement(
                                            name="regex",
                                            title=Title("Regular expression"),
                                        ),
                                    ],
                                    prefill=DefaultValue("contains"),
                                ),
                            ),
                            "default_state": DictElement(
                                required=True,
                                parameter_form=_state_choice("State if no pattern matches"),
                            ),
                            "status_rules": DictElement(
                                required=True,
                                parameter_form=List(
                                    title=Title("Status matching rules"),
                                    element_template=Dictionary(
                                        elements={
                                            "pattern": DictElement(
                                                required=True,
                                                parameter_form=String(
                                                    title=Title("Pattern"),
                                                    prefill=DefaultValue("Alive"),
                                                ),
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
    title=Title("HTML content checks"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form,
)
