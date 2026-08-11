#!/usr/bin/env python3

from cmk.rulesets.v1 import Title
from cmk.rulesets.v1.form_specs import Dictionary
from cmk.rulesets.v1.rule_specs import AgentConfig, Topic


def _parameter_form_trivy_bakery():
    return Dictionary(
        elements={}
    )


rule_spec_trivy_bakery = AgentConfig(
    name="trivy_report_bakery",
    title=Title("Deploy Trivy Report agent plugin"),
    topic=Topic.GENERAL,
    parameter_form=_parameter_form_trivy_bakery,
)