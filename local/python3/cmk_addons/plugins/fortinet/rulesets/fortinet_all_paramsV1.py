#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
# ============================================================
#  _      _ _ ____            _
# | |    (_) |  _ \ ___  ___ | | __
# | |    | | | |_) / _ \/ _ \| |/ /
# | |____| | |  __/  __/  __/|   <
# |______|_|_|_|   \___|\___||_|\_\
#

#
# Author   : Lil_peek
# Version  : 1.0.0
# Created  : 2025-12-05
#
# ============================================================

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DictElement,
    Dictionary,
    Integer,
)
from cmk.rulesets.v1.rule_specs import (
    CheckParameters,
    Topic,
    HostCondition,
)


def _parameter_form_fortinet_all():
    return Dictionary(
        title=Title("Fortinet unified monitoring parameters"),
        help_text=Help("Global thresholds for Fortinet checks (CPU, memory, license)."),
        elements={
            "cpu_warn": DictElement(
                parameter_form=Integer(title=Title("CPU warning (%)"))
            ),
            "cpu_crit": DictElement(
                parameter_form=Integer(title=Title("CPU critical (%)"))
            ),
            "mem_warn": DictElement(
                parameter_form=Integer(title=Title("Memory warning (%)"))
            ),
            "mem_crit": DictElement(
                parameter_form=Integer(title=Title("Memory critical (%)"))
            ),
            "license_warn": DictElement(
                parameter_form=Integer(title=Title("License warning (days)"))
            ),
            "license_crit": DictElement(
                parameter_form=Integer(title=Title("License critical (days)"))
            ),
        },
    )


rule_spec_fortinet_all = CheckParameters(
    name="fortinet_all_params",
    title=Title("Fortinet Complete SNMP monitoring"),
    topic=Topic.NETWORKING,
    parameter_form=_parameter_form_fortinet_all,
    condition=HostCondition(),
)
