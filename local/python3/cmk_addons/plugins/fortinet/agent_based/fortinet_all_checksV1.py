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

from cmk.plugins.lib.fortinet import DETECT_FORTIGATE
from datetime import datetime
from cmk.agent_based.v2 import (
    CheckPlugin,
    SimpleSNMPSection,
    SNMPTree,
    OIDEnd,
    StringTable,
    DiscoveryResult,
    Service,
    Result,
    State,
    Metric,
    startswith,
)

# ========================================================================
#                           SD-WAN SECTION
# ========================================================================

def parse_sdwan(string_table: StringTable):
    sdwan = {}
    for row in string_table:
        if len(row) == 8:
            idx = row[0]
            sdwan[idx] = {
                "name":   row[1],
                "member": row[2],
                "vdom":   row[3],
                "health": row[4],
                "latency":row[5],
                "jitter": row[6],
                "loss":   row[7],
            }
    return sdwan


snmp_section_sdwan = SimpleSNMPSection(
    name="fortinet_sdwan",
    parse_function=parse_sdwan,
    detect=DETECT_FORTIGATE,
    fetch=SNMPTree(
        base=".1.3.6.1.4.1.12356.101.4.9.2.1",
        oids=[
            OIDEnd(),
            "2",
            "14",
            "10",
            "4",
            "5",
            "6",
            "9",
        ],
    ),
)

# ========================================================================
#                           LICENSE SECTION
# ========================================================================

def parse_license(string_table: StringTable):
    lic = {}
    for row in string_table:
        if len(row) == 2:
            lic[row[0]] = row[1]
    return lic


snmp_section_license = SimpleSNMPSection(
    name="fortinet_license",
    parse_function=parse_license,
    detect=DETECT_FORTIGATE,
    fetch=SNMPTree(
        base=".1.3.6.1.4.1.12356.101.4.6.3.1.2.1",
        oids=[OIDEnd(), "2"],
    ),
)
# ========================================================================
#                           CLUSTER SECTION
# ========================================================================

def parse_cluster(string_table: StringTable):
    cl = {}
    for row in string_table:
        if len(row) == 8:
            cl[row[0]] = {
                "serial":    row[1],
                "cpu":       row[2],
                "memory":    row[3],
                "bandwidth": row[4],
                "sessions":  row[5],
                "av":        row[6],
                "ips":       row[7],
            }
    return cl


snmp_section_cluster = SimpleSNMPSection(
    name="fortinet_cluster",
    parse_function=parse_cluster,
    detect=DETECT_FORTIGATE,
    fetch=SNMPTree(
        base=".1.3.6.1.4.1.12356.101.13.2.1.1",
        oids=[OIDEnd(), "2", "3", "4", "5", "6", "10", "9"],
    ),
)

# ========================================================================
#                           DISCOVERY
# ========================================================================

def discover_fortinet_all(section_fortinet_sdwan,
                          section_fortinet_license,
                          section_fortinet_cluster):

    if section_fortinet_sdwan:
        for idx, d in section_fortinet_sdwan.items():
            base = f"{d['name']} on SD-WAN member {d['member']}"

            yield Service(item=f"SD-WAN health to {base}")
            yield Service(item=f"SD-WAN latency to {base}")
            yield Service(item=f"SD-WAN jitter to {base}")
            yield Service(item=f"SD-WAN packet loss to {base}")

    if section_fortinet_license:
        for idx in section_fortinet_license:
            yield Service(item=f"License {idx}")

    if section_fortinet_cluster:
        for idx in section_fortinet_cluster:
            yield Service(item=f"CPU usage unit {idx}")
            yield Service(item=f"Memory usage unit {idx}")
            yield Service(item=f"Bandwidth unit {idx}")
            yield Service(item=f"Sessions unit {idx}")
            yield Service(item=f"AV events unit {idx}")
            yield Service(item=f"IPS events unit {idx}")
            yield Service(item=f"Serial number unit {idx}")

# ========================================================================
#                           CHECK FUNCTION
# ========================================================================

def check_fortinet_all(item, params,
                       section_fortinet_sdwan,
                       section_fortinet_license,
                       section_fortinet_cluster):


    sdwan   = section_fortinet_sdwan
    license = section_fortinet_license
    cluster = section_fortinet_cluster

    item_l = item.lower()

    # =====================================================================
    #                             SD-WAN
    # =====================================================================

    if item_l.startswith("sd-wan "):

        temp = item.split(" to ", 1)[1]
        hc_name, member_part = temp.split(" on SD-WAN member ", 1)

        idx = None
        data = None
        for i, d in sdwan.items():
            if d["name"] == hc_name and d["member"] == member_part:
                idx = i
                data = d
                break

        if idx is None:
            yield Result(state=State.UNKNOWN, summary="SD-WAN entry not found")
            return

        if "health" in item_l:
            val = int(data["health"])
            if val == 0:
                yield Result(state=State.OK,
                             summary=f"Health Check to {hc_name} on SD-WAN member {member_part}: OK")
            else:
                yield Result(state=State.CRIT,
                             summary=f"Health Check to {hc_name} on SD-WAN member {member_part}: CRITICAL")
            return

        if "latency" in item_l:
            val = float(data["latency"])
            yield Result(state=State.OK,
                         summary=f"Latency to {hc_name} on SD-WAN member {member_part}: {val} ms")
            yield Metric("latency_ms", val)
            return

        if "jitter" in item_l:
            val = float(data["jitter"])
            yield Result(state=State.OK,
                         summary=f"Jitter to {hc_name} on SD-WAN member {member_part}: {val} ms")
            yield Metric("jitter_ms", val)
            return

        if "packet loss" in item_l:
            val = float(data["loss"])
            yield Result(state=State.OK,
                         summary=f"Packet loss to {hc_name} on SD-WAN member {member_part}: {val}%")
            yield Metric("loss_percent", val)
            return
    # =====================================================================
    #                             LICENSE
    # =====================================================================

    if item_l.startswith("license "):
        idx = item.split(" ")[1]
        raw_date = license[idx]

        exp_date = datetime.strptime(raw_date, "%a %b %d %H:%M:%S %Y")
        days = (exp_date - datetime.now()).days

        warn_days = params.get("license_warn", 30)
        crit_days = params.get("license_crit", 0)

        if days <= crit_days:
            yield Result(state=State.CRIT, summary=f"License {idx}: EXPIRED")
        elif days <= warn_days:
            yield Result(state=State.WARN, summary=f"License {idx}: expiring in {days} days")
        else:
            yield Result(state=State.OK, summary=f"License {idx}: {days} days remaining")

        yield Metric("license_days", days)
        return

    # =====================================================================
    #                             CLUSTER
    # =====================================================================

    idx = item.split(" ")[-1]
    d = cluster.get(idx)

    if d is None:
        yield Result(state=State.UNKNOWN, summary="Cluster entry missing")
        return

    # =============================== CPU ================================
    if item_l.startswith("cpu usage"):
        val = int(d["cpu"])
        cpu_warn = params.get("cpu_warn", 80)
        cpu_crit = params.get("cpu_crit", 95)

        if val >= cpu_crit: st = State.CRIT
        elif val >= cpu_warn: st = State.WARN
        else: st = State.OK

        yield Result(state=st, summary=f"CPU usage unit {idx}: {val}%")
        yield Metric("cpu_percent", val)
        return

    # =============================== MEMORY =============================
    if item_l.startswith("memory usage"):
        val = int(d["memory"])
        mem_warn = params.get("mem_warn", 80)
        mem_crit = params.get("mem_crit", 85)

        if val >= mem_crit: st = State.CRIT
        elif val >= mem_warn: st = State.WARN
        else: st = State.OK

        yield Result(state=st, summary=f"Memory usage unit {idx}: {val}%")
        yield Metric("mem_percent", val)
        return

    # =============================== BANDWIDTH ===========================
    if item_l.startswith("bandwidth"):
        val = int(d["bandwidth"])
        yield Result(state=State.OK, summary=f"Bandwidth unit {idx}: {val}")
        yield Metric("bandwidth", val)
        return

    # =============================== SESSIONS ============================
    if item_l.startswith("sessions"):
        val = int(d["sessions"])
        yield Result(state=State.OK, summary=f"Sessions unit {idx}: {val}")
        yield Metric("sessions", val)
        return

    # =============================== AV EVENTS ===========================
    if item_l.startswith("av events"):
        val = int(d["av"])
        yield Result(state=State.OK, summary=f"AV events unit {idx}: {val}")
        yield Metric("av_events", val)
        return

    # =============================== IPS EVENTS ==========================
    if item_l.startswith("ips events"):
        val = int(d["ips"])
        yield Result(state=State.OK, summary=f"IPS events unit {idx}: {val}")
        yield Metric("ips_events", val)
        return

    # =============================== SERIAL ==============================
    if item_l.startswith("serial number"):
        sn = d["serial"]
        if len(sn.strip()) == 0:
            yield Result(state=State.CRIT, summary=f"Serial number unit {idx}: MISSING!")
        else:
            yield Result(state=State.OK, summary=f"Serial number unit {idx}: {sn}")
        return


# ========================================================================
#                           REGISTER PLUGIN
# ========================================================================

check_plugin_fortinet_all = CheckPlugin(
    name="fortinet_all_checks",
    sections=["fortinet_sdwan", "fortinet_license", "fortinet_cluster"],
    service_name="Fortinet %s",
    discovery_function=discover_fortinet_all,
    check_function=check_fortinet_all,
    check_default_parameters={
        "cpu_warn": 80,
        "cpu_crit": 95,
        "mem_warn": 80,
        "mem_crit": 85,
        "license_warn": 30,
        "license_crit": 0,
    },
    check_ruleset_name="fortinet_all_params",
)
