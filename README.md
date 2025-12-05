# CheckMK-Fortinet-Complete-SNMP-Checks

This plugin checks the following SNMP branches creating a service for each OID that is discovered:



Health Check State to {#HC_NAME} on SD-WAN member {#MEMBER_SEQ}
1.3.6.1.4.1.12356.101.4.9.2.1.4.{#HC_ID}
Heatlth check state on a specific member link
 
Jitter to {#HC_NAME} on SD-WAN member {#MEMBER_SEQ}
1.3.6.1.4.1.12356.101.4.9.2.1.6.{#HC_ID}
 
Latency to {#HC_NAME} on SD-WAN member {#MEMBER_SEQ}
1.3.6.1.4.1.12356.101.4.9.2.1.5.{#HC_ID}
 
Packet Loss to {#HC_NAME} on SD-WAN member {#MEMBER_SEQ}
1.3.6.1.4.1.12356.101.4.9.2.1.9.{#HC_ID}

Expiry Licence {#SNMPVALUE}
.1.3.6.1.4.1.12356.101.4.6.3.1.2.1.2.{#SNMPINDEX}

CPU usage for cluster unit $1
.1.3.6.1.4.1.12356.101.13.2.1.1.3.{#SNMPINDEX}
 
Current session count for cluster unit $1
.1.3.6.1.4.1.12356.101.13.2.1.1.6.{#SNMPINDEX}
 
Memory usage for cluster unit $1
.1.3.6.1.4.1.12356.101.13.2.1.1.4.{#SNMPINDEX}
 
Network bandwidth usage for unit $1
.1.3.6.1.4.1.12356.101.13.2.1.1.5.{#SNMPINDEX}
 
Number of anti-virus events triggered on cluster unit $1
.1.3.6.1.4.1.12356.101.13.2.1.1.10.{#SNMPINDEX}
 
Number of IDS/IPS events triggered on cluster unit $1
.1.3.6.1.4.1.12356.101.13.2.1.1.9.{#SNMPINDEX}
 
Serial Number - $1
.1.3.6.1.4.1.12356.101.13.2.1.1.2.{#SNMPINDEX}




Definition of 
{#HC_ID}: 1.3.6.1.4.1.12356.101.4.9.2.1.1,
{#HC_NAME},1.3.6.1.4.1.12356.101.4.9.2.1.2,
{#MEMBER_SEQ},1.3.6.1.4.1.12356.101.4.9.2.1.14,
{#VDOM},1.3.6.1.4.1.12356.101.4.9.2.1.10




Detection of Fortinet product is done with the DETECT_FORTIGATE function defined in omd/sites/<your site>/lib/python3/cmk/plugins/lib/:

DETECT_FORTIGATE = startswith(".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.12356.101.1.")


A ruleset is also created, to make it possible to change thresholds that are defined initially as default:

"cpu_warn": 80,
"cpu_crit": 95,
"mem_warn": 80,
"mem_crit": 85,
"license_warn": 30,
"license_crit": 0


The ruleset can be found as "Fortinet Complete SNMP monitoring"
