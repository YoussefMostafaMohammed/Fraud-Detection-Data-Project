import csv
import json
import os
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

from dotenv import load_dotenv
from kafka import KafkaProducer


load_dotenv(Path(__file__).with_name(".env"))

TOPIC = "vulnerability_events"
BOOTSTRAP_SERVERS = "127.0.0.1:9092"
SEND_INTERVAL_SECONDS = 2  
ASSET_INVENTORY_PATH = os.getenv(
    "ASSET_INVENTORY_PATH",
    r"./data/raw/asset_inventory.csv",
)


# ============================================
# REALISTIC CVE DATABASE - Hardcoded but real
# ============================================

CVES_BY_PRODUCT = {
    # --- Apache Products ---
    "tomcat": [
        {"cve_id": "CVE-2016-8735", "description": "Apache Tomcat remote code execution via JmxRemoteLifecycleListener.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.92, "known_exploited": True},
        {"cve_id": "CVE-2019-0232", "description": "Apache Tomcat CGI Servlet command injection on Windows.", "cvss_score": 8.1, "severity": "HIGH", "epss_score": 0.78, "known_exploited": True},
        {"cve_id": "CVE-2020-1938", "description": "Apache Tomcat AJP Connector file read/inclusion (Ghostcat).", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.95, "known_exploited": True},
        {"cve_id": "CVE-2021-33037", "description": "Apache Tomcat HTTP request smuggling via malformed trailer headers.", "cvss_score": 5.3, "severity": "MEDIUM", "epss_score": 0.12, "known_exploited": False},
        {"cve_id": "CVE-2022-34305", "description": "Apache Tomcat XSS vulnerability in examples web application.", "cvss_score": 6.1, "severity": "MEDIUM", "epss_score": 0.08, "known_exploited": False},
        {"cve_id": "CVE-2023-28708", "description": "Apache Tomcat session fixation vulnerability in FORM authentication.", "cvss_score": 5.3, "severity": "MEDIUM", "epss_score": 0.05, "known_exploited": False},
        {"cve_id": "CVE-2023-41080", "description": "Apache Tomcat Open Redirect vulnerability in FORM authentication.", "cvss_score": 6.1, "severity": "MEDIUM", "epss_score": 0.03, "known_exploited": False},
        {"cve_id": "CVE-2023-42795", "description": "Apache Tomcat information disclosure in recycling requests.", "cvss_score": 5.3, "severity": "MEDIUM", "epss_score": 0.02, "known_exploited": False},
        {"cve_id": "CVE-2023-45648", "description": "Apache Tomcat HTTP request smuggling in chunked transfer encoding.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.15, "known_exploited": False},
        {"cve_id": "CVE-2024-21733", "description": "Apache Tomcat denial of service via incomplete HTTP request.", "cvss_score": 5.3, "severity": "MEDIUM", "epss_score": 0.04, "known_exploited": False},
    ],
    "apache http server": [
        {"cve_id": "CVE-2017-9798", "description": "Apache HTTP Server OPTIONS method information disclosure.", "cvss_score": 5.3, "severity": "MEDIUM", "epss_score": 0.22, "known_exploited": False},
        {"cve_id": "CVE-2019-0211", "description": "Apache HTTP Server privilege escalation via scoreboard manipulation.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.45, "known_exploited": True},
        {"cve_id": "CVE-2021-41773", "description": "Apache HTTP Server path traversal and remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.97, "known_exploited": True},
        {"cve_id": "CVE-2021-42013", "description": "Apache HTTP Server path traversal in mod_proxy.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.88, "known_exploited": True},
        {"cve_id": "CVE-2022-26377", "description": "Apache HTTP Server mod_proxy request smuggling.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.18, "known_exploited": False},
        {"cve_id": "CVE-2022-31813", "description": "Apache HTTP Server mod_proxy X-Forwarded-For bypass.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.11, "known_exploited": False},
        {"cve_id": "CVE-2023-25690", "description": "Apache HTTP Server mod_proxy request splitting.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.35, "known_exploited": False},
        {"cve_id": "CVE-2023-27522", "description": "Apache HTTP Server mod_proxy response splitting.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.08, "known_exploited": False},
        {"cve_id": "CVE-2023-31124", "description": "Apache HTTP Server mod_lua buffer overflow.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.06, "known_exploited": False},
        {"cve_id": "CVE-2024-27316", "description": "Apache HTTP Server HTTP/2 CONTINUATION flood DoS.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.42, "known_exploited": False},
    ],

    # --- VMware Products ---
    "esxi": [
        {"cve_id": "CVE-2019-5544", "description": "VMware ESXi OpenSLP heap overflow remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.85, "known_exploited": True},
        {"cve_id": "CVE-2020-3992", "description": "VMware ESXi OpenSLP use-after-free remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.78, "known_exploited": True},
        {"cve_id": "CVE-2021-21974", "description": "VMware ESXi OpenSLP heap overflow ( ransomware target ).", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.94, "known_exploited": True},
        {"cve_id": "CVE-2022-31696", "description": "VMware ESXi XHCI USB controller heap buffer overflow.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.15, "known_exploited": False},
        {"cve_id": "CVE-2023-20867", "description": "VMware ESXi authentication bypass in vCenter plugin.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.22, "known_exploited": False},
        {"cve_id": "CVE-2023-34048", "description": "VMware ESXi DCERPC protocol heap overflow.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.55, "known_exploited": True},
        {"cve_id": "CVE-2023-34049", "description": "VMware ESXi DCERPC protocol use-after-free.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.38, "known_exploited": False},
        {"cve_id": "CVE-2024-22252", "description": "VMware ESXi XHCI USB controller use-after-free.", "cvss_score": 8.4, "severity": "HIGH", "epss_score": 0.12, "known_exploited": False},
        {"cve_id": "CVE-2024-22253", "description": "VMware ESXi XHCI USB controller double-fetch vulnerability.", "cvss_score": 8.4, "severity": "HIGH", "epss_score": 0.09, "known_exploited": False},
    ],
    "vcenter": [
        {"cve_id": "CVE-2021-21972", "description": "VMware vCenter Server remote code execution via vSphere Client.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.96, "known_exploited": True},
        {"cve_id": "CVE-2021-21985", "description": "VMware vCenter Server remote code execution in Virtual SAN Health Check.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.92, "known_exploited": True},
        {"cve_id": "CVE-2021-22005", "description": "VMware vCenter Server arbitrary file upload to RCE.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.88, "known_exploited": True},
        {"cve_id": "CVE-2022-22948", "description": "VMware vCenter Server local privilege escalation.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.25, "known_exploited": False},
        {"cve_id": "CVE-2022-22972", "description": "VMware vCenter Server authentication bypass.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.72, "known_exploited": True},
        {"cve_id": "CVE-2023-34039", "description": "VMware vCenter Server SSH authentication bypass.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.45, "known_exploited": True},
        {"cve_id": "CVE-2023-34060", "description": "VMware vCenter Server DCERPC protocol heap overflow.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.33, "known_exploited": False},
        {"cve_id": "CVE-2024-22274", "description": "VMware vCenter Server local privilege escalation.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.08, "known_exploited": False},
    ],

    # --- Microsoft Products ---
    "exchange server": [
        {"cve_id": "CVE-2020-0688", "description": "Microsoft Exchange Server remote code execution via serialized data.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.91, "known_exploited": True},
        {"cve_id": "CVE-2021-26855", "description": "Microsoft Exchange Server SSRF vulnerability (ProxyLogon).", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.98, "known_exploited": True},
        {"cve_id": "CVE-2021-26857", "description": "Microsoft Exchange Server deserialization RCE (ProxyLogon).", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.95, "known_exploited": True},
        {"cve_id": "CVE-2021-27065", "description": "Microsoft Exchange Server arbitrary file write (ProxyLogon).", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.93, "known_exploited": True},
        {"cve_id": "CVE-2021-28480", "description": "Microsoft Exchange Server remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.87, "known_exploited": True},
        {"cve_id": "CVE-2021-34473", "description": "Microsoft Exchange Server remote code execution (ProxyShell).", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.96, "known_exploited": True},
        {"cve_id": "CVE-2021-34523", "description": "Microsoft Exchange Server elevation of privilege (ProxyShell).", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.94, "known_exploited": True},
        {"cve_id": "CVE-2021-31207", "description": "Microsoft Exchange Server security feature bypass (ProxyShell).", "cvss_score": 7.4, "severity": "HIGH", "epss_score": 0.89, "known_exploited": True},
        {"cve_id": "CVE-2022-41040", "description": "Microsoft Exchange Server SSRF vulnerability (ProxyNotShell).", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.82, "known_exploited": True},
        {"cve_id": "CVE-2022-41082", "description": "Microsoft Exchange Server remote code execution (ProxyNotShell).", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.85, "known_exploited": True},
        {"cve_id": "CVE-2023-21716", "description": "Microsoft Exchange Server remote code execution via SmartScreen.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.45, "known_exploited": False},
        {"cve_id": "CVE-2023-36745", "description": "Microsoft Exchange Server remote code execution.", "cvss_score": 8.0, "severity": "HIGH", "epss_score": 0.28, "known_exploited": False},
        {"cve_id": "CVE-2024-21410", "description": "Microsoft Exchange Server privilege escalation via NTLM relay.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.52, "known_exploited": True},
    ],
    "windows server": [
        {"cve_id": "CVE-2019-0708", "description": "Microsoft Windows Server RDP BlueKeep remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.95, "known_exploited": True},
        {"cve_id": "CVE-2020-1472", "description": "Microsoft Windows Server Netlogon elevation of privilege (Zerologon).", "cvss_score": 10.0, "severity": "CRITICAL", "epss_score": 0.97, "known_exploited": True},
        {"cve_id": "CVE-2021-34527", "description": "Microsoft Windows Server Print Spooler remote code execution (PrintNightmare).", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.94, "known_exploited": True},
        {"cve_id": "CVE-2021-36942", "description": "Microsoft Windows Server LSA spoofing vulnerability.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.35, "known_exploited": False},
        {"cve_id": "CVE-2022-26809", "description": "Microsoft Windows Server RPC runtime remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.72, "known_exploited": True},
        {"cve_id": "CVE-2022-37958", "description": "Microsoft Windows Server SPNEGO NEGOEX remote code execution.", "cvss_score": 8.1, "severity": "HIGH", "epss_score": 0.28, "known_exploited": False},
        {"cve_id": "CVE-2023-21716", "description": "Microsoft Windows Server SmartScreen remote code execution.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.42, "known_exploited": False},
        {"cve_id": "CVE-2023-36745", "description": "Microsoft Windows Server Exchange remote code execution.", "cvss_score": 8.0, "severity": "HIGH", "epss_score": 0.18, "known_exploited": False},
        {"cve_id": "CVE-2024-21413", "description": "Microsoft Windows Server Outlook remote code execution (MonikerLink).", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.65, "known_exploited": True},
    ],
    "sql server": [
        {"cve_id": "CVE-2019-1068", "description": "Microsoft SQL Server remote code execution via reporting services.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.55, "known_exploited": False},
        {"cve_id": "CVE-2020-0618", "description": "Microsoft SQL Server reporting services remote code execution.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.48, "known_exploited": True},
        {"cve_id": "CVE-2020-0615", "description": "Microsoft SQL Server elevation of privilege.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.22, "known_exploited": False},
        {"cve_id": "CVE-2021-1636", "description": "Microsoft SQL Server remote code execution via OLE DB provider.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.35, "known_exploited": False},
        {"cve_id": "CVE-2022-29143", "description": "Microsoft SQL Server Linked Server remote code execution.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.18, "known_exploited": False},
        {"cve_id": "CVE-2023-23384", "description": "Microsoft SQL Server remote code execution via SQL Server Agent.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.12, "known_exploited": False},
        {"cve_id": "CVE-2024-21364", "description": "Microsoft SQL Server remote code execution via OLE DB.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.08, "known_exploited": False},
    ],

    # --- Cisco Products ---
    "asa": [
        {"cve_id": "CVE-2018-0296", "description": "Cisco ASA/FTD denial of service via crafted HTTP request.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.65, "known_exploited": True},
        {"cve_id": "CVE-2020-3259", "description": "Cisco ASA/FTD information disclosure via directory traversal.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.55, "known_exploited": True},
        {"cve_id": "CVE-2020-3452", "description": "Cisco ASA/FTD arbitrary file read via directory traversal.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.78, "known_exploited": True},
        {"cve_id": "CVE-2023-20269", "description": "Cisco ASA unauthorized IPSec tunnel establishment.", "cvss_score": 5.3, "severity": "MEDIUM", "epss_score": 0.15, "known_exploited": False},
        {"cve_id": "CVE-2024-20399", "description": "Cisco ASA/FTD command injection in CLI.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.22, "known_exploited": False},
    ],
    "ios xe": [
        {"cve_id": "CVE-2023-20198", "description": "Cisco IOS XE Web UI privilege escalation (CiscoTalos).", "cvss_score": 10.0, "severity": "CRITICAL", "epss_score": 0.98, "known_exploited": True},
        {"cve_id": "CVE-2023-20273", "description": "Cisco IOS XE Web UI command injection.", "cvss_score": 7.2, "severity": "HIGH", "epss_score": 0.85, "known_exploited": True},
        {"cve_id": "CVE-2023-20109", "description": "Cisco IOS XE Group Encrypted Transport VPN buffer overflow.", "cvss_score": 8.6, "severity": "HIGH", "epss_score": 0.35, "known_exploited": False},
        {"cve_id": "CVE-2024-20345", "description": "Cisco IOS XE Smart Licensing buffer overflow.", "cvss_score": 8.6, "severity": "HIGH", "epss_score": 0.12, "known_exploited": False},
        {"cve_id": "CVE-2024-20353", "description": "Cisco IOS XE denial of service via crafted packets.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.08, "known_exploited": False},
    ],
    "meraki": [
        {"cve_id": "CVE-2020-16138", "description": "Cisco Meraki MX buffer overflow in VPN concentrator.", "cvss_score": 8.1, "severity": "HIGH", "epss_score": 0.25, "known_exploited": False},
        {"cve_id": "CVE-2021-1497", "description": "Cisco Meraki MX VPN concentrator command injection.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.42, "known_exploited": True},
        {"cve_id": "CVE-2022-20650", "description": "Cisco Meraki MX content filtering bypass.", "cvss_score": 5.3, "severity": "MEDIUM", "epss_score": 0.08, "known_exploited": False},
        {"cve_id": "CVE-2023-20073", "description": "Cisco Meraki MX firmware integrity verification bypass.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.05, "known_exploited": False},
    ],

    # --- Oracle Products ---
    "oracle db": [
        {"cve_id": "CVE-2018-3110", "description": "Oracle Database Java VM remote code execution.", "cvss_score": 9.9, "severity": "CRITICAL", "epss_score": 0.55, "known_exploited": True},
        {"cve_id": "CVE-2019-2551", "description": "Oracle Database TNS Listener remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.48, "known_exploited": True},
        {"cve_id": "CVE-2020-14734", "description": "Oracle Database Spatial component remote code execution.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.22, "known_exploited": False},
        {"cve_id": "CVE-2021-2356", "description": "Oracle Database Enterprise Manager remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.35, "known_exploited": False},
        {"cve_id": "CVE-2022-21547", "description": "Oracle Database Java VM remote code execution.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.18, "known_exploited": False},
        {"cve_id": "CVE-2023-21839", "description": "Oracle Database TNS Listener remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.42, "known_exploited": True},
        {"cve_id": "CVE-2023-22074", "description": "Oracle Database Java VM remote code execution.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.15, "known_exploited": False},
        {"cve_id": "CVE-2024-20918", "description": "Oracle Database OJVM remote code execution.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.08, "known_exploited": False},
    ],
    "weblogic": [
        {"cve_id": "CVE-2019-2725", "description": "Oracle WebLogic Server deserialization remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.92, "known_exploited": True},
        {"cve_id": "CVE-2020-2551", "description": "Oracle WebLogic Server IIOP deserialization remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.88, "known_exploited": True},
        {"cve_id": "CVE-2020-2883", "description": "Oracle WebLogic Server T3 protocol deserialization.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.85, "known_exploited": True},
        {"cve_id": "CVE-2021-2109", "description": "Oracle WebLogic Server JNDI injection remote code execution.", "cvss_score": 7.2, "severity": "HIGH", "epss_score": 0.72, "known_exploited": True},
        {"cve_id": "CVE-2021-2394", "description": "Oracle WebLogic Server JNDI injection via T3 protocol.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.68, "known_exploited": True},
        {"cve_id": "CVE-2022-21371", "description": "Oracle WebLogic Server path traversal information disclosure.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.25, "known_exploited": False},
        {"cve_id": "CVE-2023-21839", "description": "Oracle WebLogic Server T3/IIOP protocol remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.55, "known_exploited": True},
        {"cve_id": "CVE-2023-21931", "description": "Oracle WebLogic Server JNDI injection remote code execution.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.18, "known_exploited": False},
        {"cve_id": "CVE-2024-20931", "description": "Oracle WebLogic Server T3 protocol deserialization.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.12, "known_exploited": False},
    ],

    # --- Linux Distributions ---
    "ubuntu": [
        {"cve_id": "CVE-2021-3493", "description": "Ubuntu OverlayFS privilege escalation.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.65, "known_exploited": True},
        {"cve_id": "CVE-2021-3490", "description": "Ubuntu eBPF ALU32 bounds tracking vulnerability.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.42, "known_exploited": False},
        {"cve_id": "CVE-2022-0847", "description": "Ubuntu Dirty Pipe privilege escalation (Linux kernel).", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.88, "known_exploited": True},
        {"cve_id": "CVE-2022-0185", "description": "Ubuntu Linux kernel file system context heap overflow.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.35, "known_exploited": False},
        {"cve_id": "CVE-2023-0386", "description": "Ubuntu OverlayFS privilege escalation via FUSE.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.55, "known_exploited": True},
        {"cve_id": "CVE-2023-32629", "description": "Ubuntu Linux kernel use-after-free in netfilter subsystem.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.22, "known_exploited": False},
        {"cve_id": "CVE-2024-1086", "description": "Ubuntu Linux kernel use-after-free in nf_tables.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.45, "known_exploited": True},
    ],
    "centos": [
        {"cve_id": "CVE-2020-14386", "description": "CentOS Linux kernel af_packet memory corruption.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.38, "known_exploited": False},
        {"cve_id": "CVE-2021-3156", "description": "CentOS sudo heap buffer overflow (Baron Samedit).", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.92, "known_exploited": True},
        {"cve_id": "CVE-2021-4034", "description": "CentOS polkit pkexec privilege escalation (PwnKit).", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.95, "known_exploited": True},
        {"cve_id": "CVE-2022-22965", "description": "CentOS Spring Framework remote code execution (Spring4Shell).", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.82, "known_exploited": True},
        {"cve_id": "CVE-2022-25636", "description": "CentOS Linux kernel netfilter heap out-of-bounds write.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.28, "known_exploited": False},
        {"cve_id": "CVE-2023-38408", "description": "CentOS OpenSSH agent forwarding remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.45, "known_exploited": True},
        {"cve_id": "CVE-2024-2961", "description": "CentOS glibc iconv buffer overflow.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.15, "known_exploited": False},
    ],
    "redhat": [
        {"cve_id": "CVE-2019-14287", "description": "Red Hat sudo privilege escalation via Runas specification.", "cvss_score": 8.8, "severity": "HIGH", "epss_score": 0.78, "known_exploited": True},
        {"cve_id": "CVE-2021-3560", "description": "Red Hat polkit local privilege escalation.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.55, "known_exploited": True},
        {"cve_id": "CVE-2022-22965", "description": "Red Hat Spring Framework remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.82, "known_exploited": True},
        {"cve_id": "CVE-2022-3786", "description": "Red Hat OpenSSL X.509 email address buffer overflow.", "cvss_score": 7.5, "severity": "HIGH", "epss_score": 0.35, "known_exploited": False},
        {"cve_id": "CVE-2023-38408", "description": "Red Hat OpenSSH agent forwarding remote code execution.", "cvss_score": 9.8, "severity": "CRITICAL", "epss_score": 0.45, "known_exploited": True},
        {"cve_id": "CVE-2023-4911", "description": "Red Hat glibc ld.so buffer overflow (Looney Tunables).", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.52, "known_exploited": True},
        {"cve_id": "CVE-2024-1086", "description": "Red Hat Linux kernel nf_tables use-after-free.", "cvss_score": 7.8, "severity": "HIGH", "epss_score": 0.45, "known_exploited": True},
    ],
}


def normalize_text(value):
    return str(value or "").strip()


def load_assets_from_csv(path):
    assets = []

    with open(path, mode="r", encoding="utf-8-sig", newline="") as file_obj:
        reader = csv.DictReader(file_obj)
        for row in reader:
            asset = {
                "asset_id": normalize_text(row.get("asset_id")),
                "hostname": normalize_text(row.get("hostname")),
                "vendor": normalize_text(row.get("vendor")).lower(),
                "product": normalize_text(row.get("product")).lower(),
                "version": normalize_text(row.get("version")),
                "criticality": normalize_text(row.get("criticality")),
                "internet_facing": normalize_text(row.get("internet_facing")),
            }

            if asset["asset_id"] and asset["product"] in CVES_BY_PRODUCT:
                assets.append(asset)

    if not assets:
        supported = ", ".join(sorted(CVES_BY_PRODUCT))
        raise RuntimeError(
            f"No supported assets found in {path}. Supported products: {supported}"
        )

    return assets


def current_timestamp():
    """FIXED: Generate current UTC timestamp for real-time streaming"""
    return datetime.now(timezone.utc).isoformat()


def build_event(assets):
    asset = random.choice(assets)
    cve = random.choice(CVES_BY_PRODUCT[asset["product"]])

    event = {
        "event_id": str(uuid.uuid4()),
        "source": "streaming_scanner",
        "detected_at": current_timestamp(),  # FIXED: Use current time, not random historical date
        **asset,
        **cve,
    }
    return event


def main():
    assets = load_assets_from_csv(ASSET_INVENTORY_PATH)

    producer = KafkaProducer(
        bootstrap_servers=BOOTSTRAP_SERVERS,
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
        api_version_auto_timeout_ms=10000,
        request_timeout_ms=30000,
        max_block_ms=60000,
        metadata_max_age_ms=5000,
        retries=3,
    )

    print(f"Producer started. Topic={TOPIC}, bootstrap={BOOTSTRAP_SERVERS}", flush=True)
    print(f"Kafka connected: {producer.bootstrap_connected()}", flush=True)
    print(f"Asset inventory file: {ASSET_INVENTORY_PATH}", flush=True)
    print(f"Loaded supported assets: {len(assets)}", flush=True)
    print(f"Total CVEs in database: {sum(len(v) for v in CVES_BY_PRODUCT.values())}", flush=True)
    print(f"Kafka partitions for {TOPIC}: {producer.partitions_for(TOPIC)}", flush=True)

    while True:
        try:
            event = build_event(assets)
            metadata = producer.send(TOPIC, event).get(timeout=20)
            producer.flush()

            print(
                f"sent topic={metadata.topic} partition={metadata.partition} "
                f"offset={metadata.offset}: asset_id={event['asset_id']}, "
                f"cve_id={event['cve_id']}, detected_at={event['detected_at']}",
                flush=True,
            )
            time.sleep(SEND_INTERVAL_SECONDS)
        except Exception as exc:
            print(f"FAILED to send Kafka message: {type(exc).__name__}: {exc}", flush=True)
            time.sleep(SEND_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()