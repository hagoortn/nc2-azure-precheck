#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NC2 on Azure - landing zone pre-check
=====================================

Validates an Azure subscription / landing zone against the published
"Requirements for NC2 on Azure" before an NC2 cluster is deployed.

Run it in Azure Cloud Shell (Bash or PowerShell):

    python3 nc2-azure-precheck.py

Everything is read-only, EXCEPT the optional in-VNet connectivity test, which
creates a temporary resource group with one small Ubuntu VM per tested subnet
(no public IP), runs the outbound tests from inside your VNets, and deletes
the resource group again.

Source requirements: Nutanix "Requirements for NC2 on Azure" (last updated
2026-11-11) plus the related pages on resource providers, the NC2 custom role
and Azure Policy exemptions.
"""

import argparse
import base64
import concurrent.futures as cf
import datetime as dt
import fnmatch
import html
import ipaddress
import json
import os
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile

VERSION = "1.0.0"
DOC_URL = ("https://portal.nutanix.com/page/documents/details?targetId="
           "Nutanix-Cloud-Clusters-Azure:nc2-clusters-azure-requirements-for-nc2-on-azure-c.html")
DOC_DATE = "2026-11-11"
DELEGATION = "Microsoft.BareMetal/AzureHostedService"
CVM_INTERNAL_NET = ipaddress.ip_network("192.168.5.0/24")

# --------------------------------------------------------------------------
# Requirement data (from the Nutanix documentation)
# --------------------------------------------------------------------------

# Flow Gateway VM types. v5 is recommended, v4 is supported.
FGW_SKUS = {
    "small": {"v5": ("Standard_D4_v5", "standardDv5Family", 4),
              "v4": ("Standard_D4_v4", "standardDv4Family", 4)},
    "large": {"v5": ("Standard_D32_v5", "standardDv5Family", 32),
              "v4": ("Standard_D32_v4", "standardDv4Family", 32)},
}
# BGP gateway VMs (only with Azure Route Server / dynamic routing): 2 VMs.
BGP_PRIMARY = ("Standard_D8s_v5", "standardDSv5Family", 8)
BGP_FALLBACK = ("Standard_D3_v2", "standardDv2Family", 4)
BGP_COUNT = 2

# Outbound endpoints. "roles" = subnets the doc lists as source.
#   mgmt = cluster management subnet (tested from the PC subnet, see README)
#   fgw  = Flow Gateway subnet, bgp = BGP subnet
HTTPS_ENDPOINTS = [
    ("portal.nutanix.com", "/", "Nutanix service portal", {"mgmt", "fgw", "bgp"}),
    ("licensing-api.nutanix.com", "/", "Nutanix licensing", {"mgmt", "fgw", "bgp"}),
    ("downloads.cloud.nutanix.com", "/", "LCM / NC2 RPM downloads", {"mgmt", "fgw", "bgp"}),
    ("insights.nutanix.com", "/", "Pulse", {"mgmt", "fgw", "bgp"}),
    ("gateway-external-api.cloud.nutanix.com", "/", "NC2 console orchestration", {"mgmt", "fgw", "bgp"}),
    ("apikeys.nutanix.com", "/", "Prism Central API key registration", {"mgmt", "fgw", "bgp"}),
    ("management.azure.com", "/", "Azure Resource Manager API", {"mgmt", "fgw", "bgp"}),
    ("clusters-public-images.s3.us-west-2.amazonaws.com", "/azure/prism-central/",
     "Prism Central image download", {"mgmt"}),
    ("azure-support.nutanix.com", "/", "Teleport support tunnel (443)", {"mgmt"}),
]
TELEPORT_PORTS = [3022, 3023, 3024, 3025, 3080]
NTP_SERVERS = [("0.pool.ntp.org", "NTP pool (*.pool.ntp.org)"),
               ("1.pool.ntp.org", "NTP pool (*.pool.ntp.org)"),
               ("138.236.128.112", "Azure NTP server")]
DR_PORTS = [(2009, "Stargate"), (2020, "Disaster Recovery"), (9440, "Prism"), (22, "SSH"),
            (2010, "Curator"), (3260, "iSCSI"), (2049, "NFS")]

REQUIRED_PROVIDERS = [
    ("Microsoft.Nutanix", "FAIL", "Required by NC2 (Registering the Azure Resource Providers)."),
    ("Microsoft.Network", "FAIL", "Required by NC2 (Registering the Azure Resource Providers)."),
    ("Microsoft.Compute", "WARN", "Used for Flow Gateway / BGP VMs (NC2 role can register it)."),
    ("Microsoft.Storage", "WARN", "Used for the NC2 image storage account (NC2 role can register it)."),
    ("Microsoft.ManagedIdentity", "WARN", "Used by NC2 for user-assigned identities."),
]

# Custom role "nc2-custom-role" (primary subscription) from the Nutanix doc.
NC2_ROLE_ACTIONS = """
Microsoft.Compute/register/action
Microsoft.Compute/availabilitySets/write
Microsoft.Compute/availabilitySets/delete
Microsoft.Compute/disks/read
Microsoft.Compute/disks/write
Microsoft.Compute/disks/delete
Microsoft.Compute/locations/usages/read
Microsoft.Compute/availabilitySets/read
Microsoft.Compute/virtualMachines/*
Microsoft.Compute/snapshots/*
Microsoft.Compute/images/*
Microsoft.Network/register/action
Microsoft.Network/natGateways/*
Microsoft.Network/networkInterfaces/*
Microsoft.Network/loadBalancers/backendAddressPools/join/action
Microsoft.Network/networkSecurityGroups/*
Microsoft.Network/publicIPAddresses/*
Microsoft.Network/virtualNetworks/*
Microsoft.Network/locations/usages/read
Microsoft.Storage/register/action
Microsoft.Storage/checknameavailability/read
Microsoft.Storage/locations/checknameavailability/read
Microsoft.Storage/locations/usages/read
Microsoft.Storage/storageAccounts/write
Microsoft.Storage/storageAccounts/read
Microsoft.Storage/storageAccounts/delete
Microsoft.Storage/storageAccounts/blobServices/containers/clearLegalHold/action
Microsoft.Storage/storageAccounts/blobServices/containers/delete
Microsoft.Storage/storageAccounts/blobServices/containers/lease/action
Microsoft.Storage/storageAccounts/blobServices/containers/read
Microsoft.Storage/storageAccounts/blobServices/containers/write
Microsoft.Storage/storageAccounts/blobServices/read
Microsoft.Storage/storageAccounts/blobServices/write
Microsoft.Storage/storageAccounts/listAccountSas/action
Microsoft.Storage/storageAccounts/listkeys/action
Microsoft.Storage/storageAccounts/listServiceSas/action
Microsoft.Storage/storageAccounts/regeneratekey/action
Microsoft.Storage/storageAccounts/revokeUserDelegationKeys/action
Microsoft.ResourceHealth/AvailabilityStatuses/read
Microsoft.ResourceHealth/events/read
Microsoft.ResourceHealth/AvailabilityStatuses/current/read
Microsoft.ManagedIdentity/userAssignedIdentities/*
Microsoft.Resources/subscriptions/locations/read
Microsoft.Resources/subscriptions/resourceGroups/read
Microsoft.Resources/subscriptions/resourceGroups/write
Microsoft.Resources/subscriptions/resourceGroups/delete
Microsoft.Resources/subscriptions/resourcegroups/deployments/read
Microsoft.Resources/subscriptions/resourcegroups/deployments/write
Microsoft.Resources/subscriptions/resourcegroups/resources/read
Microsoft.Resources/subscriptions/tagNames/read
Microsoft.Resources/subscriptions/tagNames/write
Microsoft.Resources/subscriptions/tagNames/delete
Microsoft.Resources/subscriptions/tagNames/tagValues/write
Microsoft.Resources/subscriptions/tagNames/tagValues/read
Microsoft.Resources/subscriptions/tagNames/tagValues/delete
Microsoft.Resources/tags/read
Microsoft.Resources/tags/write
Microsoft.Resources/tags/delete
Microsoft.Resources/providers/read
Microsoft.Compute/sshPublicKeys/read
Microsoft.Compute/sshPublicKeys/write
Microsoft.Compute/sshPublicKeys/delete
Microsoft.Compute/sshPublicKeys/generateKeyPair/action
Microsoft.Nutanix/Interfaces/read
Microsoft.Nutanix/Interfaces/write
Microsoft.Nutanix/Interfaces/delete
Microsoft.Nutanix/Nodes/read
Microsoft.Nutanix/Nodes/write
Microsoft.Nutanix/Nodes/delete
Microsoft.Nutanix/register/action
Microsoft.Network/virtualHubs/*
Microsoft.Network/routeTables/read
Microsoft.Network/routeTables/write
Microsoft.Network/routeTables/delete
Microsoft.Network/routeTables/join/action
Microsoft.Network/routeTables/routes/read
Microsoft.Network/routeTables/routes/write
Microsoft.Network/routeTables/routes/delete
Microsoft.CostManagement/query/read
Microsoft.CostManagement/views/read
Microsoft.CostManagement/externalSubscriptions/query/read
Microsoft.CostManagement/externalSubscriptions/dimensions/read
Microsoft.CostManagement/externalSubscriptions/read
Microsoft.CostManagement/externalBillingAccounts/forecast/read
Microsoft.CostManagement/externalBillingAccounts/read
Microsoft.CostManagement/externalBillingAccounts/query/read
Microsoft.CostManagement/externalBillingAccounts/externalSubscriptions/read
Microsoft.CostManagement/externalSubscriptions/forecast/read
Microsoft.CostManagement/operations/read
Microsoft.CostManagement/forecast/read
Microsoft.Network/virtualWans/write
Microsoft.Network/virtualWans/read
Microsoft.Network/virtualWans/delete
Microsoft.Network/virtualWans/virtualHubs/read
Microsoft.Network/virtualWans/join/action
Microsoft.Network/virtualHubs/hubVirtualNetworkConnections/read
Microsoft.Network/virtualHubs/hubVirtualNetworkConnections/write
Microsoft.Network/virtualHubs/hubVirtualNetworkConnections/delete
Microsoft.Network/privateEndpoints/pushPropertiesToResource/action
Microsoft.Network/privateEndpoints/read
Microsoft.Network/privateEndpoints/write
Microsoft.Network/privateEndpoints/delete
Microsoft.Network/privateDnsZones/read
Microsoft.Network/privateDnsZones/delete
Microsoft.Network/privateDnsZones/join/action
Microsoft.Network/privateDnsZones/write
Microsoft.Network/privateEndpoints/privateDnsZoneGroups/write
Microsoft.Network/privateEndpoints/privateDnsZoneGroups/read
Microsoft.Network/privateEndpoints/privateDnsZoneGroups/delete
""".split()

NC2_ROLE_DATA_ACTIONS = """
Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action
Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete
Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action
Microsoft.Storage/storageAccounts/blobServices/containers/blobs/filter/action
Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read
Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/read
Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write
Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write
Microsoft.Storage/storageAccounts/blobServices/containers/blobs/modifyPermissions/action
""".split()

# Built-in policy definitions that are known to break NC2 deployments.
POLICY_ALLOWED_LOCATIONS = {"e56962a6-4747-49cd-b67b-bf8b01975c4c", "e765b5de-1225-4ba3-bd56-1ac6695af988"}
POLICY_ALLOWED_SKUS = {"cccc23c7-8427-4f53-ad12-b6a63eb452b3"}
POLICY_NOT_ALLOWED_TYPES = {"6c112d4e-5bc7-47ae-a041-ea2d9dccd749"}
POLICY_ALLOWED_TYPES = {"a08ec900-254a-4555-9bf5-e42af04b5c5c"}
POLICY_NO_IP_FORWARDING = {"88c0b9da-ce96-4b03-9635-f29a937e2900"}
NC2_RESOURCE_TYPES = [
    "Microsoft.Nutanix/nodes", "Microsoft.Nutanix/interfaces", "Microsoft.Compute/virtualMachines",
    "Microsoft.Compute/disks", "Microsoft.Compute/availabilitySets", "Microsoft.Compute/images",
    "Microsoft.Compute/snapshots", "Microsoft.Network/natGateways", "Microsoft.Network/publicIPAddresses",
    "Microsoft.Network/networkInterfaces", "Microsoft.Network/networkSecurityGroups",
    "Microsoft.Network/virtualNetworks", "Microsoft.Network/routeTables", "Microsoft.Network/virtualHubs",
    "Microsoft.Storage/storageAccounts", "Microsoft.ManagedIdentity/userAssignedIdentities",
    "Microsoft.Resources/resourceGroups",
]

TEST_VM_SIZES = ["Standard_B2s", "Standard_B2ls_v2", "Standard_B2als_v2", "Standard_D2s_v5",
                 "Standard_D2as_v5", "Standard_D2s_v4", "Standard_DS1_v2"]

# --------------------------------------------------------------------------
# Console output + result collection
# --------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_COL = {"PASS": "32", "WARN": "33", "FAIL": "31", "INFO": "36", "B": "1", "DIM": "2"}


def col(key, text):
    return f"\033[{_COL[key]}m{text}\033[0m" if USE_COLOR else text


RESULTS = []
_SECTION = [""]


def section(title):
    _SECTION[0] = title
    print("\n" + col("B", f"== {title} =="))


def add(status, check, detail="", fix=""):
    RESULTS.append({"section": _SECTION[0], "status": status, "check": check,
                    "detail": detail, "fix": fix})
    line = f"  {col(status, '[' + status + ']')} {check}"
    if detail:
        line += f" - {detail}"
    print(line)
    if fix and status in ("FAIL", "WARN"):
        print(col("DIM", f"         -> {fix}"))


def note(text):
    print(col("DIM", f"  {text}"))


# --------------------------------------------------------------------------
# Azure CLI wrapper
# --------------------------------------------------------------------------

class AzError(Exception):
    pass


def az(*args, timeout=900, allow_fail=False):
    cmd = ["az", *args, "--only-show-errors", "-o", "json"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        if allow_fail:
            return None
        raise AzError(f"timeout after {timeout}s: az {' '.join(args[:3])}")
    except FileNotFoundError:
        raise AzError("Azure CLI ('az') not found. Run this script in Azure Cloud Shell.")
    if p.returncode != 0:
        if allow_fail:
            return None
        msg = " ".join((p.stderr or p.stdout or f"az exited {p.returncode}").split())
        raise AzError(msg[:600])
    out = p.stdout.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def arm_get(path, api):
    return az("rest", "--method", "get", "--url",
              f"https://management.azure.com{path}?api-version={api}", allow_fail=True)


def parse_id(rid):
    parts = (rid or "").strip("/").split("/")
    return {parts[i].lower(): parts[i + 1] for i in range(0, len(parts) - 1, 2)}


def norm_loc(s):
    return (s or "").replace(" ", "").lower()


# --------------------------------------------------------------------------
# Interactive helpers
# --------------------------------------------------------------------------

INTERACTIVE = True


def ask(prompt, default=None):
    if not INTERACTIVE:
        return default
    sfx = f" [{default}]" if default not in (None, "") else ""
    try:
        val = input(f"{prompt}{sfx}: ").strip()
    except EOFError:
        return default
    return val if val else default


def choose(prompt, options, default_idx=0):
    """options: list of labels. Returns chosen index."""
    if not INTERACTIVE:
        return default_idx
    print(prompt)
    for i, o in enumerate(options, 1):
        print(f"   [{i}] {o}")
    while True:
        v = ask("  Choice", str(default_idx + 1))
        if v and v.isdigit() and 1 <= int(v) <= len(options):
            return int(v) - 1
        print("  Please enter a number from the list.")


def yesno(prompt, default=True):
    if not INTERACTIVE:
        return default
    v = ask(prompt + (" (Y/n)" if default else " (y/N)"), "")
    if not v:
        return default
    return v.lower().startswith("y")


# --------------------------------------------------------------------------
# Network model helpers
# --------------------------------------------------------------------------

def subnet_prefix(sn):
    p = sn.get("addressPrefix")
    if not p and sn.get("addressPrefixes"):
        p = sn["addressPrefixes"][0]
    return p


def net(p):
    try:
        return ipaddress.ip_network(p, strict=False)
    except Exception:
        return None


def vnet_prefixes(v):
    return [n for n in (net(p) for p in (v.get("addressSpace") or {}).get("addressPrefixes", [])) if n]


def delegations(sn):
    return [d.get("serviceName") for d in (sn.get("delegations") or []) if d.get("serviceName")]


def port_in_range(port, spec):
    spec = str(spec).strip()
    if spec in ("*", ""):
        return True
    if "-" in spec:
        a, b = spec.split("-", 1)
        return a.isdigit() and b.isdigit() and int(a) <= port <= int(b)
    return spec.isdigit() and int(spec) == port


ROLE_INFO = {
    "cluster": ("Cluster (bare-metal) subnet", 25),
    "pc": ("Prism Central subnet", 26),
    "fgw_ext": ("Flow Gateway external subnet", 26),
    "fgw_int": ("Flow Gateway internal subnet", 28),
    "bgp": ("BGP gateway subnet", 28),
    "ilb": ("Internal Load Balancer subnet", 28),
    "routeserver": ("Route Server subnet (hub VNet)", 27),
}

ROLE_HINTS = {
    "cluster": re.compile(r"(cluster|baremetal|bare-metal|bm[-_]|nc2[-_]?(mgmt|cl))", re.I),
    "pc": re.compile(r"(^|[-_.])(pc|prism)", re.I),
    "fgw_ext": re.compile(r"((fgw|flow|gw).*(ext|external|public))|(^ext|[-_]ext)", re.I),
    "fgw_int": re.compile(r"((fgw|flow|gw).*(int|internal))|(^int[-_]|[-_]int($|[-_]))", re.I),
    "bgp": re.compile(r"bgp", re.I),
    "ilb": re.compile(r"(ilb|[-_]lb($|[-_]))", re.I),
}


class Landscape:
    """Snapshot of the networking resources in the subscription."""

    def __init__(self):
        self.vnets = az("network", "vnet", "list") or []
        self.vnet_by_id = {v["id"].lower(): v for v in self.vnets}
        self.subnets = {}
        for v in self.vnets:
            for s in v.get("subnets") or []:
                self.subnets[s["id"].lower()] = {"vnet": v, "sn": s}
        self.nat = {n["id"].lower(): n for n in (az("network", "nat", "gateway", "list", allow_fail=True) or [])}
        self.rt = {r["id"].lower(): r for r in (az("network", "route-table", "list", allow_fail=True) or [])}
        self.nsg = {n["id"].lower(): n for n in (az("network", "nsg", "list", allow_fail=True) or [])}

    def resolve(self, ref):
        """Accept a full subnet ID, 'vnet/subnet' or 'rg/vnet/subnet'."""
        if not ref:
            return None
        ref = ref.strip()
        if ref.lower() in self.subnets:
            return ref.lower()
        parts = ref.strip("/").split("/")
        for sid, x in self.subnets.items():
            p = parse_id(sid)
            if len(parts) == 2 and p.get("virtualnetworks", "").lower() == parts[0].lower() \
                    and p.get("subnets", "").lower() == parts[1].lower():
                return sid
            if len(parts) == 3 and p.get("resourcegroups", "").lower() == parts[0].lower() \
                    and p.get("virtualnetworks", "").lower() == parts[1].lower() \
                    and p.get("subnets", "").lower() == parts[2].lower():
                return sid
        return None

    def label(self, sid):
        x = self.subnets.get((sid or "").lower())
        p = parse_id(x["sn"]["id"] if x else sid)
        return f"{p.get('resourcegroups')}/{p.get('virtualnetworks')}/{p.get('subnets')}"


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

def check_subscription(ctx):
    section("Subscription")
    sub = ctx["sub"]
    add("INFO", "Subscription", f"{sub['name']} ({sub['id']}), tenant {sub['tenantId']}")
    if os.environ.get("AZUREPS_HOST_ENVIRONMENT", "").startswith("cloud-shell") or os.environ.get("ACC_CLOUD"):
        add("INFO", "Running in Azure Cloud Shell", f"signed in as {sub.get('user', {}).get('name', '?')}")
    s = arm_get(f"/subscriptions/{sub['id']}", "2022-12-01") or {}
    state = s.get("state") or sub.get("state")
    if state == "Enabled":
        add("PASS", "Subscription state", "Enabled")
    else:
        add("FAIL", "Subscription state", str(state), "NC2 needs an active (Enabled) Azure subscription.")
    pol = s.get("subscriptionPolicies") or {}
    qid = pol.get("quotaId", "")
    spend = pol.get("spendingLimit", "")
    if spend == "On" or re.search(r"FreeTrial|MSDN|Sponsored|AzurePass|Student|DreamSpark", qid, re.I):
        add("WARN", "Subscription offer", f"quotaId={qid}, spendingLimit={spend}",
            "Trial/MSDN/sponsored subscriptions or a spending limit usually cannot run bare-metal NC2 "
            "nodes. Use a Pay-As-You-Go, EA or MCA subscription.")
    else:
        add("PASS", "Subscription offer", f"quotaId={qid or 'n/a'}, spendingLimit={spend or 'n/a'}")


def check_providers(ctx):
    section("Resource providers")
    loc = ctx["location"]
    for ns, sev, why in REQUIRED_PROVIDERS:
        p = az("provider", "show", "--namespace", ns, allow_fail=True)
        state = (p or {}).get("registrationState", "NotFound")
        if state == "Registered":
            add("PASS", f"{ns} registered")
        else:
            add(sev, f"{ns} registered", f"state: {state}. {why}",
                f"az provider register --namespace {ns}   (wait until 'Registered')")
        if ns == "Microsoft.Nutanix" and p:
            locs = set()
            for rt in p.get("resourceTypes") or []:
                locs.update(norm_loc(x) for x in rt.get("locations") or [])
            disp = norm_loc(ctx["location_display"])
            if not locs:
                add("INFO", "Microsoft.Nutanix region list", "provider did not return locations")
            elif norm_loc(loc) in locs or disp in locs:
                add("PASS", f"Microsoft.Nutanix offered in {ctx['location_display']}")
            else:
                add("WARN", f"Microsoft.Nutanix offered in {ctx['location_display']}",
                    "region not in the provider's location list",
                    "Check 'Supported Regions and Bare-metal Instances' in the NC2 on Azure guide "
                    "(regions need 3+ partitions) and pick a supported region.")


def check_skus(ctx):
    section("VM size availability in region")
    loc = ctx["location"]
    try:
        skus = az("vm", "list-skus", "-l", loc, "--resource-type", "virtualMachines", "--all", timeout=600) or []
    except AzError as e:
        add("WARN", "Could not list VM SKUs", str(e))
        ctx["sku_ok"] = {}
        return
    by_name = {s["name"].lower(): s for s in skus}
    ctx["sku_ok"] = {}

    def status_of(name):
        s = by_name.get(name.lower())
        if not s:
            return "missing", "not offered in this region"
        reasons, zones = [], []
        for r in s.get("restrictions") or []:
            if r.get("type") == "Location":
                reasons.append(r.get("reasonCode", "restricted"))
            elif r.get("type") == "Zone":
                zones.extend((r.get("restrictionInfo") or {}).get("zones") or [])
        if reasons:
            return "restricted", ", ".join(reasons)
        if zones:
            return "partial", f"restricted in zone(s) {','.join(sorted(zones))}"
        return "ok", "available"

    size = ctx["fgw_size"]
    want = [(FGW_SKUS[size]["v5"][0], "Flow Gateway (recommended)"),
            (FGW_SKUS[size]["v4"][0], "Flow Gateway (supported)")]
    if ctx["routing"] == "bgp":
        want += [(BGP_PRIMARY[0], "BGP gateway VM"), (BGP_FALLBACK[0], "BGP gateway VM (fallback)")]
    for name in TEST_VM_SIZES:
        st, _ = status_of(name)
        ctx["sku_ok"][name] = st in ("ok", "partial")
    for name, _ in want:
        st, _ = status_of(name)
        ctx["sku_ok"][name] = st in ("ok", "partial")
    alt = {FGW_SKUS[size]["v5"][0]: FGW_SKUS[size]["v4"][0], FGW_SKUS[size]["v4"][0]: FGW_SKUS[size]["v5"][0],
           BGP_PRIMARY[0]: BGP_FALLBACK[0], BGP_FALLBACK[0]: BGP_PRIMARY[0]}
    for name, purpose in want:
        st, why = status_of(name)
        if st == "ok":
            add("PASS", f"{name} ({purpose})", why)
        elif st == "partial":
            add("INFO", f"{name} ({purpose})", why)
        else:
            other_ok = ctx["sku_ok"].get(alt[name])
            primary = not ("supported" in purpose or "fallback" in purpose)
            sev = "FAIL" if not other_ok else ("WARN" if primary else "INFO")
            add(sev, f"{name} ({purpose})", why + (f"; {alt[name]} is available" if other_ok else ""),
                "Open a support request to lift the SKU restriction for this subscription/region "
                "(NotAvailableForSubscription) or choose another region.")
    # Fold FGW / BGP SKU outcome
    v5, v4 = FGW_SKUS[size]["v5"][0], FGW_SKUS[size]["v4"][0]
    if not ctx["sku_ok"].get(v5) and not ctx["sku_ok"].get(v4):
        add("FAIL", "Flow Gateway VM size usable", f"neither {v5} nor {v4} is available",
            "NC2 cannot deploy a Flow Gateway in this region/subscription until a size is unblocked.")
    if ctx["routing"] == "bgp" and not ctx["sku_ok"].get(BGP_PRIMARY[0]) and not ctx["sku_ok"].get(BGP_FALLBACK[0]):
        add("FAIL", "BGP gateway VM size usable", f"neither {BGP_PRIMARY[0]} nor {BGP_FALLBACK[0]} is available")


def check_quotas(ctx):
    section("Quotas (Flow Gateway + BGP)")
    loc = ctx["location"]
    try:
        usage = az("vm", "list-usage", "-l", loc) or []
    except AzError as e:
        add("FAIL", "Could not read compute quotas", str(e), "Need at least Reader on the subscription.")
        return
    u = {}
    for x in usage:
        key = (x.get("name") or {}).get("value", "").lower()
        try:
            u[key] = (int(x.get("currentValue", 0)), int(x.get("limit", 0)),
                      (x.get("name") or {}).get("localizedValue", key))
        except (TypeError, ValueError):
            continue

    def free(family):
        cur, lim, _ = u.get(family.lower(), (0, 0, family))
        return lim - cur, cur, lim

    n, size = ctx["fgw_count"], ctx["fgw_size"]
    total_vcpu_needed, vm_needed = 0, n

    # Flow Gateway family quota
    res = {}
    for gen in ("v5", "v4"):
        sku, fam, vcpu = FGW_SKUS[size][gen]
        need = n * vcpu
        f, cur, lim = free(fam)
        res[gen] = (f >= need, sku, fam, need, f, cur, lim)
    ok5, ok4 = res["v5"][0] and ctx["sku_ok"].get(res["v5"][1], True), res["v4"][0] and ctx["sku_ok"].get(res["v4"][1], True)
    for gen in ("v5", "v4"):
        ok, sku, fam, need, f, cur, lim = res[gen]
        txt = f"{n} x {sku} needs {need} vCPU; {fam}: {cur}/{lim} used, {f} free"
        if gen == "v5":
            add("PASS" if ok else ("WARN" if ok4 else "FAIL"), "Flow Gateway quota (recommended v5)", txt,
                "" if ok else f"Request a quota increase for '{u.get(fam.lower(), (0, 0, fam))[2]}' in "
                              f"{ctx['location_display']} to at least {cur + need} vCPUs.")
        else:
            add("PASS" if ok else ("INFO" if ok5 else "FAIL"), "Flow Gateway quota (supported v4)", txt,
                "" if ok else f"Request a quota increase for '{u.get(fam.lower(), (0, 0, fam))[2]}' to at least {cur + need}.")
    fgw_vcpu = n * FGW_SKUS[size]["v5"][2]
    total_vcpu_needed += fgw_vcpu
    if n < 4:
        max_need = 4 * FGW_SKUS[size]["v5"][2]
        f, cur, lim = free(FGW_SKUS[size]["v5"][1])
        add("PASS" if f >= max_need else "INFO", "Headroom for 4-node FGW scale-out (64 Gbps max)",
            f"needs {max_need} vCPU in {FGW_SKUS[size]['v5'][1]}, {f} free")

    # BGP VMs (Route Server routing only)
    if ctx["routing"] == "bgp":
        sku, fam, vcpu = BGP_PRIMARY
        need = BGP_COUNT * vcpu
        f, cur, lim = free(fam)
        fsku, ffam, fvcpu = BGP_FALLBACK
        fneed = BGP_COUNT * fvcpu
        ff, fcur, flim = free(ffam)
        prim_ok = f >= need and ctx["sku_ok"].get(sku, True)
        fb_ok = ff >= fneed and ctx["sku_ok"].get(fsku, True)
        if prim_ok:
            add("PASS", "BGP gateway VM quota", f"2 x {sku} needs {need} vCPU; {fam}: {cur}/{lim} used, {f} free")
            total_vcpu_needed += need
        elif fb_ok:
            add("WARN", "BGP gateway VM quota",
                f"{fam} has {f} free (needs {need}); NC2 will fall back to 2 x {fsku} ({ffam}: {ff} free)",
                f"Raise '{fam}' to at least {cur + need} to get the preferred {sku}.")
            total_vcpu_needed += fneed
        else:
            add("FAIL", "BGP gateway VM quota",
                f"{fam}: {f} free (needs {need}); fallback {ffam}: {ff} free (needs {fneed})",
                f"Request '{fam}' >= {cur + need} vCPUs in {ctx['location_display']} "
                f"(or switch Flow Gateway routing to ILB, which needs no BGP VMs).")
            total_vcpu_needed += need
        vm_needed += BGP_COUNT
    else:
        add("INFO", "BGP gateway VM quota", "not needed - ILB routing selected (no BGP VMs, no Route Server)")

    # Regional totals
    f, cur, lim = free("cores")
    add("PASS" if f >= total_vcpu_needed else "FAIL", "Total Regional vCPUs",
        f"needs {total_vcpu_needed}; {cur}/{lim} used, {f} free",
        "" if f >= total_vcpu_needed else f"Request 'Total Regional vCPUs' >= {cur + total_vcpu_needed}.")
    f, cur, lim = free("virtualMachines")
    if lim:
        add("PASS" if f >= vm_needed else "FAIL", "Virtual machine count", f"needs {vm_needed}; {f} free")
    add("INFO", "Managed disk capacity", "FGW/BGP need >= 120 GiB (50 GiB per FGW VM, 10 GiB per BGP VM)")

    # Networking quotas
    nu = az("network", "list-usages", "-l", loc, allow_fail=True) or []
    nmap = {}
    for x in nu:
        key = ((x.get("name") or {}).get("value") or "").lower()
        try:
            nmap[key] = (int(x.get("currentValue", 0)), int(x.get("limit", 0)))
        except (TypeError, ValueError):
            pass
    pip_need = 3  # cluster NAT, PC NAT, FGW NAT
    for key in ("standardskupublicipaddresses", "publicipaddresses"):
        if key in nmap:
            cur, lim = nmap[key]
            add("PASS" if lim - cur >= pip_need else "FAIL", "Public IP addresses",
                f"needs {pip_need} (one per NAT gateway); {cur}/{lim} used",
                "Request a Public IP quota increase.")
            break
    nat_keys = [k for k in nmap if "natgateway" in k]
    if nat_keys:
        cur, lim = nmap[nat_keys[0]]
        add("PASS" if lim - cur >= 3 else "WARN", "NAT gateways", f"needs up to 3; {cur}/{lim} used")
    if "virtualnetworks" in nmap:
        cur, lim = nmap["virtualnetworks"]
        add("PASS" if lim - cur >= 3 else "WARN", "Virtual networks", f"NC2 may create up to 3; {cur}/{lim} used")
    if "networkinterfaces" in nmap:
        cur, lim = nmap["networkinterfaces"]
        need = 2 * n + BGP_COUNT
        add("PASS" if lim - cur >= need else "WARN", "Network interfaces", f"needs ~{need}; {cur}/{lim} used")

    st = az("storage", "account", "show-usage", "-l", loc, allow_fail=True)
    if isinstance(st, dict) and "limit" in st:
        cur, lim = int(st.get("currentValue", 0)), int(st.get("limit", 0))
        need = 2 if ctx.get("mst") else 1
        add("PASS" if lim - cur >= need else "FAIL", "Storage accounts",
            f"needs {need} (NC2 image store{' + MST DR' if ctx.get('mst') else ''}); {cur}/{lim} used")


def check_subnets(ctx, L):
    section("VNets, subnets and CIDRs")
    sel = ctx["subnets"]
    if not any(sel.values()):
        add("WARN", "No subnets selected", "networking checks skipped",
            "Re-run and select the BYO subnets, or let the NC2 console create the networking.")
        return

    expected = ["cluster", "pc", "fgw_ext", "fgw_int"] + (["bgp", "routeserver"] if ctx["routing"] == "bgp" else ["ilb"])
    for role in expected:
        if not sel.get(role):
            add("INFO", f"{ROLE_INFO[role][0]} not selected",
                "checks for it were skipped (fine if the NC2 console will create it)")

    vnets_used = {}
    for role, sid in sel.items():
        if not sid:
            continue
        x = L.subnets[sid]
        v, sn = x["vnet"], x["sn"]
        vnets_used.setdefault(v["id"].lower(), set()).add(role)
        name, max_len = ROLE_INFO[role]
        pfx = net(subnet_prefix(sn))
        lbl = L.label(sid)
        if norm_loc(v.get("location")) != norm_loc(ctx["location"]):
            add("WARN", f"{name} region", f"{lbl} is in {v.get('location')}, not {ctx['location']}")
        if not pfx:
            add("FAIL", f"{name} CIDR", f"{lbl}: no IPv4 prefix found")
            continue
        if pfx.version != 4:
            add("FAIL", f"{name} CIDR", f"{lbl}: {pfx} - NC2 supports IPv4 only")
            continue
        # size
        if role == "fgw_ext":
            if pfx.prefixlen <= 24:
                add("PASS", f"{name} size", f"{lbl} = {pfx} (/24 recommended)")
            elif pfx.prefixlen <= 26:
                add("WARN", f"{name} size", f"{lbl} = {pfx}; minimum met but few floating IPs",
                    "Nutanix recommends a /24 for the Flow Gateway external subnet.")
            else:
                add("FAIL", f"{name} size", f"{lbl} = {pfx}; minimum is /26", "Resize to /24 (recommended) or at least /26.")
        else:
            ok = pfx.prefixlen <= max_len
            add("PASS" if ok else "FAIL", f"{name} size", f"{lbl} = {pfx} (minimum /{max_len})",
                "" if ok else f"Use at least a /{max_len} for this subnet.")
        # name / delegation
        dels = delegations(sn)
        if role == "cluster":
            if DELEGATION in dels:
                add("PASS", "Cluster subnet delegation", DELEGATION)
            else:
                add("FAIL", "Cluster subnet delegation", f"delegations: {dels or 'none'}",
                    f"Delegate {lbl} to {DELEGATION} (Subnet > Subnet delegation).")
            others = [s["name"] for s in v.get("subnets") or []
                      if DELEGATION in delegations(s) and s["id"].lower() != sid]
            if others:
                add("WARN", "One NC2 cluster per VNet", f"other bare-metal delegated subnets in VNet: {others}",
                    "Nutanix recommends a single NC2 cluster per Azure VNet.")
        elif dels:
            add("FAIL", f"{name} delegation", f"subnet is delegated to {dels}",
                "Only the cluster subnet may be delegated; FGW/PC/BGP subnets host regular VM NICs.")
        if role == "routeserver" and sn.get("name") != "RouteServerSubnet":
            add("FAIL", "Route Server subnet name", f"named '{sn.get('name')}'",
                "Azure requires the subnet to be named exactly 'RouteServerSubnet'.")

    # Same-VNet rules
    def vnet_of(role):
        sid = sel.get(role)
        return L.subnets[sid]["vnet"]["id"].lower() if sid else None

    if sel.get("fgw_ext") and sel.get("fgw_int"):
        same = vnet_of("fgw_ext") == vnet_of("fgw_int")
        add("PASS" if same else "FAIL", "FGW external + internal subnets in the same VNet",
            "" if same else "they are in different VNets",
            "" if same else "Place both Flow Gateway subnets in one VNet (dedicated FGW VNet or the PC VNet).")
    if sel.get("ilb") and (sel.get("fgw_ext") or sel.get("fgw_int")):
        same = vnet_of("ilb") in (vnet_of("fgw_ext"), vnet_of("fgw_int"))
        add("PASS" if same else "FAIL", "ILB subnet in the Flow Gateway VNet", "",
            "" if same else "The ILB subnet must be in the same VNet as the Flow Gateway.")
    if sel.get("bgp") and sel.get("fgw_ext"):
        same = vnet_of("bgp") == vnet_of("fgw_ext")
        add("PASS" if same else "WARN", "BGP subnet in the Flow Gateway VNet", "",
            "" if same else "Nutanix sizes the FGW VNet (/23) to hold FGW external, internal and BGP subnets.")
    if sel.get("cluster") and sel.get("pc") and vnet_of("cluster") == vnet_of("pc"):
        add("WARN", "Separate VNets for cluster and Prism Central", "cluster and PC subnets share a VNet",
            "NC2 expects one VNet each for Cluster Management and Prism Central.")

    # VNet address space sizing
    for vid, roles in vnets_used.items():
        v = L.vnet_by_id[vid]
        prefixes = vnet_prefixes(v)
        if any(p.version == 6 for p in prefixes):
            add("FAIL", f"VNet {v['name']} address space", "contains IPv6 - NC2 supports IPv4 only")
        size = sum(p.num_addresses for p in prefixes if p.version == 4)
        space = ", ".join(str(p) for p in prefixes)
        if "cluster" in roles:
            add("PASS" if size >= 128 else "FAIL", f"Cluster VNet {v['name']} size", f"{space} (minimum /25)")
        if "pc" in roles:
            need = 64 if ctx["onprem"] == "vpn" else 256
            label = "/26 (VPN)" if ctx["onprem"] == "vpn" else "/24, /23 recommended (ExpressRoute/vWAN)"
            if size >= need:
                add("PASS", f"Prism Central VNet {v['name']} size", f"{space} (minimum {label})")
            else:
                add("WARN" if ctx["onprem"] != "vpn" else "FAIL", f"Prism Central VNet {v['name']} size",
                    f"{space} (minimum {label})",
                    "Use a /23 so the PC VNet can also hold the FGW external (/24), FGW internal and BGP subnets.")
        if ("fgw_ext" in roles or "fgw_int" in roles) and "pc" not in roles:
            if size >= 512:
                add("PASS", f"Flow Gateway VNet {v['name']} size", f"{space} (/23 recommended)")
            elif size >= 128:
                add("INFO", f"Flow Gateway VNet {v['name']} size", f"{space}; /23 recommended")
            else:
                add("FAIL", f"Flow Gateway VNet {v['name']} size", f"{space}; minimum /25")
        if "routeserver" in roles:
            add("PASS" if size >= 32 else "FAIL", f"Hub VNet {v['name']} size", f"{space} (minimum /27)")

    # Overlaps
    items = list(vnets_used.keys())
    overlaps = []
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            for a in vnet_prefixes(L.vnet_by_id[items[i]]):
                for b in vnet_prefixes(L.vnet_by_id[items[j]]):
                    if a.version == b.version and a.overlaps(b):
                        overlaps.append(f"{L.vnet_by_id[items[i]]['name']} {a} <> {L.vnet_by_id[items[j]]['name']} {b}")
    add("FAIL" if overlaps else "PASS", "No overlapping address space between NC2 VNets",
        "; ".join(overlaps), "Peered VNets cannot overlap - re-IP one of them.")
    hits = [f"{L.vnet_by_id[v]['name']} {p}" for v in items for p in vnet_prefixes(L.vnet_by_id[v])
            if p.version == 4 and p.overlaps(CVM_INTERNAL_NET)]
    if hits:
        add("WARN", "192.168.5.0/24 not used", ", ".join(hits),
            "192.168.5.0/24 is used internally by every CVM/AHV host; avoid it for routed networks.")
    ctx["vnets_used"] = vnets_used


def check_egress(ctx, L):
    section("Outbound path (NAT gateway / UDR), NSGs")
    sel = ctx["subnets"]
    needs_egress = ["cluster", "pc", "fgw_ext", "bgp"]
    for role in needs_egress:
        sid = sel.get(role)
        if not sid:
            continue
        sn = L.subnets[sid]["sn"]
        name = ROLE_INFO[role][0]
        nat_id = ((sn.get("natGateway") or {}).get("id") or "").lower()
        rt_id = ((sn.get("routeTable") or {}).get("id") or "").lower()
        default_route = None
        if rt_id and rt_id in L.rt:
            for r in L.rt[rt_id].get("routes") or []:
                if r.get("addressPrefix") in ("0.0.0.0/0", "Internet"):
                    default_route = r
        nat_ok, nat_txt = False, ""
        if nat_id:
            n = L.nat.get(nat_id)
            if n is None:
                nat_ok, nat_txt = True, f"NAT gateway {parse_id(nat_id).get('natgateways')}"
            else:
                pips = (n.get("publicIpAddresses") or []) + (n.get("publicIpPrefixes") or [])
                nat_ok = bool(pips)
                nat_txt = f"NAT gateway {n['name']} ({len(pips)} public IP/prefix)"
        if default_route:
            hop = default_route.get("nextHopType")
            if hop == "VirtualAppliance":
                add("PASS", f"{name} egress", f"UDR 0.0.0.0/0 -> NVA {default_route.get('nextHopIpAddress')}"
                    + (" (overrides the NAT gateway)" if nat_id else ""),
                    "")
                note("     Make sure the NVA/firewall allows every endpoint in the connectivity section (L4, no TLS inspection).")
            elif hop == "VirtualNetworkGateway":
                add("INFO", f"{name} egress", "UDR 0.0.0.0/0 -> VNet gateway (forced tunnel to on-prem)",
                    "On-prem firewall must allow all NC2 endpoints.")
            elif hop == "None":
                add("FAIL", f"{name} egress", "UDR 0.0.0.0/0 -> None (black-holed)",
                    "Remove the route or point it to an NVA / attach a NAT gateway.")
            elif hop == "Internet":
                if nat_id:
                    add("PASS" if nat_ok else "FAIL", f"{name} egress", nat_txt + ", UDR 0/0 -> Internet")
                else:
                    add("WARN", f"{name} egress", "UDR 0/0 -> Internet without NAT gateway (default outbound access)",
                        "Attach a NAT gateway with a public IP (NC2 expects one per cluster, PC and FGW subnet).")
            else:
                add("INFO", f"{name} egress", f"UDR 0/0 next hop {hop}")
        elif nat_id:
            add("PASS" if nat_ok else "FAIL", f"{name} egress", nat_txt,
                "" if nat_ok else "Attach a public IP or prefix to the NAT gateway.")
        else:
            private = sn.get("defaultOutboundAccess") is False
            add("FAIL" if private else "WARN", f"{name} egress",
                "no NAT gateway and no 0.0.0.0/0 UDR" + (" on a private subnet (defaultOutboundAccess=false)" if private else ""),
                "Attach a NAT gateway, or route 0.0.0.0/0 to an NVA. If egress is via a vWAN secured hub "
                "(routing intent) this can be fine - the connectivity test will confirm.")

    # NSG outbound deny rules that may hit required ports
    req_ports = [443, 123, 53, 80] + TELEPORT_PORTS
    for role, sid in sel.items():
        if not sid:
            continue
        sn = L.subnets[sid]["sn"]
        nsg_id = ((sn.get("networkSecurityGroup") or {}).get("id") or "").lower()
        if not nsg_id or nsg_id not in L.nsg:
            continue
        nsg = L.nsg[nsg_id]
        hits = []
        for r in nsg.get("securityRules") or []:
            if r.get("direction") != "Outbound" or r.get("access") != "Deny":
                continue
            dst = [r.get("destinationAddressPrefix")] + (r.get("destinationAddressPrefixes") or [])
            if not any(d in ("*", "Internet", "0.0.0.0/0") for d in dst if d):
                continue
            ranges = [r.get("destinationPortRange")] + (r.get("destinationPortRanges") or [])
            ports = sorted({p for p in req_ports for rg in ranges if rg and port_in_range(p, rg)})
            if ports:
                hits.append(f"{r['name']} (prio {r.get('priority')}, ports {','.join(map(str, ports))})")
        if hits:
            add("WARN", f"NSG {nsg['name']} on {ROLE_INFO[role][0]}", "outbound deny rules: " + "; ".join(hits),
                "Ensure higher-priority allow rules exist for the NC2 endpoints.")
        else:
            add("PASS", f"NSG {nsg['name']} on {ROLE_INFO[role][0]}", "no outbound deny rules hitting NC2 ports")

    # FGW IP forwarding (only when FGW NICs already exist)
    fgw_ids = {sel.get("fgw_ext"), sel.get("fgw_int")} - {None}
    if fgw_ids:
        nics = az("network", "nic", "list", allow_fail=True) or []
        fgw_nics = [n for n in nics if any(((ip.get("subnet") or {}).get("id") or "").lower() in fgw_ids
                                           for ip in n.get("ipConfigurations") or [])]
        if not fgw_nics:
            add("INFO", "Flow Gateway NIC IP forwarding",
                "no NICs in FGW subnets yet; NC2 enables IP forwarding at deployment - make sure no policy denies it")
        else:
            bad = [n["name"] for n in fgw_nics if not (n.get("enableIPForwarding") or n.get("enableIpForwarding"))]
            add("FAIL" if bad else "PASS", "Flow Gateway NIC IP forwarding",
                f"disabled on: {bad}" if bad else f"enabled on {len(fgw_nics)} NIC(s)",
                "Enable IP forwarding on every FGW NIC (Azure portal and inside the FGW OS).")


def check_dns_peering(ctx, L):
    section("DNS and VNet connectivity")
    ctx["custom_dns"] = {}
    for vid, roles in (ctx.get("vnets_used") or {}).items():
        v = L.vnet_by_id[vid]
        dns = ((v.get("dhcpOptions") or {}).get("dnsServers")) or []
        ctx["custom_dns"][vid] = dns
        if dns:
            add("INFO", f"VNet {v['name']} DNS", f"custom DNS servers {', '.join(dns)}",
                "")
            note("     These servers must resolve public names (gateway-external-api.cloud.nutanix.com) - tested below.")
        else:
            add("PASS", f"VNet {v['name']} DNS", "Azure-provided DNS (168.63.129.16)")

    # Peerings
    graph = {}
    for vid in (ctx.get("vnets_used") or {}):
        v = L.vnet_by_id[vid]
        for p in v.get("virtualNetworkPeerings") or []:
            rid = ((p.get("remoteVirtualNetwork") or {}).get("id") or "").lower()
            graph.setdefault(vid, set()).add(rid)
            state, sync = p.get("peeringState"), p.get("peeringSyncLevel")
            if state != "Connected":
                add("FAIL", f"Peering {v['name']}/{p['name']}", f"state {state}",
                    "Re-create or sync the peering so both sides show 'Connected'.")
            elif sync and sync != "FullyInSync":
                add("WARN", f"Peering {v['name']}/{p['name']}", f"sync level {sync}",
                    "Click 'Sync' on the peering (address space changed).")
            else:
                add("PASS", f"Peering {v['name']}/{p['name']}",
                    f"-> {parse_id(rid).get('virtualnetworks')} (fwd traffic: {p.get('allowForwardedTraffic')}, "
                    f"remote gw: {p.get('useRemoteGateways')})")

    def vnet_of(role):
        sid = ctx["subnets"].get(role)
        return L.subnets[sid]["vnet"]["id"].lower() if sid else None

    pairs = [("cluster", "pc", "Cluster VNet <-> Prism Central VNet")]
    if vnet_of("fgw_ext") and vnet_of("fgw_ext") != vnet_of("pc"):
        pairs.append(("pc", "fgw_ext", "Prism Central VNet <-> Flow Gateway VNet"))
    if ctx["routing"] == "bgp" and vnet_of("routeserver"):
        pairs.append(("fgw_ext", "routeserver", "Flow Gateway VNet <-> Hub (Route Server) VNet"))
    for a, b, label in pairs:
        va, vb = vnet_of(a), vnet_of(b)
        if not va or not vb or va == vb:
            continue
        direct = vb in graph.get(va, set()) or va in graph.get(vb, set())
        common = (graph.get(va, set()) & graph.get(vb, set())) - {va, vb}
        if direct:
            add("PASS", label, "directly peered")
        elif common:
            hub = parse_id(sorted(common)[0]).get("virtualnetworks")
            add("PASS", label, f"both peered to {hub} (ensure transit via vWAN hub / NVA)")
        else:
            add("WARN", label, "no direct peering or shared hub found",
                "These VNets must be able to reach each other (peering, vWAN hub or NVA).")

    # Hybrid connectivity
    found = []
    for rtype, lbl in [("Microsoft.Network/virtualNetworkGateways", "VPN/ER gateway"),
                       ("Microsoft.Network/expressRouteCircuits", "ExpressRoute circuit"),
                       ("Microsoft.Network/virtualWans", "Virtual WAN"),
                       ("Microsoft.Network/vpnGateways", "vWAN VPN gateway"),
                       ("Microsoft.Network/expressRouteGateways", "vWAN ER gateway")]:
        r = az("resource", "list", "--resource-type", rtype, allow_fail=True) or []
        if r:
            found.append(f"{len(r)} {lbl}")
    if found:
        add("PASS", "On-prem connectivity resources in this subscription", ", ".join(found))
    else:
        add("WARN", "On-prem connectivity resources in this subscription", "none found",
            "NC2 needs ExpressRoute or VPN to on-prem. Fine if it lives in a separate connectivity subscription.")

    if ctx["routing"] == "bgp":
        rs = az("network", "routeserver", "list", allow_fail=True)
        if rs:
            here = [r["name"] for r in rs if norm_loc(r.get("location")) == norm_loc(ctx["location"])]
            add("INFO", "Azure Route Server", f"found: {here or [r['name'] for r in rs]}")
        else:
            add("INFO", "Azure Route Server", "none found - NC2 can create it in the hub VNet (needs RouteServerSubnet /27)")


def _policy_effect(defn_props, assignment):
    eff = (((defn_props.get("policyRule") or {}).get("then") or {}).get("effect") or "")
    m = re.match(r"\[parameters\('([^']+)'\)\]", eff)
    if m:
        pname = m.group(1)
        aval = ((assignment.get("parameters") or {}).get(pname) or {}).get("value")
        dval = ((defn_props.get("parameters") or {}).get(pname) or {}).get("defaultValue")
        eff = aval or dval or eff
    return str(eff).lower()


def check_policies(ctx):
    section("Azure Policy")
    sub_id = ctx["sub"]["id"]
    try:
        assigns = az("policy", "assignment", "list", "--disable-scope-strict-match") or []
    except AzError as e:
        add("WARN", "Could not read policy assignments", str(e))
        return
    exempt = az("policy", "exemption", "list", "--disable-scope-strict-match", allow_fail=True) or []
    exempted = {(e.get("policyAssignmentId") or "").lower() for e in exempt}
    sub_scope = f"/subscriptions/{sub_id}".lower()

    active = []
    for a in assigns:
        if (a.get("enforcementMode") or "Default") == "DoNotEnforce":
            continue
        if a["id"].lower() in exempted:
            continue
        if any(sub_scope == (ns or "").lower() for ns in a.get("notScopes") or []):
            continue
        active.append(a)
    add("INFO", "Policy assignments in scope", f"{len(assigns)} total, {len(active)} enforced without exemption")

    def fetch(a):
        pid = a.get("policyDefinitionId") or ""
        api = "2023-04-01"
        d = arm_get(pid, api) or {}
        return a, pid, d

    findings = 0
    audit_only = 0
    with cf.ThreadPoolExecutor(8) as ex:
        for a, pid, d in ex.map(fetch, active[:250]):
            props = d.get("properties") or {}
            guid = pid.rstrip("/").split("/")[-1].lower()
            disp = a.get("displayName") or props.get("displayName") or a.get("name")
            cat = ((props.get("metadata") or {}).get("category") or "")
            params = a.get("parameters") or {}
            is_set = "/policysetdefinitions/" in pid.lower()

            def pval(*names):
                for n in names:
                    if n in params:
                        return params[n].get("value")
                return None

            if guid in POLICY_ALLOWED_LOCATIONS or re.search(r"allowed locations", disp, re.I):
                allowed = pval("listOfAllowedLocations") or []
                if allowed and norm_loc(ctx["location"]) not in [norm_loc(x) for x in allowed]:
                    add("FAIL", f"Policy '{disp}'", f"{ctx['location']} not in allowed locations {allowed}",
                        "Add the region to the policy or create an exemption for the NC2 subscription.")
                    findings += 1
                else:
                    add("PASS", f"Policy '{disp}'", f"{ctx['location']} allowed")
                continue
            if guid in POLICY_ALLOWED_SKUS or re.search(r"allowed virtual machine size", disp, re.I):
                allowed = [s.lower() for s in (pval("listOfAllowedSKUs") or [])]
                need = [FGW_SKUS[ctx["fgw_size"]]["v5"][0], FGW_SKUS[ctx["fgw_size"]]["v4"][0]]
                if ctx["routing"] == "bgp":
                    need += [BGP_PRIMARY[0], BGP_FALLBACK[0]]
                missing = [s for s in need if allowed and s.lower() not in allowed]
                add("FAIL" if missing else "PASS", f"Policy '{disp}'",
                    f"blocks {missing}" if missing else "NC2 VM sizes allowed",
                    "Allow the FGW/BGP sizes or exempt the NC2 subscription.")
                findings += bool(missing)
                continue
            if guid in POLICY_NOT_ALLOWED_TYPES or re.search(r"not allowed resource types", disp, re.I):
                blocked = [t for t in (pval("listOfResourceTypesNotAllowed") or [])
                           if t.lower() in [x.lower() for x in NC2_RESOURCE_TYPES]]
                add("FAIL" if blocked else "PASS", f"Policy '{disp}'",
                    f"blocks {blocked}" if blocked else "no NC2 resource types blocked",
                    "Remove these types from the list or exempt the NC2 subscription.")
                findings += bool(blocked)
                continue
            if guid in POLICY_ALLOWED_TYPES or re.search(r"^allowed resource types", disp, re.I):
                allowed = [t.lower() for t in (pval("listOfResourceTypesAllowed") or [])]
                blocked = [t for t in NC2_RESOURCE_TYPES if allowed and t.lower() not in allowed]
                add("FAIL" if blocked else "PASS", f"Policy '{disp}'",
                    f"does not allow {blocked}" if blocked else "NC2 resource types allowed",
                    "Add the NC2 resource types or exempt the NC2 subscription.")
                findings += bool(blocked)
                continue
            if guid in POLICY_NO_IP_FORWARDING or re.search(r"ip forwarding", disp, re.I):
                eff = _policy_effect(props, a) if not is_set else "deny"
                if eff in ("deny", "denyaction"):
                    add("FAIL", f"Policy '{disp}'", "denies IP forwarding - the Flow Gateway NICs require it",
                        "Create a policy exemption (Policy > Assignments > Create exemption) for the NC2 subscription.")
                    findings += 1
                else:
                    add("WARN", f"Policy '{disp}'", f"effect {eff}; FGW NICs will be non-compliant")
                continue
            if is_set:
                if cat.lower() == "network" or re.search(r"network|nsg|firewall|public ip|nat", disp, re.I):
                    add("WARN", f"Initiative '{disp}'", f"category {cat or 'n/a'}; may contain deny rules",
                        "Review and exempt the NC2 subscription (Nutanix: 'Creating Azure Policy Exemptions').")
                    findings += 1
                else:
                    audit_only += 1
                continue
            eff = _policy_effect(props, a)
            if eff in ("deny", "denyaction"):
                lvl = "WARN"
                why = "deny policy" + (" (Network category)" if cat.lower() == "network" else "")
                if re.search(r"require a tag|requires? .*tag", disp, re.I):
                    why = "requires tags - NC2-created resources will not carry your tags"
                add(lvl, f"Policy '{disp}'", why,
                    "Verify it cannot block NC2 resources; otherwise create an exemption for the NC2 subscription.")
                findings += 1
            elif eff in ("modify", "append", "deployifnotexists"):
                if cat.lower() == "network":
                    add("WARN", f"Policy '{disp}'", f"effect {eff} on network resources",
                        "Policies that change NC2 network resources can break the deployment - consider an exemption.")
                    findings += 1
                else:
                    audit_only += 1
            else:
                audit_only += 1
    if len(active) > 250:
        add("INFO", "Policy scan limit", f"only the first 250 of {len(active)} assignments were evaluated")
    add("INFO", "Other enforced assignments", f"{audit_only} audit/initiative assignments with no detected NC2 impact")
    if not findings:
        add("PASS", "No conflicting deny/modify policies detected")


def _covered(action, allow, deny):
    a = action.lower()
    if not any(fnmatch.fnmatchcase(a, p.lower()) for p in allow):
        return False
    return not any(fnmatch.fnmatchcase(a, p.lower()) for p in deny)


def check_identity(ctx):
    section("NC2 custom role and app registration")
    sub_scope = f"/subscriptions/{ctx['sub']['id']}"
    try:
        roles = az("role", "definition", "list", "--scope", sub_scope, timeout=300) or []
    except AzError as e:
        add("WARN", "Could not list role definitions", str(e))
        return
    rmap = {r["name"].lower(): r for r in roles}

    def perms(r):
        allow, deny, dallow, ddeny = [], [], [], []
        for p in r.get("permissions") or []:
            allow += p.get("actions") or []
            deny += p.get("notActions") or []
            dallow += p.get("dataActions") or []
            ddeny += p.get("notDataActions") or []
        return allow, deny, dallow, ddeny

    customs = [r for r in roles if r.get("roleType") == "CustomRole"
               and _covered("Microsoft.Nutanix/Nodes/write", *perms(r)[:2])]
    if customs:
        for r in customs:
            allow, deny, dallow, ddeny = perms(r)
            miss = [x for x in NC2_ROLE_ACTIONS if not _covered(x, allow, deny)]
            dmiss = [x for x in NC2_ROLE_DATA_ACTIONS if not _covered(x, dallow, ddeny)]
            name = r.get("roleName")
            if miss or dmiss:
                add("WARN", f"Custom role '{name}'", f"missing {len(miss)} actions, {len(dmiss)} dataActions: "
                    + ", ".join((miss + dmiss)[:6]) + (" ..." if len(miss + dmiss) > 6 else ""),
                    "Update the role with the JSON from 'Creating an Azure Custom Role For Primary Subscription'.")
            else:
                add("PASS", f"Custom role '{name}'", "contains all NC2 actions and dataActions")
    else:
        add("WARN", "NC2 custom role", "no custom role with Microsoft.Nutanix/Nodes/write found in this subscription",
            "Create 'nc2-custom-role' from the Nutanix JSON (Creating an Azure Custom Role).")

    assigns = az("role", "assignment", "list", "--scope", sub_scope, "--include-inherited", allow_fail=True)
    if assigns is None:
        add("INFO", "Role assignments", "could not read role assignments (needs Reader / User Access Admin read)")
        return
    per_sp = {}
    for a in assigns:
        if a.get("principalType") != "ServicePrincipal":
            continue
        scope = (a.get("scope") or "").lower()
        if scope not in (sub_scope.lower(), "/") and not scope.startswith("/providers/microsoft.management"):
            continue
        rid = (a.get("roleDefinitionId") or "").rstrip("/").split("/")[-1].lower()
        per_sp.setdefault(a.get("principalId"), {"name": a.get("principalName") or a.get("principalId"),
                                                  "roles": []})["roles"].append(rid)
    best = None
    for pid, info in per_sp.items():
        allow, deny, dallow, ddeny = [], [], [], []
        for rid in info["roles"]:
            r = rmap.get(rid)
            if r:
                a1, d1, a2, d2 = perms(r)
                allow += a1; deny += d1; dallow += a2; ddeny += d2
        if not _covered("Microsoft.Nutanix/Nodes/write", allow, deny):
            continue
        miss = [x for x in NC2_ROLE_ACTIONS if not _covered(x, allow, deny)]
        dmiss = [x for x in NC2_ROLE_DATA_ACTIONS if not _covered(x, dallow, ddeny)]
        cand = (len(miss) + len(dmiss), info["name"], miss + dmiss,
                [rmap[r]["roleName"] for r in info["roles"] if r in rmap])
        if best is None or cand[0] < best[0]:
            best = cand
    if best is None:
        add("WARN", "App registration with NC2 role on the subscription", "none found",
            "Create an App registration in Entra ID and assign the NC2 custom role at subscription scope.")
    elif best[0] == 0:
        add("PASS", "App registration with NC2 role on the subscription", f"{best[1]} ({', '.join(best[3])})")
    else:
        add("WARN", "App registration with NC2 role on the subscription",
            f"{best[1]} is missing {best[0]} permission(s): {', '.join(best[2][:5])}{' ...' if best[0] > 5 else ''}",
            "Owner/Contributor do not include the blob dataActions NC2 needs - use the NC2 custom role.")


# --------------------------------------------------------------------------
# In-VNet connectivity test
# --------------------------------------------------------------------------

VM_PROBE = r'''
import base64, json, random, re, socket, ssl, struct, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
T = 6
tests = json.loads(base64.b64decode(sys.argv[1]).decode())

def short(e):
    s = str(e) or e.__class__.__name__
    return " ".join(s.replace("|", "/").split())[:60]

def conn(host, port):
    return socket.create_connection((host, port), timeout=T)

def t_dns(t):
    try:
        ips = sorted({a[4][0] for a in socket.getaddrinfo(t["host"], None, socket.AF_INET)})
        return "PASS", ",".join(ips[:2])
    except Exception as e:
        return "FAIL", "does not resolve (" + short(e) + ")"

def t_tcp(t):
    try:
        s = conn(t["host"], t["port"]); s.close(); return "PASS", "tcp/%d open" % t["port"]
    except socket.timeout:
        return "FAIL", "tcp/%d timeout" % t["port"]
    except Exception as e:
        return "FAIL", "tcp/%d %s" % (t["port"], short(e))

def t_https(t):
    host = t["host"]
    try:
        raw = conn(host, 443)
    except socket.timeout:
        return "FAIL", "tcp/443 timeout"
    except Exception as e:
        return "FAIL", "tcp/443 " + short(e)
    try:
        s = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        req = "HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: nc2-precheck\r\nConnection: close\r\n\r\n" % (t.get("path", "/"), host)
        s.sendall(req.encode()); line = s.recv(256).decode(errors="replace").split("\r\n", 1)[0]; s.close()
        code = line.split(" ")[1] if line.startswith("HTTP/") else "?"
        return "PASS", "TLS ok, HTTP " + code
    except ssl.SSLCertVerificationError as e:
        return "WARN", "TLS inspected? " + short(getattr(e, "verify_message", e))
    except Exception as e:
        return "FAIL", "TLS/HTTP " + short(e)

def t_http(t):
    try:
        s = conn(t["host"], 80)
        s.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n" % t["host"]).encode())
        data = b""
        while len(data) < 8192:
            c = s.recv(2048)
            if not c:
                break
            data += c
        s.close()
        head, _, body = data.decode(errors="replace").partition("\r\n\r\n")
        code = head.split(" ")[1] if head.startswith("HTTP/") else "?"
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", body)
        return "PASS", "HTTP %s, egress IP %s" % (code, m.group(1) if m else "?")
    except socket.timeout:
        return "FAIL", "tcp/80 timeout"
    except Exception as e:
        return "FAIL", "tcp/80 " + short(e)

def t_ntp(t):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(T)
        s.sendto(b"\x1b" + 47 * b"\0", (t["host"], 123)); d, _ = s.recvfrom(512); s.close()
        if len(d) < 48:
            return "FAIL", "short NTP reply"
        secs = struct.unpack("!I", d[40:44])[0] - 2208988800
        return "PASS", "udp/123 ok, offset %+.1fs" % (secs - time.time())
    except socket.timeout:
        return "FAIL", "no reply on udp/123"
    except Exception as e:
        return "FAIL", short(e)

def t_dnsudp(t):
    q = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in t["name"].split(".")) + b"\0" + struct.pack("!HH", 1, 1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(T)
        s.sendto(q, (t["host"], 53)); d, _ = s.recvfrom(4096); s.close()
        rcode = d[3] & 0x0F; an = struct.unpack("!H", d[6:8])[0]
        if rcode == 0 and an > 0:
            return "PASS", "udp/53 answered (%d rr)" % an
        return "FAIL", "udp/53 rcode %d, %d answers" % (rcode, an)
    except socket.timeout:
        return "FAIL", "no reply on udp/53"
    except Exception as e:
        return "FAIL", short(e)

def t_icmp(t):
    r = subprocess.run(["ping", "-c", "2", "-W", "2", t["host"]], capture_output=True, text=True)
    return ("PASS", "icmp ok") if r.returncode == 0 else ("FAIL", "no icmp reply")

FN = {"dns": t_dns, "tcp": t_tcp, "https": t_https, "http": t_http, "ntp": t_ntp, "dnsudp": t_dnsudp, "icmp": t_icmp}

def run(t):
    try:
        st, d = FN[t["type"]](t)
    except Exception as e:
        st, d = "FAIL", short(e)
    return t["id"], st, d

with ThreadPoolExecutor(16) as ex:
    res = list(ex.map(run, tests))
ns = []
try:
    ns = [l.split()[1] for l in open("/run/systemd/resolve/resolv.conf") if l.startswith("nameserver")]
except Exception:
    pass
print("N|" + ",".join(ns))
for i, s, d in res:
    print("R|%s|%s|%s" % (i, s, d))
'''


def build_tests(role, dns_servers, onprem_ips):
    """role: pc | fgw_ext | bgp. Returns (tests, meta). meta[id] = (label, severity_if_failed)."""
    tests, meta = [], {}
    rk = {"pc": "mgmt", "fgw_ext": "fgw", "bgp": "bgp"}[role]

    def T(kind, label, sev, **kw):
        tid = f"t{len(tests) + 1}"
        tests.append(dict(id=tid, type=kind, **kw))
        meta[tid] = (label, sev, kind, kw.get("host"))

    need = {h: ("fail" if rk in roles else "info") for h, _, _, roles in HTTPS_ENDPOINTS}
    need["gateway-external-api.cloud.nutanix.com"] = "fail"
    need["ifconfig.me"] = "fail" if rk == "bgp" else "info"
    for h, _ in NTP_SERVERS:
        if not h[0].isdigit():
            need[h] = "fail"
    for h in sorted(need):
        T("dns", f"DNS resolves {h}", need[h], host=h)
    for host, path, purpose, roles in HTTPS_ENDPOINTS:
        T("https", f"HTTPS {host} ({purpose})", "fail" if rk in roles else "info", host=host, path=path)
    for p in TELEPORT_PORTS:
        T("tcp", f"TCP {p} azure-support.nutanix.com (Teleport)", "fail" if rk == "mgmt" else "info",
          host="azure-support.nutanix.com", port=p)
    for h, lbl in NTP_SERVERS:
        T("ntp", f"NTP udp/123 {h} ({lbl})", "fail", host=h)
    T("http", "HTTP ifconfig.me:80 (BGP VM initial config / egress IP)", "fail" if rk == "bgp" else "info", host="ifconfig.me")
    T("dnsudp", "DNS udp/53 to 8.8.8.8 (BGP VM initial connectivity)", "fail" if rk == "bgp" else "info",
      host="8.8.8.8", name="gateway-external-api.cloud.nutanix.com")
    for d in dns_servers:
        T("dnsudp", f"Custom DNS server {d} answers", "fail", host=d, name="gateway-external-api.cloud.nutanix.com")
    if role == "pc":
        for ip in onprem_ips:
            T("icmp", f"ICMP to on-prem {ip}", "warn", host=ip)
            for port, svc in DR_PORTS:
                T("tcp", f"TCP {port} on-prem {ip} ({svc})", "warn", host=ip, port=port)
    return tests, meta


def map_status(st, sev):
    if st == "PASS":
        return "PASS"
    if st == "WARN":
        return "INFO" if sev == "info" else "WARN"
    return {"fail": "FAIL", "warn": "WARN", "info": "INFO"}[sev]


def _create_vm(rg, name, loc, subnet_id, pubkey, sizes):
    last = ""
    for size in sizes:
        try:
            az("vm", "create", "-g", rg, "-n", name, "-l", loc, "--image", "Ubuntu2204", "--size", size,
               "--subnet", subnet_id, "--public-ip-address", "", "--nsg", "",
               "--admin-username", "nc2check", "--ssh-key-values", pubkey,
               "--os-disk-delete-option", "Delete", "--nic-delete-option", "Delete",
               "--tags", "purpose=nc2-precheck", timeout=1200)
            return size, None
        except AzError as e:
            last = str(e)
            if "RequestDisallowedByPolicy" in last:
                return None, last
            continue
    return None, last


def connectivity_test(ctx, L):
    section("In-VNet outbound connectivity test")
    sel = ctx["subnets"]
    plan = [r for r in ("pc", "fgw_ext", "bgp") if sel.get(r) and (r != "bgp" or ctx["routing"] == "bgp")]
    if not plan:
        add("WARN", "Connectivity test skipped", "no PC / FGW external / BGP subnet selected")
        return
    if sel.get("cluster"):
        add("INFO", "Cluster (bare-metal) subnet", "delegated subnets cannot host a test VM; the PC subnet test "
            "stands in for the 'Management subnet' endpoints - its egress path was checked above")
    sizes = [s for s in TEST_VM_SIZES if ctx["sku_ok"].get(s, True)] or TEST_VM_SIZES
    rg = "nc2-precheck-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    loc = L.subnets[sel[plan[0]]]["vnet"]["location"]
    tmp = tempfile.mkdtemp(prefix="nc2chk")
    keyfile = os.path.join(tmp, "id")
    pubkey = None
    if shutil.which("ssh-keygen"):
        subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "3072", "-N", "", "-q", "-f", keyfile], check=False)
        if os.path.exists(keyfile + ".pub"):
            pubkey = open(keyfile + ".pub").read().strip()
    if not pubkey:
        add("WARN", "Connectivity test skipped", "ssh-keygen not available to create a throw-away key")
        return
    print(f"  Creating temporary resource group {rg} in {loc} with {len(plan)} test VM(s) "
          f"(no public IP). This takes ~3-5 minutes...")
    try:
        az("group", "create", "-n", rg, "-l", loc, "--tags", "purpose=nc2-precheck")
    except AzError as e:
        add("WARN", "Connectivity test skipped", f"could not create resource group: {e}")
        return
    try:
        jobs = {}
        with cf.ThreadPoolExecutor(len(plan)) as ex:
            for role in plan:
                vm = f"nc2chk-{role.replace('_', '')}"
                vloc = L.subnets[sel[role]]["vnet"]["location"]
                jobs[role] = (vm, ex.submit(_create_vm, rg, vm, vloc, sel[role], pubkey, sizes))
            created = {}
            for role, (vm, fut) in jobs.items():
                size, err = fut.result()
                if size:
                    created[role] = vm
                    note(f"     {vm} ({size}) ready in {L.label(sel[role])}")
                else:
                    add("WARN", f"Test VM in {ROLE_INFO[role][0]}", f"could not be created: {err[:300]}",
                        "If a policy blocked it, run the test from a subscription/RG where small test VMs are allowed.")

        def run_probe(role):
            vid = L.subnets[sel[role]]["vnet"]["id"].lower()
            dns = list(dict.fromkeys(ctx.get("custom_dns", {}).get(vid, []) +
                                     (ctx.get("custom_dns", {}).get(
                                         L.subnets[sel["cluster"]]["vnet"]["id"].lower(), [])
                                      if role == "pc" and sel.get("cluster") else [])))
            tests, meta = build_tests(role, dns, ctx["onprem_ips"])
            b64 = base64.b64encode(json.dumps(tests).encode()).decode()
            script = f"cat > /tmp/nc2probe.py <<'NC2PROBE_EOF'\n{VM_PROBE}\nNC2PROBE_EOF\npython3 /tmp/nc2probe.py {b64}\n"
            sf = os.path.join(tmp, f"probe-{role}.sh")
            with open(sf, "w") as f:
                f.write(script)
            out = az("vm", "run-command", "invoke", "-g", rg, "-n", created[role], "--command-id",
                     "RunShellScript", "--scripts", f"@{sf}", timeout=1200, allow_fail=True)
            return role, meta, out

        with cf.ThreadPoolExecutor(max(1, len(created))) as ex:
            outs = list(ex.map(run_probe, list(created)))
        for role, meta, out in outs:
            name = ROLE_INFO[role][0]
            print(col("B", f"  -- from {name} ({L.label(sel[role])})"))
            if not out:
                add("FAIL", f"Probe in {name}", "run-command failed - VM agent could not run the test",
                    "Egress may be fully blocked; check NSG/UDR/firewall for this subnet.")
                continue
            msg = "\n".join(v.get("message", "") for v in out.get("value") or [])
            got = {}
            for line in msg.splitlines():
                if line.startswith("N|"):
                    servers = line[2:].strip()
                    if servers:
                        add("INFO", f"[{name}] DNS servers used by the VM", servers)
                if line.startswith("R|"):
                    parts = line.split("|", 3)
                    if len(parts) == 4:
                        got[parts[1]] = (parts[2], parts[3])
            unresolved = {m[3] for tid, m in meta.items() if m[2] == "dns" and got.get(tid, ("FAIL",))[0] != "PASS"}
            for tid, (label, sev, kind, host) in meta.items():
                if tid not in got:
                    add("WARN", f"[{name}] {label}", "no result returned")
                    continue
                st, detail = got[tid]
                status = map_status(st, sev)
                fix = ""
                if kind != "dns" and host in unresolved and st != "PASS":
                    detail = "not tested - name does not resolve (see DNS result above)"
                    fix = "Fix DNS resolution first, then re-run." if status in ("FAIL", "WARN") else ""
                elif status in ("FAIL", "WARN"):
                    if detail.startswith("TLS inspected"):
                        fix = "Exclude NC2 FQDNs from TLS/SSL inspection (Nutanix validated an L4 firewall)."
                    elif "resolve" in detail:
                        fix = "Fix DNS: VNet DNS servers must resolve public Nutanix/Azure names."
                    else:
                        fix = "Allow this destination/port outbound on the NSG, NVA/firewall or proxy path."
                if sev == "info" and st != "PASS":
                    detail += " (not required for this subnet)"
                add(status, f"[{name}] {label}", detail, fix)
    finally:
        if ctx.get("keep_vms"):
            print(col("WARN", f"  Keeping test resources in resource group {rg} (--keep-test-vms). Delete it when done."))
        else:
            print(f"  Deleting temporary resource group {rg} (runs in background)...")
            az("group", "delete", "-n", rg, "--yes", "--no-wait", allow_fail=True)
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def write_reports(ctx, L, outdir):
    os.makedirs(outdir, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = os.path.join(outdir, f"nc2-azure-precheck-{ctx['location']}-{ts}")
    counts = {k: sum(1 for r in RESULTS if r["status"] == k) for k in ("FAIL", "WARN", "PASS", "INFO")}
    meta = {
        "tool_version": VERSION, "doc": DOC_URL, "doc_last_updated": DOC_DATE,
        "generated": dt.datetime.now().isoformat(timespec="seconds"),
        "subscription": f"{ctx['sub']['name']} ({ctx['sub']['id']})", "region": ctx["location_display"],
        "flow_gateway": f"{ctx['fgw_count']} x {ctx['fgw_size']}", "routing": ctx["routing"],
        "on_prem": ctx["onprem"],
        "subnets": {ROLE_INFO[k][0]: (L.label(v) if v else "-") for k, v in ctx["subnets"].items()},
    }
    with open(base + ".json", "w") as f:
        json.dump({"meta": meta, "summary": counts, "results": RESULTS}, f, indent=2)

    e = html.escape
    rows = []
    last = None
    for r in RESULTS:
        if r["section"] != last:
            rows.append(f'<tr class="sec"><td colspan="4">{e(r["section"])}</td></tr>')
            last = r["section"]
        rows.append(f'<tr><td><span class="b {r["status"]}">{r["status"]}</span></td><td>{e(r["check"])}</td>'
                    f'<td>{e(r["detail"])}</td><td>{e(r["fix"]) if r["status"] in ("FAIL", "WARN") else ""}</td></tr>')
    fails = [r for r in RESULTS if r["status"] == "FAIL"]
    top = ""
    if fails:
        top = ("<h2 style='font-size:16px;margin:20px 0 8px'>Fix these first</h2><ol style='font-size:13px'>"
               + "".join(f"<li><b>{e(r['check'])}</b> - {e(r['detail'])}"
                         + (f"<br><span style='color:#555'>{e(r['fix'])}</span>" if r['fix'] else "") + "</li>"
                         for r in fails) + "</ol>")
    sub_rows = "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in meta["subnets"].items())
    verdict = ("Not ready - fix the FAIL items before deploying" if counts["FAIL"]
               else "Ready with warnings - review the WARN items" if counts["WARN"] else "Ready to deploy")
    vclass = "FAIL" if counts["FAIL"] else "WARN" if counts["WARN"] else "PASS"
    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>NC2 on Azure pre-check - {e(ctx['location_display'])}</title>
<style>
body{{font-family:Segoe UI,Helvetica,Arial,sans-serif;margin:32px;color:#1d1d1f;max-width:1300px}}
h1{{font-size:22px;margin:0 0 4px}} .sub{{color:#666;margin-bottom:20px;font-size:13px}}
.verdict{{padding:12px 16px;border-radius:8px;font-weight:600;margin:16px 0}}
.verdict.FAIL{{background:#fde8e8;color:#9b1c1c}} .verdict.WARN{{background:#fdf6e3;color:#8a5a00}} .verdict.PASS{{background:#e6f6ec;color:#05603a}}
.cards{{display:flex;gap:12px;margin:12px 0 20px}} .card{{border:1px solid #e3e3e3;border-radius:8px;padding:10px 16px;min-width:90px}}
.card b{{display:block;font-size:22px}}
table{{border-collapse:collapse;width:100%;font-size:13px}} td,th{{border-bottom:1px solid #eee;padding:6px 8px;text-align:left;vertical-align:top}}
table.meta{{width:auto;margin-bottom:20px}} table.meta th{{color:#555;font-weight:500;padding-right:24px}}
tr.sec td{{background:#f5f5f7;font-weight:600;padding-top:10px}}
.b{{display:inline-block;border-radius:4px;padding:1px 6px;font-size:11px;font-weight:700;color:#fff}}
.b.PASS{{background:#12a150}} .b.FAIL{{background:#d92d20}} .b.WARN{{background:#dc8b00}} .b.INFO{{background:#5b7083}}
td:nth-child(4){{color:#555}} a{{color:#2563eb}}
</style></head><body>
<h1>NC2 on Azure - landing zone pre-check</h1>
<div class="sub">Generated {e(meta['generated'])} &middot; tool v{VERSION} &middot; based on
<a href="{e(DOC_URL)}">Requirements for NC2 on Azure</a> (last updated {DOC_DATE})</div>
<div class="verdict {vclass}">{verdict}</div>
<div class="cards">
<div class="card"><b style="color:#d92d20">{counts['FAIL']}</b>Fail</div>
<div class="card"><b style="color:#dc8b00">{counts['WARN']}</b>Warning</div>
<div class="card"><b style="color:#12a150">{counts['PASS']}</b>Pass</div>
<div class="card"><b style="color:#5b7083">{counts['INFO']}</b>Info</div></div>
<table class="meta">
<tr><th>Subscription</th><td>{e(meta['subscription'])}</td></tr>
<tr><th>Region</th><td>{e(meta['region'])}</td></tr>
<tr><th>Flow Gateway</th><td>{e(meta['flow_gateway'])}, routing: {e('BGP / Azure Route Server' if ctx['routing'] == 'bgp' else 'Internal Load Balancer')}</td></tr>
<tr><th>On-prem connectivity</th><td>{e(meta['on_prem'])}</td></tr>
{sub_rows}
</table>
{top}
<h2 style="font-size:16px;margin:20px 0 8px">All checks</h2>
<table><tr><th style="width:60px">Status</th><th style="width:28%">Check</th><th>Detail</th><th style="width:28%">How to fix</th></tr>
{''.join(rows)}
</table></body></html>"""
    with open(base + ".html", "w") as f:
        f.write(doc)
    return base, counts


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def pick_subnets(args, L, ctx):
    roles = ["cluster", "pc", "fgw_ext", "fgw_int"]
    roles += ["bgp", "routeserver"] if ctx["routing"] == "bgp" else ["ilb"]
    given = {"cluster": args.cluster_subnet, "pc": args.pc_subnet, "fgw_ext": args.fgw_ext_subnet,
             "fgw_int": args.fgw_int_subnet, "bgp": args.bgp_subnet, "ilb": args.ilb_subnet,
             "routeserver": args.routeserver_subnet}
    region = norm_loc(ctx["location"])
    cands = sorted([sid for sid, x in L.subnets.items() if norm_loc(x["vnet"].get("location")) == region],
                   key=lambda s: L.label(s).lower())
    sel = {}

    def suggest(role):
        for sid in cands:
            sn = L.subnets[sid]["sn"]
            if role == "cluster" and DELEGATION in delegations(sn):
                return sid
            if role == "routeserver" and sn.get("name") == "RouteServerSubnet":
                return sid
        taken = set(sel.values())
        for sid in cands:
            sn = L.subnets[sid]["sn"]
            if sid in taken:
                continue
            if role in ROLE_HINTS and ROLE_HINTS[role].search(sn.get("name", "")) \
                    and (role == "cluster" or not delegations(sn)):
                if role == "fgw_int" and ROLE_HINTS["fgw_ext"].search(sn.get("name", "")):
                    continue
                return sid
        return None

    need_menu = any(given[r] is None for r in roles) and INTERACTIVE and cands
    if need_menu:
        print(col("B", f"\nSubnets in {ctx['location_display']}:"))
        for i, sid in enumerate(cands, 1):
            sn = L.subnets[sid]["sn"]
            d = delegations(sn)
            print(f"   [{i:>2}] {L.label(sid):<60} {subnet_prefix(sn) or '':<18} {('delegated: ' + d[0]) if d else ''}")
        print(col("DIM", "   Enter = accept suggestion, number = pick, 0 = skip (not deployed yet / NC2 will create it)"))
    for role in roles:
        if given[role] is not None:
            sid = L.resolve(given[role]) if given[role] not in ("", "-", "none") else None
            if given[role] not in ("", "-", "none") and not sid:
                print(col("WARN", f"  Could not find subnet '{given[role]}' for {ROLE_INFO[role][0]} - skipped"))
            sel[role] = sid
            continue
        sug = suggest(role)
        if not need_menu:
            sel[role] = sug
            continue
        default = str(cands.index(sug) + 1) if sug else "0"
        while True:
            v = ask(f"  {ROLE_INFO[role][0]}", default)
            if v == "0":
                sel[role] = None
                break
            if v and v.isdigit() and 1 <= int(v) <= len(cands):
                sel[role] = cands[int(v) - 1]
                break
            print("  Enter a number from the list, or 0 to skip.")
    for r in ("bgp", "routeserver", "ilb"):
        sel.setdefault(r, None)
    return sel


def main():
    global INTERACTIVE
    ap = argparse.ArgumentParser(description="NC2 on Azure landing-zone pre-check (run in Azure Cloud Shell).")
    ap.add_argument("--subscription", help="Subscription ID or name (default: current az context)")
    ap.add_argument("--location", help="Azure region, e.g. westeurope")
    ap.add_argument("--cluster-subnet", help="Cluster (bare-metal, delegated) subnet: ID, vnet/subnet or rg/vnet/subnet")
    ap.add_argument("--pc-subnet", help="Prism Central subnet")
    ap.add_argument("--fgw-ext-subnet", help="Flow Gateway external subnet")
    ap.add_argument("--fgw-int-subnet", help="Flow Gateway internal subnet")
    ap.add_argument("--bgp-subnet", help="BGP gateway subnet (Route Server routing)")
    ap.add_argument("--ilb-subnet", help="Internal Load Balancer subnet (ILB routing)")
    ap.add_argument("--routeserver-subnet", help="RouteServerSubnet in the hub VNet")
    ap.add_argument("--routing", choices=["bgp", "ilb"], help="Flow Gateway routing (default bgp = Azure Route Server)")
    ap.add_argument("--fgw-size", choices=["small", "large"], help="small = D4 (4 vCPU), large = D32 (32 vCPU)")
    ap.add_argument("--fgw-count", type=int, choices=[1, 2, 3, 4], help="Number of Flow Gateway VMs (default 2)")
    ap.add_argument("--onprem", choices=["expressroute", "vwan", "vpn"], help="On-prem connectivity type")
    ap.add_argument("--onprem-ips", default=None, help="Comma-separated on-prem CVM/Prism IPs to test DR ports")
    ap.add_argument("--mst", action="store_true", help="Also plan for Multicloud Snapshot Technology (MST) DR")
    ap.add_argument("--skip-connectivity", action="store_true", help="Skip the in-VNet test (no VMs are created)")
    ap.add_argument("--connectivity", action="store_true", help="Run the in-VNet test without asking")
    ap.add_argument("--keep-test-vms", action="store_true", help="Do not delete the test resource group")
    ap.add_argument("--yes", "-y", action="store_true", help="Non-interactive: accept defaults and suggestions")
    ap.add_argument("--report-dir", default=os.path.expanduser("~/nc2-precheck"), help="Where to write the report")
    args = ap.parse_args()
    INTERACTIVE = not args.yes and sys.stdin.isatty()

    print(col("B", f"NC2 on Azure - landing zone pre-check v{VERSION}"))
    print(col("DIM", f"Requirements source: Nutanix 'Requirements for NC2 on Azure' (updated {DOC_DATE})"))

    try:
        if args.subscription:
            az("account", "set", "--subscription", args.subscription)
        sub = az("account", "show")
    except AzError as e:
        print(col("FAIL", f"Azure CLI not signed in or not available: {e}"))
        print("Run this in Azure Cloud Shell, or run 'az login' first.")
        sys.exit(3)
    if INTERACTIVE and not args.subscription:
        subs = az("account", "list", "--query", "[?state=='Enabled']", allow_fail=True) or []
        if len(subs) > 1:
            idx = next((i for i, s in enumerate(subs) if s["id"] == sub["id"]), 0)
            i = choose(col("B", "\nWhich subscription will host NC2?"), [f"{s['name']} ({s['id']})" for s in subs], idx)
            if subs[i]["id"] != sub["id"]:
                az("account", "set", "--subscription", subs[i]["id"])
                sub = az("account", "show")
    print(f"Subscription: {sub['name']} ({sub['id']})")
    print("Reading network resources...")
    L = Landscape()

    # Region
    locs = az("account", "list-locations", allow_fail=True) or []
    disp = {l["name"]: l.get("displayName", l["name"]) for l in locs}
    location = args.location
    if not location:
        default = next((x["vnet"]["location"] for x in L.subnets.values()
                        if DELEGATION in delegations(x["sn"])), None)
        regions = sorted({v["location"] for v in L.vnets})
        if INTERACTIVE and regions:
            options = [f"{r} ({disp.get(r, r)})" for r in regions] + ["other (type it)"]
            i = choose(col("B", "\nWhich Azure region is NC2 going to?"), options,
                       regions.index(default) if default in regions else 0)
            location = regions[i] if i < len(regions) else ask("  Region name (e.g. westeurope)")
        else:
            location = default or ask("Azure region (e.g. westeurope)")
    if not location:
        print(col("FAIL", "No region given. Use --location <region>."))
        sys.exit(3)
    location = norm_loc(location)

    ctx = {"sub": sub, "location": location, "location_display": disp.get(location, location), "mst": args.mst,
           "keep_vms": args.keep_test_vms}
    if args.routing:
        ctx["routing"] = args.routing
    else:
        ctx["routing"] = ["bgp", "ilb"][choose(col("B", "\nFlow Gateway routing method?"),
                                               ["Dynamic routing via Azure Route Server + 2 BGP VMs (default)",
                                                "Internal Load Balancer (ILB) - no BGP VMs / Route Server"], 0)]
    ctx["fgw_size"] = args.fgw_size or ["small", "large"][choose(col("B", "\nFlow Gateway size?"),
                                                                 ["Small - D4_v5/D4_v4, 4 vCPU (~10 Gbps each)",
                                                                  "Large - D32_v5/D32_v4, 32 vCPU (~16 Gbps each)"], 0)]
    if args.fgw_count:
        ctx["fgw_count"] = args.fgw_count
    else:
        v = ask("\nNumber of Flow Gateway VMs (2-4)", "2")
        ctx["fgw_count"] = int(v) if v and v.isdigit() and 1 <= int(v) <= 4 else 2
    ctx["onprem"] = args.onprem or ["expressroute", "vwan", "vpn"][choose(col("B", "\nOn-prem connectivity?"),
                                                                         ["ExpressRoute", "Virtual WAN", "VPN"], 0)]
    ctx["subnets"] = pick_subnets(args, L, ctx)

    if args.onprem_ips is not None:
        ips = args.onprem_ips
    else:
        ips = ask("\nOn-prem CVM / Prism IPs to test DR ports from Azure (comma-separated, Enter to skip)", "")
    ctx["onprem_ips"] = [i.strip() for i in (ips or "").split(",") if i.strip()]

    run_conn = False
    if not args.skip_connectivity:
        if args.connectivity:
            run_conn = True
        elif INTERACTIVE:
            print(col("B", "\nIn-VNet connectivity test"))
            print("  Creates a temporary resource group with 1 small Ubuntu VM (no public IP) per tested subnet,")
            print("  tests DNS, NTP, HTTPS endpoints and ports from INSIDE your VNets, then deletes everything.")
            print("  Takes ~5 minutes and costs a few cents.")
            run_conn = yesno("  Run it?", True)

    checks = [check_subscription, check_providers, check_skus, check_quotas, check_policies, check_identity]
    for fn in checks:
        try:
            fn(ctx)
        except AzError as e:
            add("WARN", f"{fn.__name__} could not complete", str(e))
    for fn in (check_subnets, check_egress, check_dns_peering):
        try:
            fn(ctx, L)
        except AzError as e:
            add("WARN", f"{fn.__name__} could not complete", str(e))
    if run_conn:
        try:
            connectivity_test(ctx, L)
        except KeyboardInterrupt:
            print(col("WARN", "\nInterrupted - test resource group deletion was started."))
        except AzError as e:
            add("WARN", "Connectivity test could not complete", str(e))
    else:
        section("In-VNet outbound connectivity test")
        add("INFO", "Skipped", "re-run with --connectivity to test DNS/NTP/HTTPS from inside the VNets")

    base, counts = write_reports(ctx, L, args.report_dir)
    print("\n" + col("B", "== Summary =="))
    print(f"  {col('FAIL', str(counts['FAIL']) + ' FAIL')}   {col('WARN', str(counts['WARN']) + ' WARN')}   "
          f"{col('PASS', str(counts['PASS']) + ' PASS')}   {col('INFO', str(counts['INFO']) + ' INFO')}")
    if counts["FAIL"]:
        print(col("FAIL", "  Not ready: fix the FAIL items before deploying NC2."))
    elif counts["WARN"]:
        print(col("WARN", "  Ready with warnings: review the WARN items."))
    else:
        print(col("PASS", "  Landing zone looks ready for NC2."))
    print(f"\n  Report: {base}.html")
    print(f"          {base}.json")
    print(col("DIM", "  Cloud Shell: Manage files > Download, then enter the path above "
                     "(relative to your home folder, e.g. nc2-precheck/...)."))
    sys.exit(2 if counts["FAIL"] else 1 if counts["WARN"] else 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
