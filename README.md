# NC2 on Azure – landing zone pre-check

One script that checks an Azure subscription against the Nutanix
**[Requirements for NC2 on Azure](https://portal.nutanix.com/page/documents/details?targetId=Nutanix-Cloud-Clusters-Azure:nc2-clusters-azure-requirements-for-nc2-on-azure-c.html)**
(doc last updated 2026-11-11) **before** you deploy an NC2 cluster. It runs in
Azure Cloud Shell, so you don't need to install anything.

It produces a PASS / WARN / FAIL list in the terminal, plus an HTML report you can send to your Nutanix team.
See [`sample-report-mock-data.html`](sample-report-mock-data.html) for an example (generated from mock data).

> [!IMPORTANT]
> **Disclaimer**
> - This is a **community tool**. It is **not an official Nutanix product** and is **not supported by Nutanix Support**.
>   It is provided as-is, without warranty. The Nutanix documentation remains the source of truth.
> - **Read-only by default.** All checks only *read* your Azure configuration and **change nothing**.
>   The only exception is the **optional, opt-in** in-VNet connectivity test (you answer `y` or pass `--connectivity`).
>   It creates a temporary resource group with small test VMs and deletes it at the end. The report states
>   exactly what, if anything, was changed during the run.

**Quick start** (in Azure Cloud Shell):

```bash
curl -sLO https://raw.githubusercontent.com/hagoortn/nc2-azure-precheck/main/nc2-azure-precheck.py && python3 nc2-azure-precheck.py
```

---

## How to run it (Azure Cloud Shell)

1. Sign in to the **Azure portal** with an account that has at least **Reader** on the NC2 subscription.
   For the optional connectivity test you also need **Contributor** (it creates temporary VMs).
2. Click the **Cloud Shell** icon (`>_`) in the top bar. Choose **Bash** or **PowerShell**; both work.
   If this is your first time, choose **No storage account required** (ephemeral session) or create one when prompted.
3. Get the script into Cloud Shell, using either option:
   - **Upload:** in Cloud Shell click **Manage files → Upload** and select `nc2-azure-precheck.py`.
   - **Download** (easiest):
     ```bash
     curl -sLO https://raw.githubusercontent.com/hagoortn/nc2-azure-precheck/main/nc2-azure-precheck.py
     ```
4. Run it:
   ```bash
   python3 nc2-azure-precheck.py
   ```
5. Answer the prompts. Press **Enter** to accept the default shown in brackets:
   - **Subscription** that will host NC2 (only asked if you have more than one)
   - **Region** where NC2 will be deployed
   - **Flow Gateway routing**: Azure Route Server + BGP VMs (default), or Internal Load Balancer
   - **Flow Gateway size** (Large = D32 is the default, Small = D4) and **number of FGW VMs** (2–4).
     The quota for *both* sizes is shown, so you can see the impact of either choice.
   - **On-prem connectivity**: ExpressRoute / Virtual WAN / VPN
   - **Subnets**: the script lists all subnets in the region and suggests one per role
     (cluster subnet = the one delegated to `Microsoft.BareMetal/AzureHostedService`, `RouteServerSubnet`,
     and name hints such as `pc`, `fgw-ext`, `fgw-int`, `bgp`).
     Enter a number to pick another subnet, or `0` to skip one the NC2 console will create.
   - **On-prem CVM / Prism IPs** (optional): tests the DR ports from Azure to on-prem
   - **Run the connectivity test?** Default is **No** (fully read-only run). Answer `y` to test DNS, NTP and
     outbound endpoints from inside your VNets (recommended, ~5 minutes, creates temporary VMs; see below).
6. Read the summary at the end. The exit status is `0` = ready, `1` = warnings, `2` = failures.
7. Download the report: **Manage files → Download**, then enter the path printed at the end, e.g.
   `nc2-precheck/nc2-azure-precheck-westeurope-20261119-120001.html`. Open it in a browser.
   A `.json` file with the same results is written next to it.

### Non-interactive run (repeatable / for scripts)

```bash
python3 nc2-azure-precheck.py -y \
  --subscription "<sub-id>" --location westeurope \
  --routing bgp --fgw-size small --fgw-count 2 --onprem expressroute \
  --cluster-subnet  rg-nc2/vnet-nc2-cluster/snet-cluster \
  --pc-subnet       rg-nc2/vnet-nc2-pc/snet-pc \
  --fgw-ext-subnet  rg-nc2/vnet-nc2-pc/snet-fgw-ext \
  --fgw-int-subnet  rg-nc2/vnet-nc2-pc/snet-fgw-int \
  --bgp-subnet      rg-nc2/vnet-nc2-pc/snet-bgp \
  --routeserver-subnet rg-hub/vnet-hub/RouteServerSubnet \
  --onprem-ips 10.1.1.10,10.1.1.11 \
  --connectivity
```

Subnets can be given as `vnet/subnet`, `rg/vnet/subnet` or a full resource ID.
Run `python3 nc2-azure-precheck.py --help` for every option (`--mst`, `--skip-connectivity`, `--keep-test-vms`, `--report-dir`).

---

## What it checks

| Area | Checks |
|---|---|
| **Subscription** | Enabled state; flags trial/MSDN/sponsored offers or a spending limit (these usually can't run bare-metal nodes) |
| **Resource providers** | `Microsoft.Nutanix` and `Microsoft.Network` registered (FAIL); Compute, Storage and ManagedIdentity (WARN); region listed by `Microsoft.Nutanix` |
| **VM sizes** | Flow Gateway `Standard_D4_v5`/`D32_v5` (recommended) and `D4_v4`/`D32_v4`; BGP VMs `Standard_D8s_v5` with fallback `Standard_D3_v2`. Detects `NotAvailableForSubscription` and zone restrictions |
| **Quotas** | Per-family vCPU for the Flow Gateway and BGP VMs (see the table below); headroom for a 4-node FGW scale-out; Total Regional vCPUs; VM count; Standard public IPs (3, one per NAT gateway); NAT gateways, VNets, NICs; storage accounts. BGP is skipped automatically for ILB routing |
| **Azure Policy** | Allowed locations, Allowed VM SKUs, (Not) allowed resource types, **"Network interfaces should disable IP forwarding"** (kills the Flow Gateway), tag-requiring deny policies, other deny/modify policies in the Network category; respects exemptions, `notScopes` and DoNotEnforce |
| **Custom role / App registration** | Custom role with all 109 actions + 9 blob dataActions from the Nutanix JSON; a service principal assigned at subscription scope that has them (Owner/Contributor lack the blob dataActions) |
| **Subnets & CIDRs** | Cluster subnet ≥ /25 and delegated to `Microsoft.BareMetal/AzureHostedService`; PC ≥ /26; FGW external /24 recommended, /26 minimum; FGW internal, BGP and ILB ≥ /28; `RouteServerSubnet` name and ≥ /27; VNet sizes (cluster /25, PC /23–/24 for ER/vWAN or /26 for VPN, FGW /23–/25, hub ≥ /27); FGW ext + int in the same VNet; ILB in the FGW VNet; one cluster per VNet; IPv4 only; no overlap between the NC2 VNets; warns if `192.168.5.0/24` (CVM internal) is used |
| **Outbound path** | Per subnet (cluster, PC, FGW external, BGP): NAT gateway with a public IP, or a `0.0.0.0/0` UDR to an NVA / VNet gateway; catches black-hole routes and private subnets with no egress. NSG outbound deny rules that hit 443/123/53/80/3022–3025/3080. IP forwarding on FGW NICs if they already exist |
| **DNS & connectivity** | Custom vs Azure DNS per VNet; peering state and sync; cluster ↔ PC ↔ FGW ↔ hub reachability (direct or via a shared hub); VPN/ExpressRoute/vWAN present; Route Server present |
| **In-VNet test (optional)** | From a throw-away VM in each of the PC, FGW external and BGP subnets: DNS resolution of every FQDN (incl. `gateway-external-api.cloud.nutanix.com`), HTTPS + TLS to every endpoint, **TLS-inspection detection**, NTP UDP/123 to `*.pool.ntp.org` and `138.236.128.112`, Teleport TCP 3022–3025/3080 to `azure-support.nutanix.com`, `ifconfig.me:80` (also shows the egress public IP), UDP/53 to `8.8.8.8`, each custom DNS server, and optionally the DR ports 2009/2020/9440/22/2010/3260/2049 + ICMP to on-prem |

### VM quota checked (Flow Gateway and BGP)

| Component | VM size | Azure quota family (portal name) | Quantity checked |
|---|---|---|---|
| Flow Gateway – Large | `Standard_D32_v5` (v5 recommended) | Standard Dv5 Family vCPUs | 2–4 VMs × 32 vCPU |
| Flow Gateway – Small | `Standard_D4_v5` (v5 recommended) | Standard Dv5 Family vCPUs | 2–4 VMs × 4 vCPU |
| Flow Gateway – legacy | `Standard_D32_v4` / `Standard_D4_v4` | Standard Dv4 Family vCPUs | same count; used only if v5 falls short |
| BGP gateway – primary | `Standard_D8s_v5` | Standard **DSv5** Family vCPUs | 2 × 8 = 16 vCPU (Route Server routing only) |
| BGP gateway – fallback | `Standard_D3_v2` | Standard Dv2 Family vCPUs | 2 × 4 = 8 vCPU, used if D8s_v5 quota/capacity is unavailable |

Both FGW sizes are always reported: the selected one decides PASS/FAIL, the other is shown as INFO.
Note: `Standard_D8s_v5` only counts against **DSv5** quota; Dv5 quota does not cover it.
The script also checks whether each size is restricted for the subscription in the region (`NotAvailableForSubscription`).

### Endpoints tested (from the Nutanix doc, tables 3–5)

| Destination | Port | Required from |
|---|---|---|
| portal.nutanix.com, licensing-api.nutanix.com, downloads.cloud.nutanix.com, insights.nutanix.com, gateway-external-api.cloud.nutanix.com, apikeys.nutanix.com, management.azure.com | TCP 443 | Management, FGW, BGP |
| *.pool.ntp.org, 138.236.128.112 (Azure NTP) | UDP 123 | Management, FGW, BGP |
| clusters-public-images.s3.us-west-2.amazonaws.com/azure/prism-central/ | TCP 443 | Management |
| azure-support.nutanix.com (Teleport) | TCP 443, 3022–3025, 3080 | Management |
| ifconfig.me | TCP 80 | BGP |
| 8.8.8.8 | UDP 53 | BGP |

---

## About the connectivity test

- It is **opt-in** and the only part of the tool that changes anything in Azure.
- It creates a resource group `nc2-precheck-xxxxxx` with **one small Ubuntu VM per tested subnet**
  (`Standard_B2s`, falling back to other 2-vCPU sizes), **no public IP and no NIC NSG**, so traffic follows
  your real subnet NSG, NAT gateway, UDR and firewall path.
- The test runs through **Run Command** (no SSH, no inbound access). The resource group is deleted at the end,
  also when you press Ctrl+C. Use `--keep-test-vms` to keep it for troubleshooting.
- **The cluster subnet can't be tested directly.** Subnets delegated to `Microsoft.BareMetal/AzureHostedService`
  can't host a normal VM. The PC subnet test stands in for the "Management subnet" endpoints, and the script
  checks the cluster subnet's egress configuration (NAT gateway or UDR) separately. If the cluster and PC subnets
  use different egress paths, check the cluster path's firewall rules by hand.
- If a policy blocks the test VMs (e.g. allowed SKUs or required tags), that part is reported as WARN and the rest of the checks still run.
- A **TLS inspected?** warning means the certificate didn't validate against public CAs, which usually means an
  SSL-inspecting firewall. Nutanix validated outbound traffic through a **Layer 4** firewall, so exclude the NC2 FQDNs from inspection.

## What it can't check

- On-prem side firewall rules beyond the optional DR port test, and VIPs for the on-prem/Azure clusters.
- PC → PE port 9463 and ICMP between CVMs/PE/PC: these only exist after deployment.
- My Nutanix workspace / Account Admin role and the NC2 subscription (outside Azure).
- Bare-metal capacity in the region. NC2 needs regions with 3+ partitions; confirm with Nutanix/Microsoft.

## Logos in the report

The HTML report header has a slot for the Nutanix NC2 and Microsoft Azure logos. They are loaded from this repo when
the report is opened, so the script itself stays a single file. Until the files exist, the report shows text labels instead.

To add them:
1. Get the official files: the Nutanix logo from the Nutanix brand guidelines/brand portal, and the Azure icon
   from Microsoft's [Azure architecture icons](https://learn.microsoft.com/azure/architecture/icons/) download
   (follow each owner's usage terms).
2. Save them as SVG files in an `assets/` folder in this repo, named exactly:
   - `assets/nutanix-nc2-logo.svg`
   - `assets/azure-logo.svg`
3. Commit and push. Every report generated from then on (including older reports when re-opened online) shows the logos.
   The header has a dark background, so use the white/reversed version of the logo if one is available.

## Permissions used

Read-only calls: `az account`, `provider show`, `vm list-skus`, `vm list-usage`, `network * list`,
`policy assignment/exemption list`, `role definition/assignment list`. The connectivity test additionally does
`group create/delete`, `vm create` and `vm run-command invoke`.
